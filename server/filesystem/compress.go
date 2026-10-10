package filesystem

import (
	"context"
	"fmt"
	"io"
	iofs "io/fs"
	"math"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"emperror.dev/errors"
	"github.com/klauspost/compress/zip"
	"github.com/mholt/archives"

	"github.com/pterodactyl/wings/internal/ufs"
	"github.com/pterodactyl/wings/server/filesystem/archiverext"
)

// CompressFiles compresses all the files matching the given paths in the
// specified directory. This function also supports passing nested paths to only
// compress certain files and folders when working in a larger directory. This
// effectively creates a local backup, but rather than ignoring specific files
// and folders, it takes an allow-list of files and folders.
//
// All paths are relative to the dir that is passed in as the first argument,
// and the compressed file will be placed at that location named
// `archive-{date}.tar.gz`.
func (fs *Filesystem) CompressFiles(dir string, paths []string) (ufs.FileInfo, error) {
	a := &Archive{Filesystem: fs, BaseDirectory: dir, Files: paths}
	d := path.Join(
		dir,
		fmt.Sprintf("archive-%s.tar.gz", strings.ReplaceAll(time.Now().Format(time.RFC3339), ":", "")),
	)
	f, err := fs.unixFS.OpenFile(d, ufs.O_WRONLY|ufs.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cw := ufs.NewCountedWriter(f)
	if err := a.Stream(context.Background(), cw); err != nil {
		return nil, err
	}
	if cw.BytesWritten() < 0 || !fs.unixFS.CanFit(cw.BytesWritten()) {
		_ = fs.unixFS.Remove(d)
		return nil, newFilesystemError(ErrCodeDiskSpace, nil)
	}
	fs.unixFS.Add(cw.BytesWritten())
	return f.Stat()
}

// archiveFS returns a read-only view of the archive read from f. The file is rewound first,
// and it is not closed, so the caller keeps ownership of it.
func archiveFS(ctx context.Context, f ufs.File, name string) (iofs.FS, error) {
	format, _, err := archives.Identify(ctx, filepath.Base(name), f)
	if err != nil && !errors.Is(err, archives.NoMatch) {
		return nil, err
	}

	// Reset the file reader.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	if format != nil {
		switch ff := format.(type) {
		case archives.Zip:
			// zip.Reader is more performant than ArchiveFS, because zip.Reader caches content information
			// and zip.Reader can open several content files concurrently because of io.ReaderAt requirement
			// while ArchiveFS can't.
			// zip.Reader doesn't suffer from issue #330 and #310 according to local test (but they should be fixed anyway)
			return zip.NewReader(f, info.Size())
		case archives.Extraction:
			return &archives.ArchiveFS{Stream: io.NewSectionReader(f, 0, info.Size()), Format: ff, Context: ctx}, nil
		case archives.Compression:
			return archiverext.FileFS{File: f, Compression: ff}, nil
		}
	}
	return nil, archives.NoMatch
}

// archiverFileSystem opens the archive at p and returns a view of it. The returned closer
// must be closed once the view is no longer used.
func (fs *Filesystem) archiverFileSystem(ctx context.Context, p string) (iofs.FS, io.Closer, error) {
	f, err := fs.unixFS.Open(p)
	if err != nil {
		return nil, nil, err
	}
	fsys, err := archiveFS(ctx, f, p)
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return fsys, f, nil
}

// SpaceAvailableForDecompression looks through a given archive and determines
// if decompressing it would put the server over its allocated disk space limit.
func (fs *Filesystem) SpaceAvailableForDecompression(ctx context.Context, dir string, file string) error {
	// Don't waste time trying to determine this if we know the server will have the space for
	// it since there is no limit.
	if fs.MaxDisk() <= 0 {
		return nil
	}
	f, err := fs.unixFS.Open(filepath.Join(dir, file))
	if err != nil {
		return err
	}
	defer f.Close()
	return fs.spaceForArchive(ctx, f, file)
}

// spaceForArchive determines whether extracting the archive read from f would put the server over
// its disk limit. Users go through this with a descriptor that has been checked against the rules.
func (fs *Filesystem) spaceForArchive(ctx context.Context, f ufs.File, name string) error {
	if fs.MaxDisk() <= 0 {
		return nil
	}
	fsys, err := archiveFS(ctx, f, name)
	if err != nil {
		if errors.Is(err, archives.NoMatch) {
			return newFilesystemError(ErrCodeUnknownArchive, err)
		}
		return err
	}

	var size atomic.Int64
	return iofs.WalkDir(fsys, ".", func(path string, d iofs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			// Stop walking if the context is canceled.
			return ctx.Err()
		default:
			info, err := d.Info()
			if err != nil {
				return err
			}
			fileSize := info.Size()
			if fileSize <= 0 {
				return nil
			}
			current := size.Load()
			if fileSize > math.MaxInt64-current {
				return newFilesystemError(ErrCodeDiskSpace, nil)
			}
			next := current + fileSize
			if !fs.unixFS.CanFit(next) {
				return newFilesystemError(ErrCodeDiskSpace, nil)
			}
			size.Store(next)
			return nil
		}
	})
}

// DecompressFile will decompress a file in a given directory by using the
// archiver tool to infer the file type and go from there. This will walk over
// all the files within the given archive and ensure that there is not a
// zip-slip attack being attempted by validating that the final path is within
// the server data directory.
func (fs *Filesystem) DecompressFile(ctx context.Context, dir string, file string) error {
	f, err := fs.unixFS.Open(filepath.Join(dir, file))
	if err != nil {
		return err
	}
	defer f.Close()

	// Identify the type of archive we are dealing with.
	format, input, err := archives.Identify(ctx, filepath.Base(file), f)
	if err != nil {
		if errors.Is(err, archives.NoMatch) {
			return newFilesystemError(ErrCodeUnknownArchive, err)
		}
		return err
	}

	return fs.extractStream(ctx, extractStreamOptions{
		FileName:  file,
		Directory: dir,
		Format:    format,
		Reader:    input,
	})
}

// ExtractStreamUnsafe .
func (fs *Filesystem) ExtractStreamUnsafe(ctx context.Context, dir string, r io.Reader) error {
	format, input, err := archives.Identify(ctx, "archive.tar.gz", r)
	if err != nil {
		if errors.Is(err, archives.NoMatch) {
			return newFilesystemError(ErrCodeUnknownArchive, err)
		}
		return err
	}
	return fs.extractStream(ctx, extractStreamOptions{
		Directory: dir,
		Format:    format,
		Reader:    input,
	})
}

type extractStreamOptions struct {
	// The directory to extract the archive to.
	Directory string
	// File name of the archive.
	FileName string
	// Format of the archive.
	Format archives.Format
	// Reader for the archive.
	Reader io.Reader
	// Restricted extracts for a user. Entries that would be written to a hidden or protected
	// location, or over a hard linked file, are skipped, and every write is made through a
	// descriptor that is checked against the rules. Internal extraction, such as a transfer,
	// writes every entry.
	Restricted bool
}

func (fs *Filesystem) extractStream(ctx context.Context, opts extractStreamOptions) error {
	// See if it's a compressed archive, such as TAR or a ZIP
	ex, ok := opts.Format.(archives.Extractor)
	if !ok {
		// If not, check if it's a single-file compression, such as
		// .log.gz, .sql.gz, and so on
		de, ok := opts.Format.(archives.Decompressor)
		if !ok {
			return nil
		}

		// Strip the compression suffix
		p := filepath.Join(opts.Directory, strings.TrimSuffix(opts.FileName, opts.Format.Extension()))

		reader, err := de.OpenReader(opts.Reader)
		if err != nil {
			return err
		}
		defer reader.Close()

		if opts.Restricted {
			return fs.writeEntry(p, reader, -1, 0o644, time.Time{}, true)
		}

		// Open the file for creation/writing
		f, err := fs.unixFS.OpenFile(p, ufs.O_WRONLY|ufs.O_CREATE, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()

		// Read in 4 KB chunks
		buf := make([]byte, 4096)
		for {
			n, err := reader.Read(buf)
			if n > 0 {

				// Check quota before writing the chunk
				if quotaErr := fs.HasSpaceFor(int64(n)); quotaErr != nil {
					return quotaErr
				}

				// Write the chunk
				if _, writeErr := f.Write(buf[:n]); writeErr != nil {
					return writeErr
				}

				// Add to quota
				fs.addDisk(int64(n))
			}

			if err != nil {
				// EOF are expected
				if err == io.EOF {
					break
				}

				// Return any other
				return err
			}
		}

		return nil
	}

	// Decompress and extract archive
	return ex.Extract(ctx, opts.Reader, func(ctx context.Context, f archives.FileInfo) error {
		if opts.Restricted {
			return fs.extractRestrictedEntry(opts, f)
		}

		p := filepath.Join(opts.Directory, f.NameInArchive)
		// Create directories explicitly; an empty one has no file to create it
		// implicitly and would otherwise be dropped during extraction.
		if f.IsDir() {
			if err := fs.mkdirAll(p, 0o755); err != nil {
				return wrapError(err, opts.FileName)
			}
			return nil
		}
		r, err := f.Open()
		if err != nil {
			return err
		}
		defer r.Close()
		if err := fs.Write(p, r, f.Size(), f.Mode()); err != nil {
			return wrapError(err, opts.FileName)
		}
		// Update the file modification time to the one set in the archive.
		if err := fs.Chtimes(p, f.ModTime(), f.ModTime()); err != nil {
			return wrapError(err, opts.FileName)
		}
		return nil
	})
}

// extractRestrictedEntry writes one entry of an archive extracted for a user. The name is
// cleaned as if it were rooted, so an entry cannot climb out of the directory it is extracted to.
func (fs *Filesystem) extractRestrictedEntry(opts extractStreamOptions, f archives.FileInfo) error {
	p := path.Join(opts.Directory, path.Clean("/"+f.NameInArchive))
	if f.IsDir() {
		return wrapError(fs.ensureDirectory(p, true), opts.FileName)
	}
	r, err := f.Open()
	if err != nil {
		return err
	}
	defer r.Close()
	return wrapError(fs.writeEntry(p, r, f.Size(), f.Mode(), f.ModTime(), true), opts.FileName)
}
