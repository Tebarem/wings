package filesystem

import (
	"archive/tar"
	"context"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"emperror.dev/errors"
	"github.com/apex/log"
	"github.com/juju/ratelimit"
	"github.com/klauspost/pgzip"

	"golang.org/x/sys/unix"

	"github.com/pterodactyl/wings/config"
	"github.com/pterodactyl/wings/internal/progress"
	"github.com/pterodactyl/wings/internal/ufs"
)

const memory = 4 * 1024

var pool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, memory)
		return b
	},
}

// TarProgress .
type TarProgress struct {
	*tar.Writer
	p *progress.Progress
}

// NewTarProgress .
func NewTarProgress(w *tar.Writer, p *progress.Progress) *TarProgress {
	if p != nil {
		p.Writer = w
	}
	return &TarProgress{
		Writer: w,
		p:      p,
	}
}

// Write .
func (p *TarProgress) Write(v []byte) (int, error) {
	if p.p == nil {
		return p.Writer.Write(v)
	}
	return p.p.Write(v)
}

type Archive struct {
	// Filesystem to create the archive with.
	Filesystem *Filesystem

	// Ignore is a gitignore string (most likely read from a file) of files to ignore
	// from the archive.
	Ignore string

	// BaseDirectory .
	BaseDirectory string

	// Files specifies the files to archive, this takes priority over the Ignore
	// option, if unspecified, all files in the BaseDirectory will be archived
	// unless Ignore is set.
	Files []string

	// Progress wraps the writer of the archive to pass through the progress tracker.
	Progress *progress.Progress

	// root is the verified canonical path of BaseDirectory for a restricted archive.
	root string

	// Restricted leaves hidden and protected files, and any directory that is hidden or
	// protected, out of the archive. It is set for archives made on behalf of a user
	// (and backups), where those files must never leave the server through Wings.
	Restricted bool

	w *TarProgress
}

// Create creates an archive at dst with all the files defined in the
// included Files array.
//
// THIS IS UNSAFE TO USE IF `dst` IS PROVIDED BY A USER! ONLY USE THIS WITH
// CONTROLLED PATHS!
func (a *Archive) Create(ctx context.Context, dst string) error {
	// Using os.OpenFile here is expected, as long as `dst` is not a user
	// provided path.
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	// Select a writer based off of the WriteLimit configuration option. If there is no
	// write limit, use the file as the writer.
	var writer io.Writer
	if writeLimit := int64(config.Get().System.Backups.WriteLimit * 1024 * 1024); writeLimit > 0 {
		// Token bucket with a capacity of "writeLimit" MiB, adding "writeLimit" MiB/s
		// and then wrap the file writer with the token bucket limiter.
		writer = ratelimit.Writer(f, ratelimit.NewBucketWithRate(float64(writeLimit), writeLimit))
	} else {
		writer = f
	}

	return a.Stream(ctx, writer)
}

type walkFunc func(dirfd int, name, relative string, d ufs.DirEntry) error

// Stream streams the creation of the archive to the given writer.
func (a *Archive) Stream(ctx context.Context, w io.Writer) error {
	if a.Filesystem == nil {
		return errors.New("filesystem: archive.Filesystem is unset")
	}

	// The base directory may come with a prefixed `/`, strip it to prevent
	// problems.
	a.BaseDirectory = strings.TrimPrefix(a.BaseDirectory, "/")

	if filesLen := len(a.Files); filesLen > 0 {
		files := make([]string, filesLen)
		for i, f := range a.Files {
			if !strings.HasPrefix(f, a.Filesystem.Path()) {
				files[i] = f
				continue
			}
			files[i] = strings.TrimPrefix(strings.TrimPrefix(f, a.Filesystem.Path()), "/")
		}
		a.Files = files
	}

	// If we're specifically looking for only certain files, or have requested
	// that certain files be ignored we'll update the callback function to reflect
	// that request. Ignore patterns are compiled before anything is written so that
	// an invalid list does not leave an empty archive behind.
	var callback walkFunc
	if len(a.Files) == 0 && len(a.Ignore) > 0 {
		i, err := compileIgnore(a.Ignore)
		if err != nil {
			return errors.WrapIf(err, "filesystem: unable to compile archive ignore patterns")
		}
		// Time each evaluation and abort if the patterns prove disproportionately
		// expensive for this server's file tree.
		budget := newIgnoreMatchBudget()
		callback = a.callback(func(_ int, _, relative string, _ ufs.DirEntry) error {
			start := time.Now()
			skip := i.MatchesPath(relative)
			if err := budget.track(time.Since(start)); err != nil {
				return err
			}
			if skip {
				return SkipThis
			}
			return nil
		})
	} else if len(a.Files) > 0 {
		callback = a.withFilesCallback()
	} else {
		callback = a.callback()
	}

	// Choose which compression level to use based on the compression_level configuration option
	var compressionLevel int
	switch config.Get().System.Backups.CompressionLevel {
	case "none":
		compressionLevel = pgzip.NoCompression
	case "best_compression":
		compressionLevel = pgzip.BestCompression
	default:
		compressionLevel = pgzip.BestSpeed
	}

	// Create a new gzip writer around the file.
	gw, _ := pgzip.NewWriterLevel(w, compressionLevel)
	_ = gw.SetConcurrency(1<<20, 1)
	defer gw.Close()

	// Create a new tar writer around the gzip writer.
	tw := tar.NewWriter(gw)
	defer tw.Close()

	a.w = NewTarProgress(tw, a.Progress)

	fs := a.Filesystem.unixFS

	// When restricted, the base directory is opened through a descriptor that has been checked
	// against the rules, and entries are classified as they are walked, so restricted files and
	// directories are skipped. Directories are skipped entirely, so their contents are never visited.
	var (
		dirfd      int
		name       string
		classifier *walkClassifier
		err        error
	)
	if a.Restricted {
		base, canonical, err := a.Filesystem.openDir(a.BaseDirectory)
		if err != nil {
			return err
		}
		defer base.Close()
		dirfd, name = int(base.Fd()), "."
		a.root = canonical
		classifier = a.Filesystem.newWalkClassifier(canonical)
	} else {
		var closeFd func()
		dirfd, name, closeFd, err = fs.SafePath(a.BaseDirectory)
		defer closeFd()
		if err != nil {
			return err
		}
	}

	// Recursively walk the base directory.
	return fs.WalkDirat(dirfd, name, func(dirfd int, name, relative string, d ufs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if classifier != nil && relative != "." {
				lvl, err := classifier.Classify(relative, d.IsDir(), d.Type()&ufs.ModeSymlink != 0)
				if err != nil {
					return err
				}
				if lvl != LevelNone {
					if d.IsDir() {
						return ufs.SkipDir
					}
					return nil
				}
			}
			return callback(dirfd, name, relative, d)
		}
	})
}

// Callback function used to determine if a given file should be included in the archive
// being generated.
func (a *Archive) callback(opts ...walkFunc) walkFunc {
	return func(dirfd int, name, relative string, d ufs.DirEntry) error {
		// Skip directories because we are walking them recursively.
		if d.IsDir() {
			return nil
		}

		// The walk starts at the base directory, so relative is already relative to it. It must
		// not be trimmed of the base directory's name: a directory beneath the base that has the
		// same name would lose its own name, and its files would be archived under the wrong path
		// or not at all.
		//
		// See https://github.com/pterodactyl/panel/issues/5030 for the original nested directory case.

		// Call the additional options passed to this callback function. If any of them return
		// a non-nil error we will exit immediately.
		for _, opt := range opts {
			if err := opt(dirfd, name, relative, d); err != nil {
				if err == SkipThis {
					return nil
				}
				return err
			}
		}

		// Add the file to the archive, if it is nested in a directory,
		// the directory will be automatically "created" in the archive.
		return a.addToArchive(dirfd, name, relative, d)
	}
}

var SkipThis = errors.New("skip this")

// Pushes only files defined in the Files key to the final archive.
func (a *Archive) withFilesCallback() walkFunc {
	return a.callback(func(_ int, _, relative string, _ ufs.DirEntry) error {
		for _, f := range a.Files {
			// Allow exact file matches, otherwise check if file is within a parent directory.
			//
			// The slashes are added in the prefix checks to prevent partial name matches from being
			// included in the archive.
			if f != relative && !strings.HasPrefix(strings.TrimSuffix(relative, "/")+"/", strings.TrimSuffix(f, "/")+"/") {
				continue
			}

			// Once we have a match return a nil value here so that the loop stops and the
			// call to this function will correctly include the file in the archive. If there
			// are no matches we'll never make it to this line, and the final error returned
			// will be the ufs.SkipDir error.
			return nil
		}

		return SkipThis
	})
}

// Adds a given file path to the final archive being created.
func (a *Archive) addToArchive(dirfd int, name, relative string, entry ufs.DirEntry) error {
	s, err := entry.Info()
	if err != nil {
		if errors.Is(err, ufs.ErrNotExist) {
			return nil
		}
		return errors.WrapIff(err, "failed executing os.Lstat on '%s'", name)
	}

	// A file in a user archive is only included once the descriptor it is read from has been
	// checked: it must still be where the walk found it, it must not be restricted, and it must
	// not be reachable by another name. The file is opened before its header is written, so a
	// file that fails the checks is skipped without leaving a broken entry in the archive.
	var pre ufs.File
	if a.Restricted && s.Mode().IsRegular() {
		opened, err := a.Filesystem.unixFS.OpenFileat(dirfd, name, ufs.O_RDONLY, 0)
		if err != nil {
			return nil
		}
		info, err := opened.Stat()
		if err != nil {
			_ = opened.Close()
			return nil
		}
		if reason := a.skipReason(opened, info, relative); reason != "" {
			log.WithField("path", relative).WithField("reason", reason).Debug("skipping file in user archive")
			_ = opened.Close()
			return nil
		}
		pre = opened
		defer pre.Close()
		s = info
	}

	// Skip socket files as they are unsupported by archive/tar.
	// Error will come from tar#FileInfoHeader: "archive/tar: sockets not supported"
	if s.Mode()&fs.ModeSocket != 0 {
		return nil
	}

	// Resolve the symlink target if the file is a symlink.
	var target string
	if s.Mode()&fs.ModeSymlink != 0 {
		// Read the target of the symlink. If there are any errors we will dump them out to
		// the logs, but we're not going to stop the backup. There are far too many cases of
		// symlinks causing all sorts of unnecessary pain in this process. Sucks to suck if
		// it doesn't work.
		// The link is read relative to the directory the walk found it in, never relative to the
		// working directory of Wings.
		buf := make([]byte, unix.PathMax)
		n, err := unix.Readlinkat(dirfd, name, buf)
		target = string(buf[:n])
		if err != nil {
			// Ignore the not exist errors specifically, since there is nothing important about that.
			if !os.IsNotExist(err) {
				log.WithField("name", name).WithField("readlink_err", err.Error()).Warn("failed reading symlink for target path; skipping...")
			}
			return nil
		}
	}

	// Get the tar FileInfoHeader in order to add the file to the archive.
	header, err := tar.FileInfoHeader(s, filepath.ToSlash(target))
	if err != nil {
		return errors.WrapIff(err, "failed to get tar#FileInfoHeader for '%s'", name)
	}

	// Fix the header name if the file is not a symlink.
	if s.Mode()&fs.ModeSymlink == 0 {
		header.Name = relative
	}

	// Write the tar FileInfoHeader to the archive.
	if err := a.w.WriteHeader(header); err != nil {
		return errors.WrapIff(err, "failed to write tar#FileInfoHeader for '%s'", name)
	}

	// If the size of the file is less than 1 (most likely for symlinks), skip writing the file.
	if header.Size < 1 {
		return nil
	}

	// If the buffer size is larger than the file size, create a smaller buffer to hold the file.
	var buf []byte
	if header.Size < memory {
		buf = make([]byte, header.Size)
	} else {
		// Get a fixed-size buffer from the pool to save on allocations.
		buf = pool.Get().([]byte)
		defer func() {
			buf = make([]byte, memory)
			pool.Put(buf)
		}()
	}

	// Open the file, unless it was already opened and checked above.
	f := pre
	if f == nil {
		opened, err := a.Filesystem.unixFS.OpenFileat(dirfd, name, ufs.O_RDONLY, 0)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return errors.WrapIff(err, "failed to open '%s' for copying", header.Name)
		}
		f = opened
		defer f.Close()
	}

	// Copy the file's contents to the archive using our buffer.
	if _, err := io.CopyBuffer(a.w, io.LimitReader(f, header.Size), buf); err != nil {
		return errors.WrapIff(err, "failed to copy '%s' to archive", header.Name)
	}
	return nil
}

// skipReason returns why an open file must not be included in a user archive, or an empty
// string if it may be included. The file must still be where the walk found it, which is
// checked on the descriptor, and it must not be restricted or reachable by another name.
func (a *Archive) skipReason(f ufs.File, info ufs.FileInfo, relative string) string {
	loc, err := a.Filesystem.fdPath(int(f.Fd()))
	if err != nil {
		return "outside of the server root"
	}
	if loc != path.Join(a.root, relative) {
		return "moved while being archived"
	}
	if a.Filesystem.rules.levelAt(loc, kindFile) != LevelNone {
		return "restricted"
	}
	if a.Filesystem.hardlinked(info) {
		return "hard linked"
	}
	return ""
}
