package filesystem

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"emperror.dev/errors"
	"github.com/gabriel-vasile/mimetype"
	"github.com/mholt/archives"
	"golang.org/x/sys/unix"

	"github.com/pterodactyl/wings/config"
	"github.com/pterodactyl/wings/internal/ufs"
)

// Restricted is the view of a server's filesystem that is used for everything a user can
// reach through Wings: the HTTP file API, downloads, uploads, remote pulls, archives, backups
// and SFTP. Internal operations, such as installation scripts, config parsing, transfers and
// disk usage, use the Filesystem directly.
//
// Every method locates the entry it acts on through a file descriptor (see safe.go), checks
// the rules against the location that descriptor refers to, and then acts through the same
// descriptor. Paths are normalized once, with the same rules the unixFS uses, so the check and
// the operation always refer to the same location.
type Restricted struct {
	fs *Filesystem
}

// Restricted returns the user-facing view of the filesystem.
func (fs *Filesystem) Restricted() *Restricted {
	return &Restricted{fs: fs}
}

// hiddenError is returned for hidden paths. It matches os.ErrNotExist so that a hidden path
// cannot be told apart from one that does not exist.
func hiddenError(p string) error {
	return errors.WithStackDepth(&Error{code: ErrNotExist, err: ufs.ErrNotExist, path: p, resolved: p}, 1)
}

// notExistError is returned for paths that do not exist.
func notExistError(p string) error {
	return hiddenError(p)
}

// protectedError is returned for protected paths.
func protectedError(p string) error {
	return errors.WithStackDepth(&Error{code: ErrCodeDenylistFile, path: p, resolved: p}, 1)
}

// hardlinkError is returned for regular files that have more than one name, while rules are
// configured. The file could otherwise be reached through a name that is not restricted.
func hardlinkError(p string) error {
	return errors.WithStackDepth(&Error{code: ErrCodeHardlink, path: p, resolved: p}, 1)
}

// notRegularError is returned for an entry that is neither a regular file nor a directory, such
// as a named pipe or a device. Reading or writing one could block or act on something else.
func notRegularError(p string) error {
	return errors.WithStackDepth(&Error{code: ErrCodeNotRegular, path: p, resolved: p}, 1)
}

// restrictedContentsError is returned when a directory cannot be changed because something
// beneath it is restricted. Hidden and protected contents are reported identically, so the
// response does not reveal which of them exist.
func restrictedContentsError(p string) error {
	return errors.WithStackDepth(&Error{code: ErrCodeRestrictedContents, path: p, resolved: p}, 1)
}

// openDir opens the directory at p for a user. It returns the open directory and its
// verified canonical path.
func (fs *Filesystem) openDir(p string) (*os.File, string, error) {
	t, err := fs.locate(p, false, true)
	if err != nil {
		return nil, "", err
	}
	defer t.close()
	if err := t.check(); err != nil {
		return nil, "", err
	}
	if !t.exists() {
		return nil, "", notExistError(p)
	}
	if !t.isDir() {
		return nil, "", unix.ENOTDIR
	}
	f, err := t.open(unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, "", err
	}
	return f, t.canonical, nil
}

// File returns a reader for a file, as well as its stat information.
func (r *Restricted) File(p string) (ufs.File, Stat, error) {
	t, err := r.fs.locate(p, false, true)
	if err != nil {
		return nil, Stat{}, err
	}
	defer t.close()
	if err := t.check(); err != nil {
		return nil, Stat{}, err
	}
	if !t.exists() {
		return nil, Stat{}, notExistError(p)
	}

	f, err := t.open(unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, Stat{}, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, Stat{}, err
	}
	if r.fs.hardlinked(info) {
		_ = f.Close()
		return nil, Stat{}, hardlinkError(p)
	}

	if !info.Mode().IsRegular() && !info.IsDir() {
		_ = f.Close()
		return nil, Stat{}, notRegularError(p)
	}
	st, err := r.statOpen(f, info, t.level)
	if err != nil {
		_ = f.Close()
		return nil, Stat{}, err
	}
	return f, st, nil
}

// statOpen returns the Stat for an open file. The content of a protected file is never read to
// detect its MIME type, and neither is a named pipe or device, since reading one could block.
func (r *Restricted) statOpen(f *os.File, info ufs.FileInfo, lvl Level) (Stat, error) {
	if lvl == LevelNone && (info.Mode().IsRegular() || info.IsDir()) {
		return statFromFile(f)
	}
	mt := "application/octet-stream"
	if info.IsDir() {
		mt = "inode/directory"
	}
	return Stat{FileInfo: info, Mimetype: mt}, nil
}

// Stat returns the stat information for a file or directory. Protected paths are visible, so
// they are returned with Protected set.
func (r *Restricted) Stat(p string) (Stat, error) {
	t, err := r.fs.locate(p, false, true)
	if err != nil {
		return Stat{}, err
	}
	defer t.close()
	if t.level == LevelHidden || !t.exists() {
		return Stat{}, notExistError(p)
	}

	f, err := t.open(unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return Stat{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Stat{}, err
	}
	if r.fs.hardlinked(info) && !info.IsDir() {
		// Metadata of a hard linked file is still returned, but its content is not sniffed.
		st := Stat{FileInfo: info, Mimetype: "application/octet-stream", Protected: t.level == LevelProtected}
		return st, nil
	}
	st, err := r.statOpen(f, info, t.level)
	if err != nil {
		return Stat{}, err
	}
	st.Protected = t.level == LevelProtected
	return st, nil
}

// ListDirectory lists the entries of a directory. Hidden entries are left out and protected
// entries are flagged.
func (r *Restricted) ListDirectory(p string) ([]Stat, error) {
	return r.listDirectory(p, true)
}

// ReadDirStat is like ListDirectory, but returns the FileInfo for each entry and does not
// detect MIME types. Hidden entries are left out.
func (r *Restricted) ReadDirStat(p string) ([]ufs.FileInfo, error) {
	stats, err := r.listDirectory(p, false)
	if err != nil {
		return nil, err
	}
	out := make([]ufs.FileInfo, 0, len(stats))
	for _, st := range stats {
		out = append(out, st.FileInfo)
	}
	return out, nil
}

// listDirectory lists the directory at p, reading every entry through the directory's own
// descriptor.
func (r *Restricted) listDirectory(p string, withMime bool) ([]Stat, error) {
	dir, dirCanonical, err := r.fs.openDir(p)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	fd := int(dir.Fd())

	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil, err
	}

	out := make([]Stat, 0, len(names))
	for _, n := range names {
		entry := path.Join(dirCanonical, n)
		info, err := statAt(fd, n)
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return nil, err
		}

		lvl := r.fs.rules.levelAt(entry, kindOfInfo(info))
		if info.Mode()&ufs.ModeSymlink != 0 {
			lvl = max(lvl, r.fs.targetLevel(entry))
		}
		if lvl == LevelHidden {
			continue
		}

		st := Stat{FileInfo: info, Mimetype: "application/octet-stream", Protected: lvl == LevelProtected}
		switch {
		case info.Mode()&ufs.ModeSymlink != 0:
		case info.IsDir():
			st.Mimetype = "inode/directory"
		case withMime && info.Mode().IsRegular() && lvl != LevelProtected && !r.fs.hardlinked(info):
			if cf, err := unix.Openat(fd, n, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0); err == nil {
				f := os.NewFile(uintptr(cf), n)
				// Only a regular file is read, a FIFO swapped in for the entry would block the sniff.
				if fi, err := f.Stat(); err == nil && fi.Mode().IsRegular() {
					if m, err := mimetype.DetectReader(f); err == nil {
						st.Mimetype = m.String()
					}
				}
				_ = f.Close()
			}
		}
		out = append(out, st)
	}

	sortStats(out)
	return out, nil
}

// Write writes the contents of the reader to the file at p, the same as Filesystem.Write.
func (r *Restricted) Write(p string, reader io.Reader, newSize int64, mode ufs.FileMode) error {
	return r.fs.writeEntry(p, reader, newSize, mode, time.Time{}, false)
}

// Restore writes an entry from a backup to p. Hidden and protected files are never overwritten,
// so those entries are skipped, and so is a hard linked file that would be overwritten.
func (r *Restricted) Restore(p string, reader io.Reader, info ufs.FileInfo) error {
	if info.IsDir() {
		return r.fs.ensureDirectory(p, true)
	}
	return r.fs.writeEntry(p, reader, info.Size(), info.Mode(), info.ModTime(), true)
}

// RestoreSymlink creates a symbolic link at p pointing at target as part of a restore, with the
// same rules as Restore: missing parent directories are made, a hidden or protected entry is
// skipped, and so is an entry that already exists. The target is not checked, the same as Symlink.
func (r *Restricted) RestoreSymlink(p, target string) error {
	return r.fs.restoreSymlink(p, target)
}

// restoreSymlink creates the symbolic link p pointing at target, skipping it when p is restricted
// or already exists. See Restricted.RestoreSymlink.
func (fs *Filesystem) restoreSymlink(p, target string) error {
	t, err := fs.locate(p, true, false)
	if err != nil {
		return err
	}
	defer t.close()
	if t.level != LevelNone || t.exists() || t.dirfd < 0 || t.name == "." {
		return nil
	}
	return unix.Symlinkat(target, t.dirfd, t.name)
}

// WriteFrom writes the contents of r to p, creating the file or truncating it if it exists, and
// returns the number of bytes written. Each write is counted against the disk limit as it happens,
// so the size does not need to be known ahead of time. If writing fails the file is removed.
func (r *Restricted) WriteFrom(p string, reader io.Reader) (int64, error) {
	f, err := r.Touch(p, ufs.O_RDWR|ufs.O_TRUNC)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, reader)
	if err == nil {
		err = r.fs.chownFd(int(f.Fd()))
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = r.Delete(p)
		return n, err
	}
	return n, nil
}

// Touch opens the file at p, creating it if needed, the same as Filesystem.Touch.
func (r *Restricted) Touch(p string, flag int) (ufs.File, error) {
	t, err := r.fs.locate(p, true, true)
	if err != nil {
		return nil, err
	}
	defer t.close()
	if err := t.check(); err != nil {
		return nil, err
	}
	if t.name == "." || t.isDir() {
		return nil, &Error{code: ErrCodeIsDirectory, resolved: p}
	}

	if t.exists() && !t.st.Mode().IsRegular() {
		return nil, notRegularError(p)
	}
	f, err := t.open((flag&^unix.O_TRUNC)|unix.O_CREAT|unix.O_NONBLOCK, 0o644)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, &Error{code: ErrCodeIsDirectory, resolved: p}
	}
	if r.fs.hardlinked(info) {
		_ = f.Close()
		return nil, hardlinkError(p)
	}
	// The size being replaced is the size of the opened file, not the size it had when looked up.
	currentSize := info.Size()
	if flag&unix.O_TRUNC != 0 {
		if err := f.Truncate(0); err != nil {
			_ = f.Close()
			return nil, err
		}
		r.fs.unixFS.Add(-currentSize)
		currentSize = 0
	}
	return newQuotaFile(r.fs, f, currentSize), nil
}

// CreateDirectory creates the directory name within p, along with any missing parents.
func (r *Restricted) CreateDirectory(name string, p string) error {
	return r.fs.ensureDirectory(path.Join(p, name), false)
}

// Symlink creates a symbolic link at newpath. The target is not checked, since reading the
// link is subject to the rules for wherever it resolves to.
func (r *Restricted) Symlink(oldpath, newpath string) error {
	t, err := r.fs.locate(newpath, false, false)
	if err != nil {
		return err
	}
	defer t.close()
	if err := t.check(); err != nil {
		return err
	}
	if t.dirfd < 0 {
		return notExistError(newpath)
	}
	if t.name == "." {
		return unix.EEXIST
	}
	return unix.Symlinkat(oldpath, t.dirfd, t.name)
}

// Chtimes changes the access and modification times of a file.
func (r *Restricted) Chtimes(p string, atime, mtime time.Time) error {
	t, err := r.fs.locate(p, false, true)
	if err != nil {
		return err
	}
	defer t.close()
	if err := t.check(); err != nil {
		return err
	}
	if !t.exists() {
		return notExistError(p)
	}

	f, err := t.open(unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if r.fs.hardlinked(info) {
		return hardlinkError(p)
	}
	return setTimes(int(f.Fd()), atime, mtime)
}

// Chmod changes the mode of a file or directory. A directory that contains a restricted
// entry cannot be changed.
func (r *Restricted) Chmod(p string, mode ufs.FileMode) error {
	t, err := r.fs.locate(p, false, true)
	if err != nil {
		return err
	}
	defer t.close()
	if err := t.check(); err != nil {
		return err
	}
	if !t.exists() {
		return notExistError(p)
	}
	if t.isDir() {
		restricted, err := r.fs.containsRestrictedAt(t)
		if err != nil {
			return err
		}
		if restricted {
			return restrictedContentsError(p)
		}
	}

	f, err := t.open(unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if r.fs.hardlinked(info) {
		return hardlinkError(p)
	}
	return f.Chmod(mode)
}

// Chown gives the server user ownership of a single entry. Unlike Filesystem.Chown it never
// recurses, and the entry is not followed if it is a symbolic link.
func (r *Restricted) Chown(p string) error {
	t, err := r.fs.locate(p, false, false)
	if err != nil {
		return err
	}
	defer t.close()
	if err := t.check(); err != nil {
		return err
	}
	if !t.exists() {
		return notExistError(p)
	}
	if r.fs.isTest {
		return nil
	}
	return unix.Fchownat(t.dirfd, t.name, config.Get().System.User.Uid, config.Get().System.User.Gid, unix.AT_SYMLINK_NOFOLLOW)
}

// Rename moves the file or directory at from to to. Both locations are checked. A directory
// that contains a restricted entry cannot be moved, since the entry would be moved out from
// under its rules.
func (r *Restricted) Rename(from, to string) error {
	src, err := r.fs.locate(from, false, false)
	if err != nil {
		return err
	}
	defer src.close()
	if err := src.check(); err != nil {
		return err
	}
	if !src.exists() {
		return notExistError(from)
	}
	if src.name == "." {
		return NewBadPathResolution(from, "the root directory cannot be moved")
	}
	if src.isDir() {
		restricted, err := r.fs.containsRestrictedAt(src)
		if err != nil {
			return err
		}
		if restricted {
			return restrictedContentsError(from)
		}
	}

	// Missing parents of the destination are made, as the unixFS rename does. They are only made
	// after the destination's name has been checked.
	dst, err := r.fs.locate(to, true, false)
	if err != nil {
		return err
	}
	defer dst.close()
	if err := dst.check(); err != nil {
		return err
	}
	if dst.dirfd < 0 {
		return notExistError(to)
	}
	if dst.name == "." {
		return NewBadPathResolution(to, "the root directory cannot be replaced")
	}
	// The contents of a directory are checked under their names after the move too, so a
	// directory cannot be renamed to a restricted name to plant files under it.
	if src.isDir() {
		restricted, err := r.fs.containsRestrictedAs(src, dst.canonical)
		if err != nil {
			return err
		}
		if restricted {
			return restrictedContentsError(to)
		}
	}
	return unix.Renameat(src.dirfd, src.name, dst.dirfd, dst.name)
}

// Delete removes the file or directory at p. A directory that contains a restricted entry is
// refused, and the root directory cannot be deleted.
func (r *Restricted) Delete(p string) error {
	t, err := r.fs.locate(p, false, false)
	if err != nil {
		return err
	}
	defer t.close()
	if t.name == "." {
		return NewBadPathResolution(p, "the root directory cannot be deleted")
	}
	if err := t.check(); err != nil {
		return err
	}
	if !t.exists() {
		return notExistError(p)
	}
	if t.isDir() {
		restricted, err := r.fs.containsRestrictedAt(t)
		if err != nil {
			return err
		}
		if restricted {
			return restrictedContentsError(p)
		}
	}
	return r.fs.removeEntry(t.dirfd, t.name, t.canonical)
}

// Copy copies the file at p to a new file beside it. The source must not be restricted, and
// neither may the new file.
func (r *Restricted) Copy(p string) error {
	t, err := r.fs.locate(p, false, true)
	if err != nil {
		return err
	}
	defer t.close()
	if err := t.check(); err != nil {
		return err
	}
	if !t.exists() || !t.st.Mode().IsRegular() {
		return ufs.ErrNotExist
	}

	src, err := t.open(unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer src.Close()
	info, err := src.Stat()
	if err != nil {
		return err
	}
	if r.fs.hardlinked(info) {
		return hardlinkError(p)
	}
	size := info.Size()
	// Reserve the space so that copies happening at the same time cannot each use it.
	if err := r.fs.reserveDisk(size); err != nil {
		return err
	}
	// Release the reservation even if the copy panics, see Filesystem.Write.
	var used int64
	defer func() { r.fs.releaseDisk(size, used) }()

	base := t.name
	extension := filepath.Ext(base)
	baseName := strings.TrimSuffix(base, extension)
	// Ensure that ".tar" is also counted as apart of the file extension.
	if strings.HasSuffix(baseName, ".tar") {
		extension = ".tar" + extension
		baseName = strings.TrimSuffix(baseName, ".tar")
	}

	taken := func(n string) bool {
		return r.fs.rules.levelAt(path.Join(t.dir, n), kindUnknown) != LevelNone
	}
	newName, err := r.fs.findCopySuffix(t.dirfd, baseName, extension, taken)
	if err != nil {
		return err
	}
	newPath := path.Join(t.dir, newName)
	if lvl := r.fs.rules.levelAt(newPath, kindFile); lvl != LevelNone {
		return refusal(newPath, lvl)
	}

	dfd, err := unix.Openat(t.dirfd, newName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(info.Mode().Perm()))
	if err != nil {
		return err
	}
	dst := os.NewFile(uintptr(dfd), newPath)
	defer dst.Close()

	n, err := io.Copy(dst, io.LimitReader(src, size))
	used = n
	if err != nil {
		return err
	}
	return r.fs.chownFd(dfd)
}

// CompressFiles creates an archive of the given files in dir. Hidden and protected files are
// skipped rather than failing the whole archive, and so are hard linked files.
func (r *Restricted) CompressFiles(dir string, paths []string) (ufs.FileInfo, error) {
	d, dirCanonical, err := r.fs.openDir(dir)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	dirfd := int(d.Fd())

	// Never write into an existing file, such as an archive created by another request within
	// the same second.
	stamp := fmt.Sprintf("archive-%s", strings.ReplaceAll(time.Now().Format(time.RFC3339), ":", ""))
	var (
		name string
		af   ufs.File
	)
	for i := 0; ; i++ {
		name = stamp + ".tar.gz"
		if i > 0 {
			name = fmt.Sprintf("%s-%d.tar.gz", stamp, i)
		}
		if lvl := r.fs.rules.levelAt(path.Join(dirCanonical, name), kindFile); lvl != LevelNone {
			return nil, refusal(path.Join(dirCanonical, name), lvl)
		}
		af, err = r.fs.unixFS.OpenFileat(dirfd, name, ufs.O_WRONLY|ufs.O_CREATE|ufs.O_EXCL, 0o644)
		if err == nil {
			break
		}
		if !errors.Is(err, ufs.ErrExist) || i >= 100 {
			return nil, err
		}
	}

	// Count every write to the archive against the disk limit as it happens, so that archives
	// being created at the same time cannot each use all the space that is left.
	qf := newQuotaFile(r.fs, af, 0)
	a := &Archive{Filesystem: r.fs, BaseDirectory: dirCanonical, Files: paths, Restricted: true}
	if err := a.Stream(context.Background(), qf); err != nil {
		// Give back the space the partial archive used before removing it.
		if st, serr := qf.Stat(); serr == nil {
			r.fs.unixFS.Add(-st.Size())
		}
		_ = qf.Close()
		_ = unix.Unlinkat(dirfd, name, 0)
		return nil, err
	}
	st, err := qf.Stat()
	if err != nil {
		_ = qf.Close()
		return nil, err
	}
	if err := qf.Close(); err != nil {
		return nil, err
	}
	return st, nil
}

// DecompressFile extracts an archive in dir. Entries that would be written to a restricted
// location are skipped.
func (r *Restricted) DecompressFile(ctx context.Context, dir string, file string) error {
	d, dirCanonical, err := r.fs.openDir(dir)
	if err != nil {
		return err
	}
	_ = d.Close()

	t, err := r.fs.locate(path.Join(dir, file), false, true)
	if err != nil {
		return err
	}
	defer t.close()
	if err := t.check(); err != nil {
		return err
	}
	if !t.exists() {
		return notExistError(file)
	}
	f, err := t.open(unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if r.fs.hardlinked(info) {
		return hardlinkError(file)
	}
	if !info.Mode().IsRegular() {
		return notRegularError(file)
	}

	// The disk space the archive needs is read from the same descriptor that it is extracted from.
	if err := r.fs.spaceForArchive(ctx, f, file); err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}

	format, input, err := archives.Identify(ctx, filepath.Base(file), f)
	if err != nil {
		if errors.Is(err, archives.NoMatch) {
			return newFilesystemError(ErrCodeUnknownArchive, err)
		}
		return err
	}

	return r.fs.extractStream(ctx, extractStreamOptions{
		FileName:   file,
		Directory:  dirCanonical,
		Format:     format,
		Reader:     input,
		Restricted: true,
	})
}

// SpaceAvailableForDecompression checks if the archive at dir/file would fit on the server.
func (r *Restricted) SpaceAvailableForDecompression(ctx context.Context, dir string, file string) error {
	t, err := r.fs.locate(path.Join(dir, file), false, true)
	if err != nil {
		return err
	}
	defer t.close()
	if err := t.check(); err != nil {
		return err
	}
	if !t.exists() {
		return notExistError(file)
	}
	f, err := t.open(unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if r.fs.hardlinked(info) {
		return hardlinkError(file)
	}
	if !info.Mode().IsRegular() {
		return notRegularError(file)
	}
	return r.fs.spaceForArchive(ctx, f, file)
}

// TruncateRootDirectory removes the contents of the server's root directory. Hidden and
// protected files, along with the directories that contain them, are kept.
func (r *Restricted) TruncateRootDirectory() error {
	rootfd, err := r.fs.openDirPath(nil, false)
	if err != nil {
		return err
	}
	return r.fs.pruneDir(rootfd, "/")
}

// sortStats orders entries alphabetically, with directories listed before other entries.
func sortStats(out []Stat) {
	slices.SortStableFunc(out, func(a, b Stat) int {
		switch {
		case a.Name() == b.Name():
			return 0
		case a.Name() > b.Name():
			return 1
		default:
			return -1
		}
	})
	slices.SortStableFunc(out, func(a, b Stat) int {
		switch {
		case a.IsDir() && b.IsDir():
			return 0
		case a.IsDir():
			return -1
		default:
			return 1
		}
	})
}
