package filesystem

import (
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"emperror.dev/errors"
	"golang.org/x/sys/unix"

	"github.com/pterodactyl/wings/config"
	"github.com/pterodactyl/wings/internal/ufs"
)

// This file contains the descriptor based primitives used for every user-facing operation.
//
// The rules are checked against where an operation will actually act, not against the path
// a user typed. A path is resolved one component at a time, each directory is opened with
// O_NOFOLLOW from the directory before it, and the location the descriptor really refers to is
// read back from /proc/self/fd. The operation is then performed through the same descriptor, so
// a symbolic link or a moved directory swapped in after the check cannot redirect the operation.

// testLocateHook, when set by a test, runs between opening the directories of an entry and
// verifying where they are. It lets a test swap a directory for a symbolic link in that window.
var testLocateHook func(stage string)

// errRaced is returned internally when the location of a descriptor no longer matches the
// location it was checked at. The operation is retried, or refused.
var errRaced = errors.New("filesystem: path changed while it was being accessed")

// target is an entry inside of the server root, located without following symbolic links.
type target struct {
	fs *Filesystem
	// dirfd is an open directory that contains the entry. It is -1 when the containing
	// directory does not exist, which means the entry does not exist either. For the root
	// directory it is an open descriptor for the root itself.
	dirfd int
	// name is the entry's name within dirfd, or "." for the root directory.
	name string
	// dir is the verified canonical path of the containing directory.
	dir string
	// canonical is the verified canonical path of the entry, such as "/plugins/a.jar".
	canonical string
	// st is the lstat of the entry, nil if it does not exist.
	st ufs.FileInfo
	// level is the restriction that applies to the entry.
	level Level
}

// close releases the containing directory.
func (t *target) close() {
	if t.dirfd >= 0 {
		_ = unix.Close(t.dirfd)
		t.dirfd = -1
	}
}

// exists reports whether the entry exists.
func (t *target) exists() bool {
	return t.dirfd >= 0 && t.st != nil
}

// isDir reports whether the entry is a directory. Symbolic links are never directories.
func (t *target) isDir() bool {
	return t.exists() && t.st.Mode()&ufs.ModeSymlink == 0 && t.st.IsDir()
}

// check returns the error that refuses user access to the entry, if it is restricted.
func (t *target) check() error {
	return refusal(t.canonical, t.level)
}

// open opens the entry without following a symbolic link at its final component, and checks
// that the file descriptor still refers to the location the entry was checked at.
func (t *target) open(flags int, perm uint32) (*os.File, error) {
	fd, err := unix.Openat(t.dirfd, t.name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, perm)
	if err != nil {
		return nil, err
	}
	if err := t.fs.verifyFd(fd, t.canonical); err != nil {
		_ = unix.Close(fd)
		return nil, racedError(t.canonical)
	}
	return os.NewFile(uintptr(fd), t.canonical), nil
}

// refusal returns the error that prevents user access to p at the given level. Hidden paths
// report that they do not exist, protected paths are denied.
func refusal(p string, lvl Level) error {
	switch lvl {
	case LevelHidden:
		return hiddenError(p)
	case LevelProtected:
		return protectedError(p)
	}
	return nil
}

// racedError is returned when a path keeps changing while it is accessed. It is reported
// the same way as a path that resolves outside of the server root.
func racedError(p string) error {
	return errors.WithStackDepth(&Error{code: ErrCodePathResolution, path: p, resolved: p}, 1)
}

// rootTarget returns the root directory as a target.
func (fs *Filesystem) rootTarget() (*target, error) {
	dirfd, err := fs.openDirPath(nil, false)
	if err != nil {
		return nil, err
	}
	st, err := statAt(dirfd, ".")
	if err != nil {
		_ = unix.Close(dirfd)
		return nil, err
	}
	return &target{fs: fs, dirfd: dirfd, name: ".", dir: "/", canonical: "/", st: st}, nil
}

// locate finds the entry at p. Each directory on the way is opened without following
// symbolic links, and the rules are checked against the location that was actually reached.
//
// If create is set, missing parent directories are made, but only after the path has been
// checked, so nothing is created inside a restricted location. If follow is set, a symbolic
// link at the final component is followed; otherwise the link itself is the entry.
//
// The returned target always has its level set, and the caller must call close on it. A
// restricted entry is returned with its level rather than as an error, so the caller can
// decide what the user should be told.
func (fs *Filesystem) locate(p string, create, follow bool) (*target, error) {
	logical, err := fs.logicalPath(p)
	if err != nil {
		return nil, err
	}
	// requested is the path as the user named it. The rules also apply to that name, so a
	// symbolic link whose own name is hidden or protected is restricted even when it resolves
	// to something visible.
	requested := logical

	for hops := 0; hops <= maxSymlinkHops; hops++ {
		canonical, err := fs.canonicalFor(logical, follow)
		if err != nil {
			return nil, err
		}
		if canonical == "/" {
			return fs.rootTarget()
		}
		comps, name := splitCanonical(canonical)

		// Decide before anything is created, using the path as it resolves now. Creating
		// the directories of a path that is restricted would leave files behind.
		if create {
			if lvl := fs.requestedLevel(requested, canonical, kindUnknown); lvl != LevelNone {
				return &target{fs: fs, dirfd: -1, name: name, dir: path.Dir(canonical), canonical: canonical, level: lvl}, nil
			}
		}

		dirfd, err := fs.openDirPath(comps, create)
		if err != nil {
			switch {
			case (errors.Is(err, unix.ENOENT) || isNotDirectory(err)) && !create:
				// Nothing can exist beneath a missing or non-directory parent. The level is
				// still computed, so that a hidden parent answers the same way whether or not
				// it exists.
				lvl := fs.requestedLevel(requested, canonical, kindUnknown)
				return &target{fs: fs, dirfd: -1, name: name, dir: path.Dir(canonical), canonical: canonical, level: lvl}, nil
			case errors.Is(err, unix.ELOOP):
				// A directory was replaced with a symbolic link since it was resolved.
				logical = canonical
				continue
			}
			return nil, err
		}

		if testLocateHook != nil {
			testLocateHook("after-open")
		}
		parent := "/" + strings.Join(comps, "/")
		if err := fs.verifyFd(dirfd, parent); err != nil {
			// A directory was moved after it was opened. Resolve the path again.
			_ = unix.Close(dirfd)
			logical = canonical
			continue
		}

		st, err := statAt(dirfd, name)
		if err != nil && !errors.Is(err, unix.ENOENT) {
			_ = unix.Close(dirfd)
			return nil, err
		}
		if st != nil && st.Mode()&ufs.ModeSymlink != 0 && follow {
			link, err := readlinkAt(dirfd, name)
			_ = unix.Close(dirfd)
			if err != nil {
				return nil, err
			}
			next, err := fs.linkLogical(parent, link)
			if err != nil {
				return nil, err
			}
			logical = next
			continue
		}

		entry := path.Join(parent, name)
		kind := kindUnknown
		if st != nil {
			kind = kindOfInfo(st)
		}
		lvl := fs.requestedLevel(requested, entry, kind)
		if st != nil && st.Mode()&ufs.ModeSymlink != 0 {
			// A link that is not followed is itself the entry, but what it points to must
			// not be reachable through it either.
			lvl = max(lvl, fs.targetLevel(entry))
		}
		return &target{fs: fs, dirfd: dirfd, name: name, dir: parent, canonical: entry, st: st, level: lvl}, nil
	}
	return nil, racedError(p)
}

// requestedLevel returns the restriction on an entry, given the path it was requested by and the
// location that path resolves to. Both names are checked, so a link cannot hide a restricted name.
func (fs *Filesystem) requestedLevel(requested, canonical string, kind entryKind) Level {
	lvl := fs.rules.levelAt(canonical, kind)
	if requested != canonical {
		lvl = max(lvl, fs.rules.levelAt(requested, kindUnknown))
	}
	return lvl
}

// isNotDirectory reports whether err means a path component is not a directory.
func isNotDirectory(err error) bool {
	return errors.Is(err, unix.ENOTDIR) || errors.Is(err, ufs.ErrNotDirectory)
}

// canonicalFor returns the location p refers to, with every symbolic link in its directories
// followed. The final component is only followed if follow is set.
func (fs *Filesystem) canonicalFor(logical string, follow bool) (string, error) {
	if follow {
		return fs.resolvePath(logical)
	}
	dir, base := path.Split(logical)
	parent, err := fs.resolvePath(dir)
	if err != nil {
		return "", err
	}
	return path.Join(parent, base), nil
}

// linkLogical returns the path a symbolic link in the directory parent points to. The result
// is not cleaned, so that ".." components are resolved against the links they follow, the same
// way the kernel resolves them.
func (fs *Filesystem) linkLogical(parent, link string) (string, error) {
	if !path.IsAbs(link) {
		return parent + "/" + link, nil
	}
	real := fs.realBase
	switch {
	case link == real || link == real+"/":
		return "/", nil
	case strings.HasPrefix(link, real+"/"):
		return link[len(real):], nil
	}
	return "", errOutsideRoot
}

// targetLevel returns the restriction on the location a symbolic link points to.
func (fs *Filesystem) targetLevel(canonical string) Level {
	if fs.rules.unrestricted() {
		return LevelNone
	}
	resolved, err := fs.resolvePath(canonical)
	if err != nil || resolved == canonical {
		return LevelNone
	}
	return fs.rules.levelAt(resolved, fs.kindOf(resolved))
}

// splitCanonical splits an absolute canonical path into the directories above it and its
// final component. The path must not be the root.
func splitCanonical(canonical string) ([]string, string) {
	parts := strings.Split(strings.TrimPrefix(canonical, "/"), "/")
	last := len(parts) - 1
	return parts[:last], parts[last]
}

// openDirPath opens the directory made of the given components, starting at the root. No
// symbolic link is followed. If create is set, missing directories are made and owned by the
// server user.
func (fs *Filesystem) openDirPath(comps []string, create bool) (int, error) {
	fd, err := unix.Open(fs.realBase, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, c := range comps {
		next, err := unix.Openat(fd, c, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err == unix.ENOENT && create {
			if err := unix.Mkdirat(fd, c, 0o755); err != nil {
				_ = unix.Close(fd)
				return -1, err
			}
			next, err = unix.Openat(fd, c, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err == nil {
				if err := fs.chownFd(next); err != nil {
					_ = unix.Close(next)
					_ = unix.Close(fd)
					return -1, err
				}
			}
		}
		_ = unix.Close(fd)
		if err != nil {
			return -1, err
		}
		fd = next
	}
	return fd, nil
}

// fdPath returns the canonical path, relative to the server root, that an open file descriptor
// currently refers to. The kernel reports the location the descriptor was opened at, which
// is what the descriptor's operations act on, even if the directories above it have changed.
// An error is returned if the descriptor is outside of the server root.
func (fs *Filesystem) fdPath(fd int) (string, error) {
	host, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return "", err
	}
	switch {
	case host == fs.realBase:
		return "/", nil
	case strings.HasPrefix(host, fs.realBase+"/"):
		return host[len(fs.realBase):], nil
	}
	return "", errOutsideRoot
}

// verifyFd checks that the file descriptor refers to the canonical path want.
func (fs *Filesystem) verifyFd(fd int, want string) error {
	got, err := fs.fdPath(fd)
	if err != nil || got != want {
		return errRaced
	}
	return nil
}

// statAt returns the lstat information for name within dirfd, without following a symbolic
// link. The error wraps ENOENT if the entry does not exist.
func statAt(dirfd int, name string) (ufs.FileInfo, error) {
	fd, err := unix.Openat(dirfd, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	return f.Stat()
}

// readlinkAt returns the target of the symbolic link name within dirfd.
func readlinkAt(dirfd int, name string) (string, error) {
	buf := make([]byte, unix.PathMax)
	n, err := unix.Readlinkat(dirfd, name, buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

// chownFd gives the server user ownership of an open file or directory.
func (fs *Filesystem) chownFd(fd int) error {
	if fs.isTest {
		return nil
	}
	return unix.Fchown(fd, config.Get().System.User.Uid, config.Get().System.User.Gid)
}

// setTimes sets the access and modification times of an open file or directory.
func setTimes(fd int, atime, mtime time.Time) error {
	ts := []unix.Timespec{unix.NsecToTimespec(atime.UnixNano()), unix.NsecToTimespec(mtime.UnixNano())}
	return unix.UtimesNanoAt(fd, "", ts, unix.AT_EMPTY_PATH)
}

// hardlinked reports whether a regular file has more than one name. Rules are enforced on
// names, so once any rules are configured a file that can be reached by another name is
// refused.
func (fs *Filesystem) hardlinked(info ufs.FileInfo) bool {
	if fs.rules.unrestricted() || !info.Mode().IsRegular() {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Nlink > 1
}

// ContainsRestricted reports whether dir, or any file or directory beneath it, is hidden or
// protected. Symbolic links found while walking are not followed, but are classified by the
// location they point to.
func (fs *Filesystem) ContainsRestricted(dir string) (bool, error) {
	if fs.rules.unrestricted() {
		return false, nil
	}
	t, err := fs.locate(dir, false, true)
	if err != nil {
		return false, err
	}
	defer t.close()
	if !t.exists() {
		return false, nil
	}
	return fs.containsRestrictedAt(t)
}

// containsRestrictedAt walks the directory the target refers to, starting from the descriptor
// it was located with. It stops at the first restricted entry.
func (fs *Filesystem) containsRestrictedAt(t *target) (bool, error) {
	return fs.containsRestrictedAs(t, t.canonical)
}

// containsRestrictedAs is containsRestrictedAt with the directory treated as if it were at
// base. It is used before a directory is moved, to check the names its contents would have
// after the move.
func (fs *Filesystem) containsRestrictedAs(t *target, base string) (bool, error) {
	if fs.rules.unrestricted() || !t.isDir() {
		return false, nil
	}
	w := fs.newWalkClassifier(base)
	found := false
	err := fs.unixFS.WalkDirat(t.dirfd, t.name, func(_ int, _, rel string, d ufs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		lvl, err := w.Classify(rel, d.IsDir(), d.Type()&ufs.ModeSymlink != 0)
		if err != nil {
			return err
		}
		if lvl != LevelNone {
			found = true
			return errStopWalk
		}
		return nil
	})
	if found {
		return true, nil
	}
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return false, err
	}
	return false, nil
}

// removeEntry removes the entry name from dirfd, and everything beneath it if it is a
// directory. Every entry is checked before it is removed, so a restricted file that appears
// in the tree while it is being removed stops the removal rather than being deleted.
func (fs *Filesystem) removeEntry(dirfd int, name, canonical string) error {
	st, err := statAt(dirfd, name)
	if err != nil {
		return err
	}
	if lvl := fs.entryLevel(canonical, st); lvl != LevelNone {
		return refusal(canonical, lvl)
	}

	if st.IsDir() && st.Mode()&ufs.ModeSymlink == 0 {
		fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		dir := os.NewFile(uintptr(fd), canonical)
		defer dir.Close()
		if err := fs.verifyFd(fd, canonical); err != nil {
			return racedError(canonical)
		}
		names, err := dir.Readdirnames(-1)
		if err != nil {
			return err
		}
		for _, n := range names {
			if err := fs.removeEntry(fd, n, path.Join(canonical, n)); err != nil {
				return err
			}
		}
		return unix.Unlinkat(dirfd, name, unix.AT_REMOVEDIR)
	}

	if st.Mode().IsRegular() {
		if err := unix.Unlinkat(dirfd, name, 0); err != nil {
			return err
		}
		fs.unixFS.Add(-st.Size())
		return nil
	}
	return unix.Unlinkat(dirfd, name, 0)
}

// entryLevel returns the restriction on an entry, given its lstat. A symbolic link is restricted
// if it has a restricted name, or if it points to a restricted location.
func (fs *Filesystem) entryLevel(canonical string, st ufs.FileInfo) Level {
	lvl := fs.rules.levelAt(canonical, kindOfInfo(st))
	if st.Mode()&ufs.ModeSymlink != 0 {
		lvl = max(lvl, fs.targetLevel(canonical))
	}
	return lvl
}

// pruneDir removes everything from the directory dirfd that is not restricted. Directories
// that contain restricted files are emptied of everything else. dirfd is owned by the call.
func (fs *Filesystem) pruneDir(dirfd int, canonical string) error {
	dir := os.NewFile(uintptr(dirfd), canonical)
	defer dir.Close()
	if err := fs.verifyFd(dirfd, canonical); err != nil {
		return racedError(canonical)
	}
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, n := range names {
		childCanonical := path.Join(canonical, n)
		st, err := statAt(dirfd, n)
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return err
		}
		if fs.entryLevel(childCanonical, st) != LevelNone {
			continue
		}
		if st.IsDir() && st.Mode()&ufs.ModeSymlink == 0 {
			child := &target{fs: fs, dirfd: dirfd, name: n, dir: canonical, canonical: childCanonical, st: st}
			restricted, err := fs.containsRestrictedAt(child)
			if err != nil {
				return err
			}
			if restricted {
				cfd, err := unix.Openat(dirfd, n, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				if err != nil {
					return err
				}
				if err := fs.pruneDir(cfd, childCanonical); err != nil {
					return err
				}
				continue
			}
		}
		if err := fs.removeEntry(dirfd, n, childCanonical); err != nil {
			return err
		}
	}
	return nil
}

// ensureDirectory creates the directory at p, and any missing parents, owned by the server
// user. If skipRestricted is set, a restricted location is skipped rather than refused.
func (fs *Filesystem) ensureDirectory(p string, skipRestricted bool) error {
	t, err := fs.locate(p, true, true)
	if err != nil {
		return err
	}
	defer t.close()
	if t.level != LevelNone {
		if skipRestricted {
			return nil
		}
		return t.check()
	}
	if t.exists() {
		if t.isDir() {
			return nil
		}
		return unix.ENOTDIR
	}
	if t.name == "." {
		return nil
	}
	if err := unix.Mkdirat(t.dirfd, t.name, 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	fd, err := unix.Openat(t.dirfd, t.name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return fs.chownFd(fd)
}

// writeEntry writes rd to the file at p, replacing its contents. A size below zero means the
// size is not known, in which case the data is accounted for as it is written. The mtime is
// applied when it is not zero.
//
// If skipRestricted is set, a restricted file, or one that is hard linked, is skipped instead
// of being refused.
func (fs *Filesystem) writeEntry(p string, rd io.Reader, size int64, mode ufs.FileMode, mtime time.Time, skipRestricted bool) error {
	t, err := fs.locate(p, true, true)
	if err != nil {
		return err
	}
	defer t.close()
	if t.level != LevelNone {
		if skipRestricted {
			return nil
		}
		return t.check()
	}
	if t.name == "." || t.isDir() {
		return &Error{code: ErrCodeIsDirectory, resolved: p}
	}

	var currentSize int64
	if t.exists() && t.st.Mode().IsRegular() {
		currentSize = t.st.Size()
	}
	// Reserve the space for the write, so that writes happening at the same time cannot each use
	// the space that is left. The reservation is released when the write finishes. A write of an
	// unknown size reserves the space for each chunk as it is read instead.
	var reserved, used int64
	if size >= 0 {
		if err := fs.reserveDisk(size - currentSize); err != nil {
			return err
		}
		reserved = max(size-currentSize, 0)
	}
	defer func() { fs.releaseDisk(reserved, used) }()

	if t.exists() && !t.st.Mode().IsRegular() {
		if skipRestricted {
			return nil
		}
		return notRegularError(p)
	}
	f, err := t.open(unix.O_WRONLY|unix.O_CREAT|unix.O_NONBLOCK, uint32(mode.Perm()))
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return &Error{code: ErrCodeIsDirectory, resolved: p}
	}
	if fs.hardlinked(info) {
		if skipRestricted {
			return nil
		}
		return hardlinkError(p)
	}
	if err := f.Truncate(0); err != nil {
		return err
	}

	// The old contents are gone once the file is truncated.
	used = -currentSize
	var n int64
	switch {
	case size == 0:
	case size > 0:
		n, err = io.Copy(f, io.LimitReader(rd, size))
		used = n - currentSize
	default:
		// Each chunk reserves its own space as it is written, so only the old contents are
		// removed from the usage here.
		n, err = copyWithQuota(fs, f, rd)
		fs.unixFS.Add(-currentSize)
		used = 0
	}
	if err != nil {
		return err
	}

	if err := fs.chownFd(int(f.Fd())); err != nil {
		return err
	}
	if !mtime.IsZero() {
		return setTimes(int(f.Fd()), mtime, mtime)
	}
	return nil
}

// copyWithQuota copies rd into dst, checking the disk quota before each chunk is written.
func copyWithQuota(fs *Filesystem, dst io.Writer, rd io.Reader) (int64, error) {
	var total int64
	buf := make([]byte, 4096)
	for {
		n, rerr := rd.Read(buf)
		if n > 0 {
			if err := fs.reserveDisk(int64(n)); err != nil {
				return total, err
			}
			w, err := dst.Write(buf[:n])
			fs.releaseDisk(int64(n), int64(w))
			total += int64(w)
			if err != nil {
				return total, err
			}
		}
		if rerr == io.EOF {
			return total, nil
		}
		if rerr != nil {
			return total, rerr
		}
	}
}
