package filesystem

import (
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"emperror.dev/errors"
	"github.com/apex/log"
	"golang.org/x/sys/unix"

	"github.com/pterodactyl/wings/internal/ufs"
)

// Level describes how much access to a path is granted to users going through Wings.
type Level int

const (
	// LevelNone means the path has no restrictions.
	LevelNone Level = iota
	// LevelProtected means the path is visible in listings, but it cannot be read,
	// downloaded, written, deleted, moved, copied or included in an archive.
	LevelProtected
	// LevelHidden means the path behaves as if it does not exist for users going
	// through Wings.
	LevelHidden
)

// maxSymlinkHops limits how many symbolic links are followed while resolving a path.
const maxSymlinkHops = 40

var (
	// errOutsideRoot is returned when a symbolic link resolves to a location that is
	// not inside of the server root.
	errOutsideRoot = errors.New("filesystem: symbolic link resolves to a location outside the server root")
	// errSymlinkLoop is returned when too many symbolic links are followed.
	errSymlinkLoop = errors.New("filesystem: too many levels of symbolic links")
	// errStopWalk is used internally to stop a walk as soon as a restricted path is found.
	errStopWalk = errors.New("filesystem: stop walking")
)

// entryKind is the type of an entry, used to decide whether directory-only file
// rules apply to it.
type entryKind int

const (
	kindUnknown entryKind = iota
	kindFile
	kindDir
)

// fileRules holds the compiled hidden and protected rules for a server. They can be
// replaced at any time when the server configuration is synced with the Panel.
//
// The rules are gitignore-style lines. Supported syntax:
//   - Blank lines and lines starting with "#" are ignored. A leading "\" escapes a "#" or "!".
//   - "!" at the start negates a rule: a later negated rule re-allows what an earlier rule matched.
//   - A trailing "/" restricts a rule to directories. A directory rule also covers everything beneath it.
//   - A rule with no "/" other than a trailing one matches a name at any depth. A rule containing a
//     "/" is anchored to the server root, and a leading "/" is optional.
//   - "*" matches anything except "/", "?" matches one character except "/", "**" matches across
//     directories, and "[...]" / "[!...]" match a character class.
//
// A line that cannot be compiled is matched literally and a warning is logged, so that it can
// never silently stop protecting anything.
type fileRules struct {
	mu        sync.RWMutex
	hidden    []rule
	protected []rule
	// none is true when no lines are configured, which lets classification skip all of its
	// work. This is the case for most servers.
	none bool
}

// rule is a single compiled line.
type rule struct {
	re      *regexp.Regexp
	negate  bool
	dirOnly bool
}

func newFileRules(hidden, protected []string) *fileRules {
	r := &fileRules{}
	r.set(hidden, protected)
	return r
}

// set replaces the compiled rules. The lines are compiled before the lock is taken, so
// concurrent checks are only blocked for the moment the new rules are swapped in.
func (r *fileRules) set(hidden, protected []string) {
	h := compileRules(hidden)
	p := compileRules(protected)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.hidden = h
	r.protected = p
	r.none = len(hidden) == 0 && len(protected) == 0
}

// unrestricted reports whether no rules are configured, in which case nothing can be
// restricted.
func (r *fileRules) unrestricted() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.none
}

// compileRules compiles gitignore-style lines, see fileRules for the syntax.
func compileRules(lines []string) []rule {
	out := make([]rule, 0, len(lines))
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var r rule
		switch {
		case strings.HasPrefix(line, "!"):
			r.negate = true
			line = line[1:]
		case strings.HasPrefix(line, `\!`), strings.HasPrefix(line, `\#`):
			line = line[1:]
		}
		if strings.HasSuffix(line, "/") {
			r.dirOnly = true
			line = strings.TrimRight(line, "/")
		}
		anchored := strings.Contains(line, "/")
		line = strings.TrimPrefix(line, "/")
		if line == "" {
			continue
		}

		re, err := compileGlob(line, anchored)
		if err != nil {
			log.WithField("pattern", raw).WithField("error", err).Warn("file rule could not be compiled, matching it literally")
			re = regexp.MustCompile(`(?s)^/(?:.*/)?` + regexp.QuoteMeta(line) + `(?:/.*)?$`)
			if anchored {
				re = regexp.MustCompile("(?s)^/" + regexp.QuoteMeta(line) + `(?:/.*)?$`)
			}
		}
		r.re = re
		out = append(out, r)
	}
	return out
}

// compileGlob turns a glob (without leading or trailing slashes) into a regular expression
// matched against absolute paths such as "/plugins/Licensed.jar". The expression also matches
// everything beneath a match.
func compileGlob(glob string, anchored bool) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("(?s)^/")
	if !anchored {
		b.WriteString("(?:.*/)?")
	}
	b.WriteString(translateGlob(glob))
	b.WriteString("(?:/.*)?$")
	return regexp.Compile(b.String())
}

// translateGlob converts the glob syntax to regular expression syntax. Everything that is not
// a glob operator is quoted, so no character in a rule can change the meaning of the expression.
func translateGlob(glob string) string {
	runes := []rune(glob)
	var b strings.Builder
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch c {
		case '*':
			if i+1 < len(runes) && runes[i+1] == '*' {
				if i+2 < len(runes) && runes[i+2] == '/' {
					b.WriteString("(?:.*/)?")
					i += 2
					continue
				}
				b.WriteString(".*")
				i++
				continue
			}
			b.WriteString("[^/]*")
		case '?':
			b.WriteString("[^/]")
		case '[':
			end := -1
			for j := i + 2; j < len(runes); j++ {
				if runes[j] == ']' {
					end = j
					break
				}
			}
			if end < 0 {
				b.WriteString(`\[`)
				continue
			}
			class := runes[i+1 : end]
			b.WriteByte('[')
			if class[0] == '!' {
				b.WriteByte('^')
				class = class[1:]
			}
			b.WriteString(strings.ReplaceAll(string(class), `\`, `\\`))
			b.WriteByte(']')
			i = end
		case '\\':
			if i+1 < len(runes) {
				i++
				b.WriteString(regexp.QuoteMeta(string(runes[i])))
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return b.String()
}

// matchRules reports whether p is matched by the rules, the last rule that applies deciding.
func matchRules(rules []rule, p string, isDir bool) bool {
	matched := false
	for _, r := range rules {
		if r.dirOnly && !isDir {
			continue
		}
		if r.re.MatchString(p) {
			matched = !r.negate
		}
	}
	return matched
}

// levelOf returns the level for a single absolute path. isDir is whether the path is a directory.
func (r *fileRules) levelOf(p string, isDir bool) Level {
	if matchRules(r.hidden, p, isDir) {
		return LevelHidden
	}
	if matchRules(r.protected, p, isDir) {
		return LevelProtected
	}
	return LevelNone
}

// levelAt returns the strongest level that applies to p, an absolute path such as
// "/plugins/Licensed.jar". Every ancestor directory is matched as a directory since a rule
// for a directory applies to everything beneath it.
func (r *fileRules) levelAt(p string, kind entryKind) Level {
	if p == "/" {
		return LevelNone
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.none {
		return LevelNone
	}

	var lvl Level
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	prefix := ""
	for _, part := range parts[:len(parts)-1] {
		prefix += "/" + part
		lvl = max(lvl, r.levelOf(prefix, true))
		if lvl == LevelHidden {
			return lvl
		}
	}

	switch kind {
	case kindDir:
		lvl = max(lvl, r.levelOf(p, true))
	case kindFile:
		lvl = max(lvl, r.levelOf(p, false))
	default:
		// The entry does not exist (or its type is unknown), so it could be either.
		lvl = max(lvl, r.levelOf(p, true), r.levelOf(p, false))
	}
	return lvl
}

// cleanPath normalizes a path given relative to the server root into an absolute path
// beginning with a slash. It is only for paths that are already known to be relative to
// the root; user supplied paths must go through logicalPath.
func cleanPath(p string) string {
	return path.Clean("/" + filepath.ToSlash(p))
}

// logicalPath returns the absolute path, relative to the server root, that a user supplied
// path refers to. It uses the exact normalization of the unixFS, so the result names the
// same location the filesystem operations will act on. An error is returned if the path
// does not refer to a location inside of the server root.
func (fs *Filesystem) logicalPath(p string) (string, error) {
	rel, err := fs.unixFS.RelPath(p)
	if err != nil {
		return "", err
	}
	if rel == "." {
		return "/", nil
	}
	return "/" + rel, nil
}

// splitPath splits a path into its components. Empty components are included.
func splitPath(p string) []string {
	return strings.Split(filepath.ToSlash(p), "/")
}

// isUnresolvable reports whether err means that a path cannot be resolved inside of the
// server root.
func isUnresolvable(err error) bool {
	return errors.Is(err, errOutsideRoot) || errors.Is(err, errSymlinkLoop) || errors.Is(err, ufs.ErrBadPathResolution)
}

// lstatLink returns the information about p without following a symbolic link at its final
// component. If p is a symbolic link, the target it points to is also returned.
//
// This is a path based lookup. It is only used to decide which location to inspect, every
// decision that allows an operation is made again on an open file descriptor (see safe.go).
func (fs *Filesystem) lstatLink(p string) (ufs.FileInfo, string, error) {
	dirfd, name, closeFd, err := fs.unixFS.SafePath(p)
	defer closeFd()
	if err != nil {
		return nil, "", err
	}
	st, err := fs.unixFS.Lstatat(dirfd, name)
	if err != nil {
		return nil, "", err
	}
	if st.Mode()&ufs.ModeSymlink == 0 {
		return st, "", nil
	}
	buf := make([]byte, unix.PathMax)
	n, err := unix.Readlinkat(dirfd, name, buf)
	if err != nil {
		return nil, "", err
	}
	return st, string(buf[:n]), nil
}

// kindOf returns the kind of the entry at p, without following a symbolic link at its final
// component. Symbolic links are treated as files, the same as gitignore.
func (fs *Filesystem) kindOf(p string) entryKind {
	st, _, err := fs.lstatLink(p)
	if err != nil {
		return kindUnknown
	}
	return kindOfInfo(st)
}

// kindOfInfo returns the entry kind for the information from an lstat call.
func kindOfInfo(st ufs.FileInfo) entryKind {
	if st.Mode()&ufs.ModeSymlink == 0 && st.IsDir() {
		return kindDir
	}
	return kindFile
}

// resolvePath returns the location p points to after every symbolic link along the way,
// including a final one, has been followed. The result is an absolute path relative to the
// server root. Components that do not exist are kept as they are.
//
// Each component is resolved on its own against the real directory it is in, which is the
// same way the kernel resolves a path. Resolving the path lexically would disagree with the
// kernel for targets such as "sub/../file" when "sub" is a link.
//
// Like lstatLink this is only used to choose a location to inspect, never to authorize access.
func (fs *Filesystem) resolvePath(p string) (string, error) {
	var resolved []string
	pending := splitPath(p)
	hops := 0

	for len(pending) > 0 {
		c := pending[0]
		pending = pending[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			if len(resolved) == 0 {
				return "", errOutsideRoot
			}
			resolved = resolved[:len(resolved)-1]
			continue
		}

		cur := path.Join("/"+strings.Join(resolved, "/"), c)
		st, target, err := fs.lstatLink(cur)
		if err != nil {
			if !errors.Is(err, ufs.ErrNotExist) && !isNotDirectory(err) {
				return "", err
			}
			// Nothing exists here, so nothing beneath it can be a symbolic link either.
			resolved = append(resolved, c)
			continue
		}
		if st.Mode()&ufs.ModeSymlink == 0 {
			resolved = append(resolved, c)
			continue
		}

		hops++
		if hops > maxSymlinkHops {
			return "", errSymlinkLoop
		}
		if path.IsAbs(target) {
			// Absolute targets are only followed when they point inside of the root.
			base := strings.TrimSuffix(fs.Path(), "/")
			if !strings.HasPrefix(target+"/", base+"/") {
				return "", errOutsideRoot
			}
			target = strings.TrimPrefix(target, base)
			resolved = nil
		}
		// Relative targets are relative to the directory the link lives in, which is the
		// resolved path so far.
		pending = append(splitPath(target), pending...)
	}

	return "/" + strings.Join(resolved, "/"), nil
}

// Classify returns the strongest restriction that applies to p. Both the path as it was
// requested and the location it resolves to after following symbolic links are checked.
//
// This is a path based check for callers that only need an answer, such as tests and the
// classification of symbolic link targets. Operations on user input do not rely on it: they
// check the location of the file descriptor they actually act on (see safe.go).
func (fs *Filesystem) Classify(p string) (Level, error) {
	logical, err := fs.logicalPath(p)
	if err != nil {
		return LevelNone, err
	}
	if logical == "/" || fs.rules.unrestricted() {
		return LevelNone, nil
	}

	canonical, err := fs.resolvePath(logical)
	if err != nil {
		if !isUnresolvable(err) {
			return LevelNone, err
		}
		canonical = ""
	}

	lvl := fs.rules.levelAt(logical, fs.kindOf(logical))
	if canonical != "" && canonical != logical {
		lvl = max(lvl, fs.rules.levelAt(canonical, fs.kindOf(canonical)))
	}
	return lvl, nil
}

// walkClassifier classifies the entries found while walking a directory whose canonical
// location is known. Walks never follow symbolic links, so every entry that is not a
// symbolic link sits at the same relative location beneath the walked directory. Symbolic
// links found by the walk are classified by the location they point to.
type walkClassifier struct {
	fs *Filesystem
	// base is the canonical path the walk started from.
	base string
}

// newWalkClassifier returns a classifier for entries beneath the canonical directory base.
func (fs *Filesystem) newWalkClassifier(base string) *walkClassifier {
	return &walkClassifier{fs: fs, base: cleanPath(base)}
}

// Classify returns the restriction for an entry at rel, a path relative to the base of the walk.
func (w *walkClassifier) Classify(rel string, isDir, isSymlink bool) (Level, error) {
	if w.fs.rules.unrestricted() {
		return LevelNone, nil
	}
	if isSymlink {
		return w.fs.Classify(path.Join(w.base, rel))
	}

	kind := kindFile
	if isDir {
		kind = kindDir
	}
	return w.fs.rules.levelAt(path.Join(w.base, rel), kind), nil
}
