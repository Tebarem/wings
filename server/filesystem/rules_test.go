package filesystem

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/franela/goblin"
)

// newRestrictedFs returns a filesystem with the given rules applied.
func newRestrictedFs(t *testing.T, hidden, protected []string) (*Filesystem, *rootFs) {
	t.Helper()
	fs, rfs := NewFs()
	fs.SetRules(hidden, protected)
	return fs, rfs
}

// mustWriteFile creates a file (and its parents) within the server root.
func mustWriteFile(t *testing.T, rfs *rootFs, p, content string) {
	t.Helper()
	full := filepath.Join(rfs.root, "server", p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// mustMkdir creates a directory (and its parents) within the server root.
func mustMkdir(t *testing.T, rfs *rootFs, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(rfs.root, "server", p), 0o755); err != nil {
		t.Fatal(err)
	}
}

// mustSymlink creates a symbolic link within the server root.
func mustSymlink(t *testing.T, rfs *rootFs, target, link string) {
	t.Helper()
	if err := os.Symlink(target, filepath.Join(rfs.root, "server", link)); err != nil {
		t.Fatal(err)
	}
}

func TestFilesystem_Classify(t *testing.T) {
	g := Goblin(t)

	g.Describe("Classify", func() {
		fs, rfs := newRestrictedFs(t, []string{"/hidden.txt", "hiddendir/"}, []string{"/Licensed.jar", "secrets/", "*.key", "/d/x"})
		mustWriteFile(t, rfs, "hidden.txt", "hidden")
		mustWriteFile(t, rfs, "Licensed.jar", "protected")
		mustWriteFile(t, rfs, "plain.txt", "plain")
		mustWriteFile(t, rfs, "hiddendir/file.txt", "hidden")
		mustWriteFile(t, rfs, "secrets/a/b.txt", "protected")
		mustWriteFile(t, rfs, "nested/Licensed.jar", "not at the root, so the anchored pattern does not apply")
		mustWriteFile(t, rfs, "nested/token.key", "protected")
		// "sub" is a link to "d/e", so "sub/../x" is "d/x" for the kernel, but "x" when the path
		// is cleaned lexically.
		mustWriteFile(t, rfs, "d/e/keep", "plain")
		mustWriteFile(t, rfs, "d/x", "protected")
		mustSymlink(t, rfs, "d/e", "sub")
		mustSymlink(t, rfs, "sub/../x", "tricky")

		classify := func(p string) Level {
			t.Helper()
			lvl, err := fs.Classify(p)
			if err != nil {
				t.Fatalf("unexpected error classifying %q: %v", p, err)
			}
			return lvl
		}

		g.It("classifies logical paths against the rules", func() {
			g.Assert(classify("/hidden.txt")).Equal(LevelHidden)
			g.Assert(classify("hidden.txt")).Equal(LevelHidden)
			g.Assert(classify("/Licensed.jar")).Equal(LevelProtected)
			g.Assert(classify("/plain.txt")).Equal(LevelNone)
			g.Assert(classify("/")).Equal(LevelNone)
		})

		g.It("only applies anchored patterns at the root", func() {
			g.Assert(classify("/nested/Licensed.jar")).Equal(LevelNone)
		})

		g.It("applies patterns without a slash to file names anywhere", func() {
			g.Assert(classify("/nested/token.key")).Equal(LevelProtected)
			g.Assert(classify("/nested/new.key")).Equal(LevelProtected)
		})

		g.It("applies directory patterns to everything beneath the directory", func() {
			g.Assert(classify("/secrets")).Equal(LevelProtected)
			g.Assert(classify("/secrets/a")).Equal(LevelProtected)
			g.Assert(classify("/secrets/a/b.txt")).Equal(LevelProtected)
			g.Assert(classify("/secrets/new/file.txt")).Equal(LevelProtected)
			g.Assert(classify("/hiddendir")).Equal(LevelHidden)
			g.Assert(classify("/hiddendir/file.txt")).Equal(LevelHidden)
		})

		g.It("does not apply a directory pattern to a file with the same name", func() {
			mustWriteFile(t, rfs, "secrets-file", "plain")
			g.Assert(classify("/secrets-file")).Equal(LevelNone)
		})

		g.It("treats paths that do not exist as both files and directories", func() {
			g.Assert(classify("/secrets/new.txt")).Equal(LevelProtected)
			g.Assert(classify("/new-dir")).Equal(LevelNone)
		})

		g.It("classifies a symlink by the location it points to", func() {
			mustSymlink(t, rfs, "Licensed.jar", "link-relative.jar")
			mustSymlink(t, rfs, filepath.Join(rfs.root, "server", "Licensed.jar"), "link-absolute.jar")
			mustSymlink(t, rfs, "hidden.txt", "link-hidden")
			g.Assert(classify("/link-relative.jar")).Equal(LevelProtected)
			g.Assert(classify("/link-absolute.jar")).Equal(LevelProtected)
			g.Assert(classify("/link-hidden")).Equal(LevelHidden)
		})

		g.It("classifies a dangling symlink by the name it would create", func() {
			mustSymlink(t, rfs, "new.key", "dangling")
			g.Assert(classify("/dangling")).Equal(LevelProtected)
		})

		g.It("classifies paths beneath a symlinked directory by their real location", func() {
			mustSymlink(t, rfs, "secrets", "alias")
			g.Assert(classify("/alias")).Equal(LevelProtected)
			g.Assert(classify("/alias/a/b.txt")).Equal(LevelProtected)
		})

		g.It("resolves symlinks in the middle of a target the same way the kernel does", func() {
			g.Assert(classify("/tricky")).Equal(LevelProtected)
			g.Assert(classify("/sub/keep")).Equal(LevelNone)
		})

		g.It("ignores symlinks whose target is outside of the server root", func() {
			mustSymlink(t, rfs, "/etc", "escape")
			lvl, err := fs.Classify("/escape/passwd")
			g.Assert(err).IsNil()
			g.Assert(lvl).Equal(LevelNone)
		})

		g.It("uses the strongest level that applies", func() {
			mustWriteFile(t, rfs, "hiddendir/Licensed.jar", "hidden")
			g.Assert(classify("/hiddendir/Licensed.jar")).Equal(LevelHidden)
		})
	})

	g.Describe("ContainsRestricted", func() {
		fs, rfs := newRestrictedFs(t, []string{"/hidden.txt", "*.secret"}, []string{"/Licensed.jar", "*.key"})
		mustWriteFile(t, rfs, "plugins/token.key", "plugin")
		mustWriteFile(t, rfs, "plugins/plain.txt", "plain")
		mustWriteFile(t, rfs, "empty/plain.txt", "plain")
		mustWriteFile(t, rfs, "hidden.txt", "hidden")
		mustWriteFile(t, rfs, "deep/a/b/x.secret", "hidden")
		mustMkdir(t, rfs, "deep/empty")

		g.It("reports a directory that has a protected file beneath it", func() {
			restricted, err := fs.ContainsRestricted("/plugins")
			g.Assert(err).IsNil()
			g.Assert(restricted).IsTrue()
		})

		g.It("reports a directory that has a hidden file beneath it", func() {
			restricted, err := fs.ContainsRestricted("/deep")
			g.Assert(err).IsNil()
			g.Assert(restricted).IsTrue()
		})

		g.It("reports the root directory when a restricted file is anywhere in it", func() {
			restricted, err := fs.ContainsRestricted("/")
			g.Assert(err).IsNil()
			g.Assert(restricted).IsTrue()
		})

		g.It("reports a directory with no restricted files beneath it", func() {
			restricted, err := fs.ContainsRestricted("/empty")
			g.Assert(err).IsNil()
			g.Assert(restricted).IsFalse()

			restricted, err = fs.ContainsRestricted("/deep/empty")
			g.Assert(err).IsNil()
			g.Assert(restricted).IsFalse()
		})

		g.It("reports a file that is not restricted as unrestricted", func() {
			restricted, err := fs.ContainsRestricted("/empty/plain.txt")
			g.Assert(err).IsNil()
			g.Assert(restricted).IsFalse()
		})

		g.It("reports a missing path as unrestricted", func() {
			restricted, err := fs.ContainsRestricted("/does-not-exist")
			g.Assert(err).IsNil()
			g.Assert(restricted).IsFalse()
		})
	})

	g.Describe("SetRules", func() {
		fs, rfs := newRestrictedFs(t, nil, []string{"/Licensed.jar"})
		mustWriteFile(t, rfs, "Licensed.jar", "protected")

		g.It("replaces the rules that apply to the filesystem", func() {
			lvl, err := fs.Classify("/Licensed.jar")
			g.Assert(err).IsNil()
			g.Assert(lvl).Equal(LevelProtected)

			fs.SetRules(nil, nil)
			lvl, err = fs.Classify("/Licensed.jar")
			g.Assert(err).IsNil()
			g.Assert(lvl).Equal(LevelNone)

			fs.SetRules([]string{"/Licensed.jar"}, nil)
			lvl, err = fs.Classify("/Licensed.jar")
			g.Assert(err).IsNil()
			g.Assert(lvl).Equal(LevelHidden)
		})
	})
}

// Rules are matched literally where the syntax calls for it, so that no character in a rule can
// change what it matches, and a rule that cannot be compiled still protects what it names.
func TestFileRules_Syntax(t *testing.T) {
	g := Goblin(t)

	g.Describe("rule syntax", func() {
		fs, _ := newRestrictedFs(t, nil, []string{"a+b.txt", "[z-a].txt", "*.key", "!keep.key", "build/", "x(y).bin"})

		classify := func(p string) Level {
			t.Helper()
			lvl, err := fs.Classify(p)
			if err != nil {
				t.Fatalf("unexpected error classifying %q: %v", p, err)
			}
			return lvl
		}

		g.It("matches regular expression characters literally", func() {
			g.Assert(classify("/a+b.txt")).Equal(LevelProtected)
			g.Assert(classify("/aab.txt")).Equal(LevelNone)
			g.Assert(classify("/x(y).bin")).Equal(LevelProtected)
			g.Assert(classify("/xy.bin")).Equal(LevelNone)
		})

		g.It("still protects a rule that cannot be compiled, matching it literally", func() {
			g.Assert(classify("/[z-a].txt")).Equal(LevelProtected)
			g.Assert(classify("/m.txt")).Equal(LevelNone)
		})

		g.It("re-allows what a later negated rule names", func() {
			g.Assert(classify("/keep.key")).Equal(LevelNone)
			g.Assert(classify("/other.key")).Equal(LevelProtected)
		})

		g.It("applies a directory rule only to directories", func() {
			g.Assert(classify("/build/output.bin")).Equal(LevelProtected)
			g.Assert(classify("/builds")).Equal(LevelNone)
		})
	})
}
