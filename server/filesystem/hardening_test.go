package filesystem

import (
	"os"
	"strings"
	"testing"

	. "github.com/franela/goblin"
	"golang.org/x/sys/unix"
)

// Newlines are ordinary characters in a name, so rules must match across them.
func TestFileRules_Newlines(t *testing.T) {
	g := Goblin(t)

	g.Describe("newlines in names", func() {
		fs, rfs := newRestrictedFs(t, nil, []string{"plugins/**", "*.jar"})

		classify := func(p string) Level {
			t.Helper()
			lvl, err := fs.Classify(p)
			if err != nil {
				t.Fatalf("unexpected error classifying %q: %v", p, err)
			}
			return lvl
		}

		g.It("matches a double star across a newline", func() {
			g.Assert(classify("/plugins/x\ny")).Equal(LevelProtected)
		})

		g.It("matches a file name pattern across a newline in a directory name", func() {
			g.Assert(classify("/a\nb/c.jar")).Equal(LevelProtected)
		})

		g.It("refuses an upload whose name contains a newline", func() {
			err := fs.Restricted().Write("/plugins/evil\n.jar", strings.NewReader("x"), 1, 0o644)
			g.Assert(isDenylist(err)).IsTrue("expected denylist error, got %v", err)
			g.Assert(serverFileExists(rfs, "plugins/evil\n.jar")).IsFalse()
		})
	})
}

// A directory cannot be renamed to a name whose rules would restrict its contents, planting
// them under a restricted name.
func TestRestricted_RenamePlanting(t *testing.T) {
	g := Goblin(t)

	plant := func(t *testing.T, hidden, protected []string) (*Filesystem, *rootFs) {
		t.Helper()
		fs, rfs := restrictedFixture(t)
		fs.SetRules(hidden, protected)
		mustWriteFile(t, rfs, "x/Evil.jar", "planted")
		return fs, rfs
	}

	g.Describe("renaming a directory onto a restricted name", func() {
		g.It("refuses when the new name would protect the directory's contents", func() {
			fs, rfs := plant(t, nil, []string{"newplugins/*.jar"})
			err := fs.Restricted().Rename("/x", "/newplugins")
			g.Assert(isRestrictedContents(err)).IsTrue("expected restricted contents error, got %v", err)
			g.Assert(serverFileExists(rfs, "x/Evil.jar")).IsTrue()
			g.Assert(serverFileExists(rfs, "newplugins")).IsFalse()
		})

		g.It("refuses when the new name would hide the directory's contents", func() {
			fs, rfs := plant(t, []string{"newplugins/*.jar"}, nil)
			err := fs.Restricted().Rename("/x", "/newplugins")
			g.Assert(isRestrictedContents(err)).IsTrue("expected restricted contents error, got %v", err)
			g.Assert(serverFileExists(rfs, "x/Evil.jar")).IsTrue()
		})

		g.It("allows the rename when the new name leaves the contents unrestricted", func() {
			fs, rfs := plant(t, nil, []string{"newplugins/*.jar"})
			g.Assert(fs.Restricted().Rename("/x", "/moved")).IsNil()
			g.Assert(serverFileExists(rfs, "moved/Evil.jar")).IsTrue()
		})
	})
}

// A missing path and a path beneath a regular file answer the same way whether or not the file
// exists, so the response does not reveal a hidden file.
func TestRestricted_NotDirectoryOracle(t *testing.T) {
	g := Goblin(t)

	g.Describe("paths beneath a file", func() {
		fs, rfs := newRestrictedFs(t, []string{"secret.txt"}, nil)
		mustWriteFile(t, rfs, "secret.txt", "hidden")

		g.It("answers Stat the same whether or not the hidden file exists", func() {
			_, errExists := fs.Restricted().Stat("/secret.txt/x")
			g.Assert(os.Remove(serverFile(rfs, "secret.txt"))).IsNil()
			_, errAbsent := fs.Restricted().Stat("/secret.txt/x")
			g.Assert(isNotExist(errExists)).IsTrue("expected not exist, got %v", errExists)
			g.Assert(isNotExist(errAbsent)).IsTrue("expected not exist, got %v", errAbsent)
			g.Assert(errExists.Error()).Equal(errAbsent.Error())
		})

		g.It("answers Write the same whether or not the hidden file exists", func() {
			mustWriteFile(t, rfs, "secret.txt", "hidden")
			errExists := fs.Restricted().Write("/secret.txt/x", strings.NewReader("x"), 1, 0o644)
			g.Assert(os.Remove(serverFile(rfs, "secret.txt"))).IsNil()
			errAbsent := fs.Restricted().Write("/secret.txt/x", strings.NewReader("x"), 1, 0o644)
			g.Assert(isNotExist(errExists)).IsTrue("expected not exist, got %v", errExists)
			g.Assert(isNotExist(errAbsent)).IsTrue("expected not exist, got %v", errAbsent)
			g.Assert(errExists.Error()).Equal(errAbsent.Error())
		})

		g.It("answers CreateDirectory the same whether or not the hidden file exists", func() {
			mustWriteFile(t, rfs, "secret.txt", "hidden")
			errExists := fs.Restricted().CreateDirectory("x", "/secret.txt")
			g.Assert(os.Remove(serverFile(rfs, "secret.txt"))).IsNil()
			errAbsent := fs.Restricted().CreateDirectory("x", "/secret.txt")
			g.Assert(isNotExist(errExists)).IsTrue("expected not exist, got %v", errExists)
			g.Assert(isNotExist(errAbsent)).IsTrue("expected not exist, got %v", errAbsent)
			g.Assert(errExists.Error()).Equal(errAbsent.Error())
		})

		g.It("answers a visible file the same way as a missing one", func() {
			mustWriteFile(t, rfs, "plain.txt", "plain")
			_, errFile := fs.Restricted().Stat("/plain.txt/x")
			_, errMissing := fs.Restricted().Stat("/missing.txt/x")
			g.Assert(isNotExist(errFile)).IsTrue("expected not exist, got %v", errFile)
			g.Assert(isNotExist(errMissing)).IsTrue("expected not exist, got %v", errMissing)
		})
	})
}

// Renames create the missing parents of their destination, as they always have.
func TestRestricted_RenameCreatesParents(t *testing.T) {
	g := Goblin(t)

	g.Describe("rename", func() {
		g.It("moves a file into a directory that does not exist yet", func() {
			fs, rfs := restrictedFixture(t)
			g.Assert(fs.Restricted().Rename("/visible.txt", "/newdir/a.txt")).IsNil()
			g.Assert(readServerFile(t, rfs, "newdir/a.txt")).Equal("visible")
			g.Assert(serverFileExists(rfs, "visible.txt")).IsFalse()
		})
	})
}

// A symbolic link is restricted by its own name as well as by what it points to.
func TestRestricted_HiddenLinkNames(t *testing.T) {
	g := Goblin(t)

	g.Describe("links with restricted names", func() {
		g.It("hides a symbolic link whose name is hidden, even if its target is visible", func() {
			fs, rfs := restrictedFixture(t)
			fs.SetRules([]string{"hiddenlink"}, nil)
			mustSymlink(t, rfs, "visible.txt", "hiddenlink")
			_, err := fs.Restricted().Stat("/hiddenlink")
			g.Assert(isNotExist(err)).IsTrue("expected not exist, got %v", err)
			err = fs.Restricted().Write("/hiddenlink", strings.NewReader("x"), 1, 0o644)
			g.Assert(isNotExist(err)).IsTrue("expected not exist, got %v", err)
			g.Assert(readServerFile(t, rfs, "visible.txt")).Equal("visible")
		})

		g.It("refuses writes through a hidden symlinked directory name", func() {
			fs, rfs := restrictedFixture(t)
			fs.SetRules([]string{"alias/"}, nil)
			mustSymlink(t, rfs, "plugins", "alias")
			err := fs.Restricted().Write("/alias/new.txt", strings.NewReader("x"), 1, 0o644)
			g.Assert(isNotExist(err)).IsTrue("expected not exist, got %v", err)
			g.Assert(serverFileExists(rfs, "plugins/new.txt")).IsFalse()
		})
	})
}

// Named pipes and devices are never read or written, since that could block or act on the wrong
// thing.
func TestRestricted_NonRegularFiles(t *testing.T) {
	g := Goblin(t)

	g.Describe("a named pipe", func() {
		fs, rfs := restrictedFixture(t)
		if err := unix.Mkfifo(serverFile(rfs, "pipe"), 0o644); err != nil {
			t.Fatal(err)
		}

		g.It("is refused for reading without blocking", func() {
			_, _, err := fs.Restricted().File("/pipe")
			g.Assert(IsErrorCode(err, ErrCodeNotRegular)).IsTrue("expected not regular error, got %v", err)
		})

		g.It("is refused for writing without blocking", func() {
			err := fs.Restricted().Write("/pipe", strings.NewReader("x"), 1, 0o644)
			g.Assert(IsErrorCode(err, ErrCodeNotRegular)).IsTrue("expected not regular error, got %v", err)
		})

		g.It("is refused by touch without blocking", func() {
			_, err := fs.Restricted().Touch("/pipe", os.O_RDWR|os.O_TRUNC)
			g.Assert(IsErrorCode(err, ErrCodeNotRegular)).IsTrue("expected not regular error, got %v", err)
		})

		g.It("can be stat'ed without blocking", func() {
			st, err := fs.Restricted().Stat("/pipe")
			g.Assert(err).IsNil()
			g.Assert(st.IsDir()).IsFalse()
		})
	})
}

// A protected file's content is never read to work out its MIME type.
func TestRestricted_ProtectedContentNotSniffed(t *testing.T) {
	g := Goblin(t)

	g.Describe("MIME types", func() {
		fs, _ := restrictedFixture(t)

		g.It("is not detected for a protected file", func() {
			st, err := fs.Restricted().Stat("/Licensed.jar")
			g.Assert(err).IsNil()
			g.Assert(st.Mimetype).Equal("application/octet-stream")
			g.Assert(st.Protected).IsTrue()
		})

		g.It("is detected for a visible file", func() {
			st, err := fs.Restricted().Stat("/visible.txt")
			g.Assert(err).IsNil()
			g.Assert(st.Mimetype != "application/octet-stream").IsTrue("expected a detected type, got %q", st.Mimetype)
		})

		g.It("is not detected for a protected entry in a listing", func() {
			stats, err := fs.Restricted().ListDirectory("/")
			g.Assert(err).IsNil()
			for _, st := range stats {
				if st.Name() == "Licensed.jar" {
					g.Assert(st.Mimetype).Equal("application/octet-stream")
				}
			}
		})
	})
}

// A copy's name skips any name that is restricted, so the suffix never reveals one.
func TestRestricted_CopySkipsRestrictedNames(t *testing.T) {
	g := Goblin(t)

	g.Describe("copy suffix", func() {
		g.It("chooses a suffix that is not a restricted name", func() {
			fs, rfs := restrictedFixture(t)
			fs.SetRules([]string{"/hidden.txt", "hiddendir/", "visible copy.txt"}, []string{"/Licensed.jar", "*.key"})
			g.Assert(fs.Restricted().Copy("/visible.txt")).IsNil()
			g.Assert(serverFileExists(rfs, "visible copy.txt")).IsFalse()
			g.Assert(readServerFile(t, rfs, "visible copy 1.txt")).Equal("visible")
		})
	})
}

// Without any rules a server behaves as it did before rules existed: nothing is refused, and
// hard links and directories are not walked for restricted contents.
func TestRestricted_NoRulesBehavesLikeUpstream(t *testing.T) {
	g := Goblin(t)

	g.Describe("no rules configured", func() {
		g.It("does not refuse anything", func() {
			fs, rfs := restrictedFixture(t)
			fs.SetRules(nil, nil)

			lvl, err := fs.Classify("/Licensed.jar")
			g.Assert(err).IsNil()
			g.Assert(lvl).Equal(LevelNone)

			restricted, err := fs.ContainsRestricted("/")
			g.Assert(err).IsNil()
			g.Assert(restricted).IsFalse()

			g.Assert(fs.Restricted().Delete("/plugins")).IsNil()
			g.Assert(serverFileExists(rfs, "plugins")).IsFalse()

			g.Assert(fs.Restricted().Rename("/hiddendir", "/moved")).IsNil()
			g.Assert(serverFileExists(rfs, "moved/file.txt")).IsTrue()
		})

		g.It("reads hard links", func() {
			fs, rfs := restrictedFixture(t)
			fs.SetRules(nil, nil)
			if err := os.Link(serverFile(rfs, "Licensed.jar"), serverFile(rfs, "copy.txt")); err != nil {
				t.Fatal(err)
			}
			f, _, err := fs.Restricted().File("/copy.txt")
			g.Assert(err).IsNil()
			if f != nil {
				_ = f.Close()
			}
		})
	})
}
