package filesystem

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	. "github.com/franela/goblin"
)

// Paths are normalized with the unixFS rules, so the check and the operation refer to the same
// location, even for paths that spell the root directory out in full.
func TestRestricted_PathNormalization(t *testing.T) {
	g := Goblin(t)

	g.Describe("paths", func() {
		g.It("refuses a protected file named with the absolute path of the root", func() {
			fs, rfs := restrictedFixture(t)
			err := fs.Restricted().Write(fs.Path()+"/Licensed.jar", strings.NewReader("x"), 1, 0o644)
			g.Assert(isDenylist(err)).IsTrue("expected denylist error, got %v", err)
			g.Assert(readServerFile(t, rfs, "Licensed.jar")).Equal("protected")
		})

		g.It("refuses a protected file named with the root path glued to a name", func() {
			// The unixFS maps "<root>Licensed.jar" onto "Licensed.jar" inside the root.
			fs, rfs := restrictedFixture(t)
			err := fs.Restricted().Write(fs.Path()+"Licensed.jar", strings.NewReader("x"), 1, 0o644)
			g.Assert(isDenylist(err)).IsTrue("expected denylist error, got %v", err)
			g.Assert(readServerFile(t, rfs, "Licensed.jar")).Equal("protected")
		})

		g.It("refuses a protected file reached by climbing out of the root and back in", func() {
			// The unixFS maps "../<root name>/Licensed.jar" onto "Licensed.jar" inside the root.
			fs, rfs := restrictedFixture(t)
			rootName := filepath.Base(fs.Path())
			_, _, err := fs.Restricted().File("../" + rootName + "/Licensed.jar")
			g.Assert(isDenylist(err)).IsTrue("expected denylist error, got %v", err)
			err = fs.Restricted().Write("../"+rootName+"/Licensed.jar", strings.NewReader("x"), 1, 0o644)
			g.Assert(isDenylist(err)).IsTrue("expected denylist error, got %v", err)
			g.Assert(readServerFile(t, rfs, "Licensed.jar")).Equal("protected")
		})

		g.It("refuses a path that leaves the server root", func() {
			fs, rfs := restrictedFixture(t)
			err := fs.Restricted().Write("../outside.txt", strings.NewReader("x"), 1, 0o644)
			g.Assert(err != nil).IsTrue("expected an error for a path outside the root")
			g.Assert(serverFileExists(rfs, "../outside.txt")).IsFalse()
		})
	})
}

// A directory that is swapped for a symbolic link between the check and the operation must not
// redirect the operation. The hook simulates the swap at the point a real race would occur.
func TestRestricted_SwapDuringAccess(t *testing.T) {
	g := Goblin(t)

	setup := func() (*Filesystem, *rootFs, string) {
		fs, rfs := restrictedFixture(t)
		fs.SetRules([]string{"/hidden.txt", "hiddendir/"}, []string{"/Licensed.jar", "*.key", "secrets/"})
		mustMkdir(t, rfs, "secrets")
		return fs, rfs, filepath.Join(rfs.root, "server")
	}

	g.Describe("directory swapped for a symbolic link", func() {
		g.It("is refused when the swap happens after the directory was opened", func() {
			fs, rfs, base := setup()
			testLocateHook = func(string) {
				testLocateHook = nil
				_ = os.Rename(filepath.Join(base, "plugins"), filepath.Join(base, "plugins.moved"))
				_ = os.Symlink("secrets", filepath.Join(base, "plugins"))
			}
			defer func() { testLocateHook = nil }()

			err := fs.Restricted().Write("/plugins/new.txt", strings.NewReader("x"), 1, 0o644)
			g.Assert(isDenylist(err)).IsTrue("expected denylist error, got %v", err)
			g.Assert(serverFileExists(rfs, "secrets/new.txt")).IsFalse()
		})

		g.It("does not write into a protected directory when a visible one is moved into it", func() {
			fs, rfs, base := setup()
			testLocateHook = func(string) {
				testLocateHook = nil
				_ = os.Rename(filepath.Join(base, "plugins"), filepath.Join(base, "secrets", "plugins"))
			}
			defer func() { testLocateHook = nil }()

			_ = fs.Restricted().Write("/plugins/new.txt", strings.NewReader("x"), 1, 0o644)
			g.Assert(serverFileExists(rfs, "secrets/plugins/new.txt")).IsFalse()
			g.Assert(serverFileExists(rfs, "secrets/plugins/plain.txt")).IsTrue()
		})

		g.It("refuses a write through a symbolic link to a protected directory", func() {
			fs, rfs, _ := setup()
			mustSymlink(t, rfs, "secrets", "alias")
			err := fs.Restricted().Write("/alias/new.txt", strings.NewReader("x"), 1, 0o644)
			g.Assert(isDenylist(err)).IsTrue("expected denylist error, got %v", err)
			g.Assert(serverFileExists(rfs, "secrets/new.txt")).IsFalse()
		})

		g.It("does not follow a swapped final file into a protected file", func() {
			fs, rfs, base := setup()
			testLocateHook = func(string) {
				testLocateHook = nil
				_ = os.Rename(filepath.Join(base, "visible.txt"), filepath.Join(base, "visible.bak"))
				_ = os.Symlink("Licensed.jar", filepath.Join(base, "visible.txt"))
			}
			defer func() { testLocateHook = nil }()

			err := fs.Restricted().Write("/visible.txt", strings.NewReader("x"), 1, 0o644)
			g.Assert(isDenylist(err)).IsTrue("expected denylist error, got %v", err)
			g.Assert(readServerFile(t, rfs, "Licensed.jar")).Equal("protected")
		})
	})
}

// A file with a second name cannot be read, written or copied through that name while rules are
// configured, since the name is not what the rules were checked against.
func TestRestricted_Hardlinks(t *testing.T) {
	g := Goblin(t)

	hardlinked := func(t *testing.T, rfs *rootFs) {
		t.Helper()
		if err := os.Link(serverFile(rfs, "Licensed.jar"), serverFile(rfs, "copy.txt")); err != nil {
			t.Fatal(err)
		}
	}

	g.Describe("hard linked files", func() {
		g.It("refuses to read a hard link of a protected file", func() {
			fs, rfs := restrictedFixture(t)
			hardlinked(t, rfs)
			_, _, err := fs.Restricted().File("/copy.txt")
			g.Assert(isHardlink(err)).IsTrue("expected hardlink error, got %v", err)
			_, err = fs.Restricted().Stat("/copy.txt")
			g.Assert(err).IsNil()
		})

		g.It("refuses to write through a hard link", func() {
			fs, rfs := restrictedFixture(t)
			hardlinked(t, rfs)
			err := fs.Restricted().Write("/copy.txt", strings.NewReader("replaced"), 8, 0o644)
			g.Assert(isHardlink(err)).IsTrue("expected hardlink error, got %v", err)
			g.Assert(readServerFile(t, rfs, "Licensed.jar")).Equal("protected")
		})

		g.It("refuses to copy a hard link", func() {
			fs, rfs := restrictedFixture(t)
			hardlinked(t, rfs)
			err := fs.Restricted().Copy("/copy.txt")
			g.Assert(isHardlink(err)).IsTrue("expected hardlink error, got %v", err)
		})

		g.It("allows a hard link to be deleted", func() {
			fs, rfs := restrictedFixture(t)
			hardlinked(t, rfs)
			g.Assert(fs.Restricted().Delete("/copy.txt")).IsNil()
			g.Assert(serverFileExists(rfs, "copy.txt")).IsFalse()
			g.Assert(readServerFile(t, rfs, "Licensed.jar")).Equal("protected")
		})

		g.It("leaves hard links out of archives", func() {
			fs, rfs := restrictedFixture(t)
			hardlinked(t, rfs)
			info, err := fs.Restricted().CompressFiles("/", []string{"copy.txt", "visible.txt"})
			g.Assert(err).IsNil()
			entries := archiveEntries(t, serverFile(rfs, info.Name()))
			g.Assert(contains(entries, "copy.txt")).IsFalse()
			g.Assert(contains(entries, "visible.txt")).IsTrue()

			dst := filepath.Join(t.TempDir(), "backup.tar.gz")
			g.Assert((&Archive{Filesystem: fs, Restricted: true}).Create(context.Background(), dst)).IsNil()
			g.Assert(contains(archiveEntries(t, dst), "copy.txt")).IsFalse()
		})

		g.It("allows hard links when no rules are configured", func() {
			fs, rfs := restrictedFixture(t)
			fs.SetRules(nil, nil)
			hardlinked(t, rfs)
			f, _, err := fs.Restricted().File("/copy.txt")
			g.Assert(err).IsNil()
			if f != nil {
				_ = f.Close()
			}
		})
	})
}

// Transfers write every entry of the archive. Only user extraction is restricted.
func TestFilesystem_TransferKeepsRestrictedFiles(t *testing.T) {
	g := Goblin(t)

	g.Describe("internal extraction", func() {
		g.It("writes restricted entries when extracting an internal archive", func() {
			fs, rfs := restrictedFixture(t)
			archive := filepath.Join(t.TempDir(), "transfer.tar.gz")
			writeTarGz(t, archive, []struct{ name, content string }{
				{"Licensed.jar", "transferred"},
				{"hidden.txt", "transferred"},
				{"plugins/token.key", "transferred"},
			})
			f, err := os.Open(archive)
			g.Assert(err).IsNil()
			defer f.Close()

			g.Assert(fs.ExtractStreamUnsafe(context.Background(), "/", f)).IsNil()
			g.Assert(readServerFile(t, rfs, "Licensed.jar")).Equal("transferred")
			g.Assert(readServerFile(t, rfs, "hidden.txt")).Equal("transferred")
			g.Assert(readServerFile(t, rfs, "plugins/token.key")).Equal("transferred")
		})
	})
}

// Restores never overwrite a restricted file, and do write the entries that are not restricted.
func TestRestricted_Restore(t *testing.T) {
	g := Goblin(t)

	g.Describe("restore", func() {
		g.It("skips restricted entries and writes the rest", func() {
			fs, rfs := restrictedFixture(t)
			info, err := os.Stat(serverFile(rfs, "visible.txt"))
			g.Assert(err).IsNil()

			g.Assert(fs.Restricted().Restore("/Licensed.jar", strings.NewReader("replaced"), info)).IsNil()
			g.Assert(readServerFile(t, rfs, "Licensed.jar")).Equal("protected")

			g.Assert(fs.Restricted().Restore("/hidden.txt", strings.NewReader("replaced"), info)).IsNil()
			g.Assert(readServerFile(t, rfs, "hidden.txt")).Equal("hidden")

			g.Assert(fs.Restricted().Restore("/restored.txt", strings.NewReader("visible"), info)).IsNil()
			g.Assert(readServerFile(t, rfs, "restored.txt")).Equal("visible")
		})
	})
}

// A directory is refused the same way whether the restricted thing inside it is hidden or
// protected, so the response does not reveal which of them exist.
func TestRestricted_DirectoryRefusalDoesNotDistinguish(t *testing.T) {
	g := Goblin(t)

	g.Describe("refusals", func() {
		g.It("reports hidden and protected contents with the same error", func() {
			fs, rfs := restrictedFixture(t)
			fs.SetRules([]string{"*.secret"}, []string{"*.key"})
			mustWriteFile(t, rfs, "withhidden/a.secret", "x")
			mustWriteFile(t, rfs, "withprotected/b.key", "x")

			errHidden := fs.Restricted().Delete("/withhidden")
			errProtected := fs.Restricted().Delete("/withprotected")
			g.Assert(isRestrictedContents(errHidden)).IsTrue("expected restricted contents error, got %v", errHidden)
			g.Assert(isRestrictedContents(errProtected)).IsTrue("expected restricted contents error, got %v", errProtected)
		})
	})
}

// Directories are created through symbolic links to directories that are not restricted, and
// never through a link to a restricted one.
func TestRestricted_CreateDirectoryThroughLinks(t *testing.T) {
	g := Goblin(t)

	g.Describe("CreateDirectory", func() {
		g.It("creates a directory through a link to an unrestricted directory", func() {
			fs, rfs := restrictedFixture(t)
			mustSymlink(t, rfs, "plugins", "pluginlink")
			g.Assert(fs.Restricted().CreateDirectory("made", "/pluginlink")).IsNil()
			g.Assert(serverFileExists(rfs, "plugins/made")).IsTrue()
		})

		g.It("refuses to create a directory through a link to a protected directory", func() {
			fs, rfs := restrictedFixture(t)
			fs.SetRules(nil, []string{"secrets/"})
			mustMkdir(t, rfs, "secrets")
			mustSymlink(t, rfs, "secrets", "secretlink")
			err := fs.Restricted().CreateDirectory("made", "/secretlink")
			g.Assert(isDenylist(err)).IsTrue("expected denylist error, got %v", err)
			g.Assert(serverFileExists(rfs, "secrets/made")).IsFalse()
		})
	})
}
