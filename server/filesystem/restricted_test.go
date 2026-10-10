package filesystem

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/franela/goblin"
)

// restrictedFixture returns a filesystem with a hidden and protected file, a directory
// containing a protected file, and links to each of them.
func restrictedFixture(t *testing.T) (*Filesystem, *rootFs) {
	t.Helper()
	fs, rfs := newRestrictedFs(t, []string{"/hidden.txt", "hiddendir/"}, []string{"/Licensed.jar", "*.key"})
	mustWriteFile(t, rfs, "visible.txt", "visible")
	mustWriteFile(t, rfs, "Licensed.jar", "protected")
	mustWriteFile(t, rfs, "hidden.txt", "hidden")
	mustWriteFile(t, rfs, "hiddendir/file.txt", "hidden")
	mustWriteFile(t, rfs, "plugins/plain.txt", "plain")
	mustWriteFile(t, rfs, "plugins/token.key", "protected")
	mustSymlink(t, rfs, "Licensed.jar", "link.jar")
	mustSymlink(t, rfs, "hidden.txt", "link-hidden")
	return fs, rfs
}

func serverFile(rfs *rootFs, p string) string {
	return filepath.Join(rfs.root, "server", p)
}

func readServerFile(t *testing.T, rfs *rootFs, p string) string {
	t.Helper()
	b, err := os.ReadFile(serverFile(rfs, p))
	if err != nil {
		t.Fatalf("failed to read %q: %v", p, err)
	}
	return string(b)
}

func serverFileExists(rfs *rootFs, p string) bool {
	_, err := os.Lstat(serverFile(rfs, p))
	return err == nil
}

func isNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}

func isDenylist(err error) bool {
	return IsErrorCode(err, ErrCodeDenylistFile)
}

func isRestrictedContents(err error) bool {
	return IsErrorCode(err, ErrCodeRestrictedContents)
}

func isHardlink(err error) bool {
	return IsErrorCode(err, ErrCodeHardlink)
}

// archiveEntries returns the names of the files in a gzipped tar archive.
func archiveEntries(t *testing.T, p string) []string {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
	}
	return names
}

// writeTarGz writes a gzipped tar archive with the given files to p.
func writeTarGz(t *testing.T, p string, files []struct{ name, content string }) {
	t.Helper()
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, file := range files {
		if err := tw.WriteHeader(&tar.Header{Name: file.name, Mode: 0o644, Size: int64(len(file.content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(file.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRestricted_Read(t *testing.T) {
	g := Goblin(t)

	g.Describe("File", func() {
		g.It("returns a visible file", func() {
			fs, _ := restrictedFixture(t)
			f, st, err := fs.Restricted().File("/visible.txt")
			g.Assert(err).IsNil()
			if f != nil {
				defer f.Close()
			}
			g.Assert(st.Protected).IsFalse()
		})

		g.It("refuses a protected file", func() {
			fs, _ := restrictedFixture(t)
			_, _, err := fs.Restricted().File("/Licensed.jar")
			g.Assert(isDenylist(err)).IsTrue("expected denylist error, got %v", err)
		})

		g.It("refuses a protected file reached through a symlink", func() {
			fs, _ := restrictedFixture(t)
			_, _, err := fs.Restricted().File("/link.jar")
			g.Assert(isDenylist(err)).IsTrue("expected denylist error, got %v", err)
		})

		g.It("reports a hidden file as not existing", func() {
			fs, _ := restrictedFixture(t)
			_, _, err := fs.Restricted().File("/hidden.txt")
			g.Assert(isNotExist(err)).IsTrue("expected not exist error, got %v", err)

			_, _, err = fs.Restricted().File("/link-hidden")
			g.Assert(isNotExist(err)).IsTrue("expected not exist error, got %v", err)
		})
	})

	g.Describe("Stat", func() {
		g.It("returns a protected file, flagged as protected", func() {
			fs, _ := restrictedFixture(t)
			st, err := fs.Restricted().Stat("/Licensed.jar")
			g.Assert(err).IsNil()
			g.Assert(st.Protected).IsTrue()
		})

		g.It("reports a hidden file as not existing", func() {
			fs, _ := restrictedFixture(t)
			_, err := fs.Restricted().Stat("/hidden.txt")
			g.Assert(isNotExist(err)).IsTrue("expected not exist error, got %v", err)
		})
	})

	g.Describe("ListDirectory", func() {
		g.It("leaves out hidden entries and flags protected ones", func() {
			fs, _ := restrictedFixture(t)
			stats, err := fs.Restricted().ListDirectory("/")
			g.Assert(err).IsNil()

			byName := make(map[string]Stat)
			for _, st := range stats {
				byName[st.Name()] = st
			}
			g.Assert(byName["visible.txt"].Protected).IsFalse()
			g.Assert(byName["Licensed.jar"].Protected).IsTrue()
			g.Assert(byName["plugins"].Protected).IsFalse()
			_, hidden := byName["hidden.txt"]
			g.Assert(hidden).IsFalse()
			_, hiddenDir := byName["hiddendir"]
			g.Assert(hiddenDir).IsFalse()
			_, hiddenLink := byName["link-hidden"]
			g.Assert(hiddenLink).IsFalse()
		})

		g.It("flags entries of a protected directory as protected", func() {
			fs, _ := restrictedFixture(t)
			stats, err := fs.Restricted().ListDirectory("/plugins")
			g.Assert(err).IsNil()
			g.Assert(len(stats)).Equal(2)
			for _, st := range stats {
				g.Assert(st.Protected).Equal(st.Name() == "token.key")
			}
		})

		g.It("reports a hidden directory as not existing", func() {
			fs, _ := restrictedFixture(t)
			_, err := fs.Restricted().ListDirectory("/hiddendir")
			g.Assert(isNotExist(err)).IsTrue("expected not exist error, got %v", err)
		})

		g.It("leaves out hidden entries from ReadDirStat", func() {
			fs, _ := restrictedFixture(t)
			infos, err := fs.Restricted().ReadDirStat("/")
			g.Assert(err).IsNil()
			var names []string
			for _, info := range infos {
				names = append(names, info.Name())
			}
			g.Assert(strings.Contains(strings.Join(names, ","), "hidden")).IsFalse()
			g.Assert(strings.Contains(strings.Join(names, ","), "Licensed.jar")).IsTrue()
		})
	})
}

func TestRestricted_Write(t *testing.T) {
	g := Goblin(t)

	g.Describe("Write", func() {
		g.It("writes a new file", func() {
			fs, rfs := restrictedFixture(t)
			g.Assert(fs.Restricted().Write("/new.txt", strings.NewReader("new"), 3, 0o644)).IsNil()
			g.Assert(readServerFile(t, rfs, "new.txt")).Equal("new")
		})

		g.It("refuses to overwrite a protected file", func() {
			fs, rfs := restrictedFixture(t)
			err := fs.Restricted().Write("/Licensed.jar", strings.NewReader("replaced"), 8, 0o644)
			g.Assert(isDenylist(err)).IsTrue("expected denylist error, got %v", err)
			g.Assert(readServerFile(t, rfs, "Licensed.jar")).Equal("protected")
		})

		g.It("refuses to write through a symlink to a protected file", func() {
			fs, rfs := restrictedFixture(t)
			err := fs.Restricted().Write("/link.jar", strings.NewReader("replaced"), 8, 0o644)
			g.Assert(isDenylist(err)).IsTrue("expected denylist error, got %v", err)
			g.Assert(readServerFile(t, rfs, "Licensed.jar")).Equal("protected")
		})

		g.It("refuses to write to a hidden file as if it does not exist", func() {
			fs, rfs := restrictedFixture(t)
			err := fs.Restricted().Write("/hidden.txt", strings.NewReader("replaced"), 8, 0o644)
			g.Assert(isNotExist(err)).IsTrue("expected not exist error, got %v", err)
			g.Assert(readServerFile(t, rfs, "hidden.txt")).Equal("hidden")
		})

		g.It("refuses to create a file inside a hidden directory", func() {
			fs, rfs := restrictedFixture(t)
			err := fs.Restricted().Write("/hiddendir/new.txt", strings.NewReader("new"), 3, 0o644)
			g.Assert(isNotExist(err)).IsTrue("expected not exist error, got %v", err)
			g.Assert(serverFileExists(rfs, "hiddendir/new.txt")).IsFalse()
		})

		g.It("refuses to create a protected file by pattern", func() {
			fs, rfs := restrictedFixture(t)
			err := fs.Restricted().Write("/plugins/new.key", strings.NewReader("new"), 3, 0o644)
			g.Assert(isDenylist(err)).IsTrue("expected denylist error, got %v", err)
			g.Assert(serverFileExists(rfs, "plugins/new.key")).IsFalse()
		})
	})

	g.Describe("Touch", func() {
		g.It("refuses to truncate a protected file", func() {
			fs, rfs := restrictedFixture(t)
			_, err := fs.Restricted().Touch("/Licensed.jar", os.O_RDWR|os.O_TRUNC)
			g.Assert(isDenylist(err)).IsTrue("expected denylist error, got %v", err)
			g.Assert(readServerFile(t, rfs, "Licensed.jar")).Equal("protected")
		})
	})

	g.Describe("CreateDirectory", func() {
		g.It("creates a directory", func() {
			fs, rfs := restrictedFixture(t)
			g.Assert(fs.Restricted().CreateDirectory("new", "/")).IsNil()
			g.Assert(serverFileExists(rfs, "new")).IsTrue()
		})

		g.It("refuses to create a directory inside a hidden directory", func() {
			fs, rfs := restrictedFixture(t)
			err := fs.Restricted().CreateDirectory("new", "/hiddendir")
			g.Assert(isNotExist(err)).IsTrue("expected not exist error, got %v", err)
			g.Assert(serverFileExists(rfs, "hiddendir/new")).IsFalse()
		})
	})

	g.Describe("Symlink", func() {
		g.It("refuses to replace a protected file with a link", func() {
			fs, rfs := restrictedFixture(t)
			err := fs.Restricted().Symlink("/visible.txt", "/Licensed.jar")
			g.Assert(isDenylist(err)).IsTrue("expected denylist error, got %v", err)
			g.Assert(readServerFile(t, rfs, "Licensed.jar")).Equal("protected")
		})
	})

	g.Describe("Chtimes", func() {
		g.It("refuses to change the times of a protected file", func() {
			fs, _ := restrictedFixture(t)
			err := fs.Restricted().Chtimes("/Licensed.jar", time.Now(), time.Now())
			g.Assert(isDenylist(err)).IsTrue("expected denylist error, got %v", err)
		})
	})

	g.Describe("Chmod", func() {
		g.It("refuses a protected file", func() {
			fs, _ := restrictedFixture(t)
			err := fs.Restricted().Chmod("/Licensed.jar", 0o600)
			g.Assert(isDenylist(err)).IsTrue("expected denylist error, got %v", err)
		})

		g.It("refuses a directory that contains a protected file", func() {
			fs, _ := restrictedFixture(t)
			err := fs.Restricted().Chmod("/plugins", 0o700)
			g.Assert(isRestrictedContents(err)).IsTrue("expected restricted contents error, got %v", err)
		})
	})

	g.Describe("Copy", func() {
		g.It("copies a visible file", func() {
			fs, rfs := restrictedFixture(t)
			g.Assert(fs.Restricted().Copy("/visible.txt")).IsNil()
			g.Assert(readServerFile(t, rfs, "visible copy.txt")).Equal("visible")
		})

		g.It("refuses to copy a protected file", func() {
			fs, rfs := restrictedFixture(t)
			err := fs.Restricted().Copy("/Licensed.jar")
			g.Assert(isDenylist(err)).IsTrue("expected denylist error, got %v", err)
			g.Assert(serverFileExists(rfs, "Licensed copy.jar")).IsFalse()
		})

		g.It("skips a protected name when choosing the name of a copy", func() {
			fs, rfs := restrictedFixture(t)
			// The source is visible, but the first name the copy would take is protected, so the
			// copy takes the next free name instead.
			fs.SetRules(nil, []string{"*copy.txt"})
			g.Assert(fs.Restricted().Copy("/visible.txt")).IsNil()
			g.Assert(serverFileExists(rfs, "visible copy.txt")).IsFalse()
			g.Assert(readServerFile(t, rfs, "visible copy 1.txt")).Equal("visible")
		})
	})
}

func TestRestricted_Delete(t *testing.T) {
	g := Goblin(t)

	g.Describe("Delete", func() {
		g.It("deletes a visible file", func() {
			fs, rfs := restrictedFixture(t)
			g.Assert(fs.Restricted().Delete("/visible.txt")).IsNil()
			g.Assert(serverFileExists(rfs, "visible.txt")).IsFalse()
		})

		g.It("refuses to delete a protected file", func() {
			fs, rfs := restrictedFixture(t)
			err := fs.Restricted().Delete("/Licensed.jar")
			g.Assert(isDenylist(err)).IsTrue("expected denylist error, got %v", err)
			g.Assert(serverFileExists(rfs, "Licensed.jar")).IsTrue()
		})

		g.It("refuses to delete a directory that contains a protected file", func() {
			fs, rfs := restrictedFixture(t)
			err := fs.Restricted().Delete("/plugins")
			g.Assert(isRestrictedContents(err)).IsTrue("expected restricted contents error, got %v", err)
			g.Assert(serverFileExists(rfs, "plugins/token.key")).IsTrue()
			g.Assert(serverFileExists(rfs, "plugins/plain.txt")).IsTrue()
		})

		g.It("reports a hidden file as not existing", func() {
			fs, rfs := restrictedFixture(t)
			err := fs.Restricted().Delete("/hidden.txt")
			g.Assert(isNotExist(err)).IsTrue("expected not exist error, got %v", err)
			g.Assert(serverFileExists(rfs, "hidden.txt")).IsTrue()
		})
	})

	g.Describe("Rename", func() {
		g.It("renames a visible file", func() {
			fs, rfs := restrictedFixture(t)
			g.Assert(fs.Restricted().Rename("/visible.txt", "/moved.txt")).IsNil()
			g.Assert(readServerFile(t, rfs, "moved.txt")).Equal("visible")
		})

		g.It("refuses to move a protected file", func() {
			fs, rfs := restrictedFixture(t)
			err := fs.Restricted().Rename("/Licensed.jar", "/moved.jar")
			g.Assert(isDenylist(err)).IsTrue("expected denylist error, got %v", err)
			g.Assert(readServerFile(t, rfs, "Licensed.jar")).Equal("protected")
		})

		g.It("refuses to move a directory that contains a protected file out from under its pattern", func() {
			fs, rfs := restrictedFixture(t)
			err := fs.Restricted().Rename("/plugins", "/moved")
			g.Assert(isRestrictedContents(err)).IsTrue("expected restricted contents error, got %v", err)
			g.Assert(serverFileExists(rfs, "plugins/token.key")).IsTrue()
			g.Assert(serverFileExists(rfs, "moved")).IsFalse()
		})

		g.It("refuses to move a file onto a protected file", func() {
			fs, rfs := restrictedFixture(t)
			err := fs.Restricted().Rename("/visible.txt", "/Licensed.jar")
			g.Assert(isDenylist(err)).IsTrue("expected denylist error, got %v", err)
			g.Assert(readServerFile(t, rfs, "Licensed.jar")).Equal("protected")
		})

		g.It("reports a hidden file as not existing", func() {
			fs, _ := restrictedFixture(t)
			err := fs.Restricted().Rename("/hidden.txt", "/moved.txt")
			g.Assert(isNotExist(err)).IsTrue("expected not exist error, got %v", err)
		})
	})
}

func TestRestricted_Archives(t *testing.T) {
	g := Goblin(t)

	g.Describe("CompressFiles", func() {
		g.It("leaves restricted files out of the archive", func() {
			fs, rfs := restrictedFixture(t)
			info, err := fs.Restricted().CompressFiles("/", []string{"visible.txt", "Licensed.jar", "hidden.txt", "plugins", "hiddendir"})
			g.Assert(err).IsNil()

			entries := archiveEntries(t, serverFile(rfs, info.Name()))
			g.Assert(contains(entries, "visible.txt")).IsTrue()
			g.Assert(contains(entries, "plugins/plain.txt")).IsTrue()
			g.Assert(contains(entries, "Licensed.jar")).IsFalse()
			g.Assert(contains(entries, "plugins/token.key")).IsFalse()
			g.Assert(contains(entries, "hidden.txt")).IsFalse()
			g.Assert(contains(entries, "hiddendir/file.txt")).IsFalse()
		})

		g.It("refuses to archive a hidden directory as if it does not exist", func() {
			fs, _ := restrictedFixture(t)
			_, err := fs.Restricted().CompressFiles("/hiddendir", []string{"file.txt"})
			g.Assert(isNotExist(err)).IsTrue("expected not exist error, got %v", err)
		})

		g.It("refuses to create the archive at a protected name", func() {
			fs, rfs := restrictedFixture(t)
			fs.SetRules(nil, []string{"archive-*"})
			_, err := fs.Restricted().CompressFiles("/", []string{"visible.txt"})
			g.Assert(isDenylist(err)).IsTrue("expected denylist error, got %v", err)
			entries, err := os.ReadDir(filepath.Join(rfs.root, "server"))
			g.Assert(err).IsNil()
			for _, e := range entries {
				g.Assert(strings.HasPrefix(e.Name(), "archive-")).IsFalse()
			}
		})
	})

	g.Describe("Backup archives", func() {
		g.It("leaves hidden, protected and links to them out of the archive", func() {
			fs, _ := restrictedFixture(t)
			dst := filepath.Join(t.TempDir(), "backup.tar.gz")
			a := &Archive{Filesystem: fs, Restricted: true}
			g.Assert(a.Create(context.Background(), dst)).IsNil()

			entries := archiveEntries(t, dst)
			g.Assert(contains(entries, "visible.txt")).IsTrue()
			g.Assert(contains(entries, "plugins/plain.txt")).IsTrue()
			g.Assert(contains(entries, "Licensed.jar")).IsFalse()
			g.Assert(contains(entries, "link.jar")).IsFalse()
			g.Assert(contains(entries, "plugins/token.key")).IsFalse()
			g.Assert(contains(entries, "hidden.txt")).IsFalse()
			g.Assert(contains(entries, "link-hidden")).IsFalse()
			g.Assert(contains(entries, "hiddendir/file.txt")).IsFalse()
		})

		g.It("includes everything when the archive is not restricted", func() {
			fs, _ := restrictedFixture(t)
			dst := filepath.Join(t.TempDir(), "transfer.tar.gz")
			a := &Archive{Filesystem: fs}
			g.Assert(a.Create(context.Background(), dst)).IsNil()

			entries := archiveEntries(t, dst)
			g.Assert(contains(entries, "Licensed.jar")).IsTrue()
			g.Assert(contains(entries, "hidden.txt")).IsTrue()
		})
	})

	g.Describe("DecompressFile", func() {
		g.It("skips entries that would overwrite or create a restricted file", func() {
			fs, rfs := restrictedFixture(t)
			writeTarGz(t, serverFile(rfs, "bundle.tar.gz"), []struct{ name, content string }{
				{"new-file.txt", "extracted"},
				{"Licensed.jar", "overwritten"},
				{"hidden.txt", "overwritten"},
				{"plugins/token.key", "overwritten"},
				{"plugins/plain.txt", "overwritten"},
				{"hiddendir/file.txt", "overwritten"},
				{"link.jar", "overwritten"},
			})

			g.Assert(fs.Restricted().DecompressFile(context.Background(), "/", "bundle.tar.gz")).IsNil()
			g.Assert(readServerFile(t, rfs, "new-file.txt")).Equal("extracted")
			g.Assert(readServerFile(t, rfs, "Licensed.jar")).Equal("protected")
			g.Assert(readServerFile(t, rfs, "hidden.txt")).Equal("hidden")
			g.Assert(readServerFile(t, rfs, "plugins/token.key")).Equal("protected")
			g.Assert(readServerFile(t, rfs, "hiddendir/file.txt")).Equal("hidden")
			g.Assert(readServerFile(t, rfs, "plugins/plain.txt")).Equal("overwritten")
		})

		g.It("refuses an archive that is itself restricted", func() {
			fs, _ := restrictedFixture(t)
			err := fs.Restricted().DecompressFile(context.Background(), "/", "Licensed.jar")
			g.Assert(isDenylist(err)).IsTrue("expected denylist error, got %v", err)
		})
	})
}

func TestRestricted_TruncateRootDirectory(t *testing.T) {
	g := Goblin(t)

	g.Describe("TruncateRootDirectory", func() {
		g.It("keeps restricted files and the directories that contain them", func() {
			fs, rfs := restrictedFixture(t)
			g.Assert(fs.Restricted().TruncateRootDirectory()).IsNil()

			g.Assert(serverFileExists(rfs, "visible.txt")).IsFalse()
			g.Assert(serverFileExists(rfs, "plugins/plain.txt")).IsFalse()
			g.Assert(serverFileExists(rfs, "Licensed.jar")).IsTrue()
			g.Assert(readServerFile(t, rfs, "Licensed.jar")).Equal("protected")
			g.Assert(serverFileExists(rfs, "hidden.txt")).IsTrue()
			g.Assert(serverFileExists(rfs, "hiddendir/file.txt")).IsTrue()
			g.Assert(serverFileExists(rfs, "plugins/token.key")).IsTrue()
			g.Assert(serverFileExists(rfs, "link.jar")).IsTrue()
		})

		g.It("empties the root directory when nothing is restricted", func() {
			fs, rfs := restrictedFixture(t)
			fs.SetRules(nil, nil)
			g.Assert(fs.Restricted().TruncateRootDirectory()).IsNil()
			g.Assert(serverFileExists(rfs, "Licensed.jar")).IsFalse()
			g.Assert(serverFileExists(rfs, "hidden.txt")).IsFalse()
		})
	})
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
