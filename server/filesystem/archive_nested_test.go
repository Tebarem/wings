package filesystem

import (
	"context"
	"path/filepath"
	"testing"

	. "github.com/franela/goblin"
)

// The entries of an archive are named relative to its base directory. A directory beneath the base
// that has the same name as the base must keep its contents under its own name.
func TestArchive_NestedDirectoryWithBaseName(t *testing.T) {
	g := Goblin(t)

	g.Describe("base directory with a nested directory of the same name", func() {
		g.It("keeps nested contents under their path when compressing restricted files", func() {
			fs, rfs := restrictedFixture(t)
			mustWriteFile(t, rfs, "plugins/plugins/inner.txt", "inner")

			info, err := fs.Restricted().CompressFiles("/plugins", []string{"plugins", "plain.txt"})
			g.Assert(err).IsNil()

			entries := archiveNamesOf(t, serverFile(rfs, "plugins/"+info.Name()))
			g.Assert(contains(entries, "plugins/inner.txt")).IsTrue()
			g.Assert(contains(entries, "plain.txt")).IsTrue()
			g.Assert(contains(entries, "inner.txt")).IsFalse()
		})

		g.It("keeps nested contents under their path in a restricted archive of the whole base", func() {
			fs, rfs := restrictedFixture(t)
			mustWriteFile(t, rfs, "plugins/plugins/inner.txt", "inner")

			dst := filepath.Join(t.TempDir(), "backup.tar.gz")
			a := &Archive{Filesystem: fs, BaseDirectory: "plugins", Restricted: true}
			g.Assert(a.Create(context.Background(), dst)).IsNil()

			entries := archiveNamesOf(t, dst)
			g.Assert(contains(entries, "plugins/inner.txt")).IsTrue()
			g.Assert(contains(entries, "plain.txt")).IsTrue()
			g.Assert(contains(entries, "token.key")).IsFalse()
		})

		g.It("keeps nested contents under their path in an unrestricted archive of the base", func() {
			fs, rfs := restrictedFixture(t)
			mustWriteFile(t, rfs, "plugins/plugins/inner.txt", "inner")

			dst := filepath.Join(t.TempDir(), "archive.tar.gz")
			a := &Archive{Filesystem: fs, BaseDirectory: "plugins"}
			g.Assert(a.Create(context.Background(), dst)).IsNil()

			entries := archiveNamesOf(t, dst)
			g.Assert(contains(entries, "plugins/inner.txt")).IsTrue()
			g.Assert(contains(entries, "plain.txt")).IsTrue()
			g.Assert(contains(entries, "inner.txt")).IsFalse()
		})
	})
}
