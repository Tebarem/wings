package filesystem

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The restricted view counts a file once however many names it has, the same as the
// unrestricted removal: deleting one of its names does not free any space.
func TestRestrictedDeletingLinkedNamesKeepsUsageAtSizeOnDisk(t *testing.T) {
	fs, rfs := NewFs()
	t.Cleanup(func() { _ = os.RemoveAll(rfs.root) })

	const size = 8 << 10
	require.NoError(t, rfs.CreateServerFile("a", randomData(t, size)))
	base := filepath.Join(rfs.root, "server")
	for _, name := range []string{"b", "c", "d"} {
		require.NoError(t, os.Link(filepath.Join(base, "a"), filepath.Join(base, name)))
	}

	_, err := fs.DiskUsage(false)
	require.NoError(t, err)
	require.Equal(t, int64(size), fs.CachedUsage())

	for _, name := range []string{"b", "c", "d"} {
		require.NoError(t, fs.Restricted().Delete(name))
	}
	assert.Equal(t, int64(size), fs.CachedUsage())

	// Removing the last name frees the space.
	require.NoError(t, fs.Restricted().Delete("a"))
	assert.Equal(t, int64(0), fs.CachedUsage())
}

// After deleting linked names through the restricted view, a write that does not fit the
// space left on disk is still refused.
func TestRestrictedDeletingLinkedNamesDoesNotAllowWritesOverLimit(t *testing.T) {
	fs, rfs := NewFs()
	t.Cleanup(func() { _ = os.RemoveAll(rfs.root) })

	const size = 8 << 10
	require.NoError(t, rfs.CreateServerFile("a", randomData(t, size)))
	base := filepath.Join(rfs.root, "server")
	for _, name := range []string{"b", "c"} {
		require.NoError(t, os.Link(filepath.Join(base, "a"), filepath.Join(base, name)))
	}

	_, err := fs.DiskUsage(false)
	require.NoError(t, err)
	for _, name := range []string{"b", "c"} {
		require.NoError(t, fs.Restricted().Delete(name))
	}

	fs.SetDiskLimit(2 * size)
	err = fs.Write("new", bytes.NewReader(randomData(t, 2*size)), 2*size, 0o644)
	assert.True(t, IsErrorCode(err, ErrCodeDiskSpace), "expected the write to be refused, got %v", err)
}
