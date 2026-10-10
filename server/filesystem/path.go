package filesystem

import (
	"path/filepath"
	"strings"
)

// Generate a path to the file by cleaning it up and appending the root server path to it. This
// DOES NOT guarantee that the file resolves within the server data directory. You'll want to use
// the fs.unsafeIsInDataDirectory(p) function to confirm.
func (fs *Filesystem) unsafeFilePath(p string) string {
	// Calling filepath.Clean on the joined directory will resolve it to the absolute path,
	// removing any ../ type of resolution arguments, and leaving us with a direct path link.
	//
	// This will also trim the existing root path off the beginning of the path passed to
	// the function since that can get a bit messy.
	return filepath.Clean(filepath.Join(fs.Path(), strings.TrimPrefix(p, fs.Path())))
}

// Check that that path string starts with the server data directory path. This function DOES NOT
// validate that the rest of the path does not end up resolving out of this directory, or that the
// targeted file or folder is not a symlink doing the same thing.
func (fs *Filesystem) unsafeIsInDataDirectory(p string) bool {
	return strings.HasPrefix(strings.TrimSuffix(p, "/")+"/", strings.TrimSuffix(fs.Path(), "/")+"/")
}
