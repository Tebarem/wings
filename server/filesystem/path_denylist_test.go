package filesystem

import (
	"testing"
)

// The hidden and protected rules are matched against the cleaned path the filesystem
// uses, so a path cannot avoid a rule by spelling it differently. This was the upstream
// denylist check, now applied through the rules.
func TestRulesMatchTheResolvedPath(t *testing.T) {
	NewFs()
	fs, err := New(t.TempDir(), 0, nil, []string{"/server.jar", "config/"})
	if err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{
		"server.jar", "/server.jar", "./server.jar", "/./server.jar", "//server.jar",
		"/sub/../server.jar", "config/a.yml", "/x/../config/a.yml",
		"/config/", "config/", "/x/../config/",
	} {
		if lvl, err := fs.Classify(p); err != nil || lvl != LevelProtected {
			t.Errorf("expected %q to be protected, got level %v, err %v", p, lvl, err)
		}
	}
	// A path that leaves the server root is refused outright rather than classified.
	if _, err := fs.Classify("../server.jar"); err == nil {
		t.Errorf("expected ../server.jar to be refused as leaving the root")
	}
	for _, p := range []string{"sub/server.jar", "/server.jar.bak", "/configs/a.yml"} {
		if lvl, err := fs.Classify(p); err != nil || lvl != LevelNone {
			t.Errorf("expected %q to be allowed, got level %v, err %v", p, lvl, err)
		}
	}
}
