package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pterodactyl/wings/remote"
)

const panelRegistryConfigJSON = `{"container":{"image":"ghcr.io/myorg/img:tag","registry_auth":[{"registry":"ghcr.io/myorg","username":"someuser","password":"hunter2-secret"}]}}`

func TestRegistryAuthMarshalJSONRedactsCredentials(t *testing.T) {
	var c Configuration
	if err := json.Unmarshal([]byte(panelRegistryConfigJSON), &c); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	b, err := json.Marshal(&c)
	if err != nil {
		t.Fatalf("unexpected marshal error: %v", err)
	}

	out := string(b)
	if strings.Contains(out, "hunter2-secret") || strings.Contains(out, "someuser") {
		t.Fatalf("marshaled configuration leaked credentials: %s", out)
	}
	if !strings.Contains(out, `"registry_auth":[{"registry":"ghcr.io/myorg","username":"[REDACTED]","password":"[REDACTED]"}]`) {
		t.Fatalf("expected redacted registry_auth in marshaled configuration, got: %s", out)
	}
}

func TestRegistryAuthUnmarshalFromPanelReadsCredentials(t *testing.T) {
	var c Configuration
	if err := json.Unmarshal([]byte(panelRegistryConfigJSON), &c); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if len(c.Container.RegistryAuth) != 1 {
		t.Fatalf("expected 1 registry entry, got %d", len(c.Container.RegistryAuth))
	}

	auth := c.Container.RegistryAuth[0]
	if auth.Registry != "ghcr.io/myorg" || auth.Username != "someuser" || auth.Password != "hunter2-secret" {
		t.Fatalf("unmarshal did not read the panel values: %+v", auth)
	}

	creds := registryCredentials(c.Container.RegistryAuth)
	if creds["ghcr.io/myorg"].Password != "hunter2-secret" {
		t.Fatalf("lookup map did not carry the password through")
	}
}

func TestRegistryAuthFormattingRedactsCredentials(t *testing.T) {
	auth := RegistryAuth{Registry: "ghcr.io/myorg", Username: "someuser", Password: "hunter2-secret"}

	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		out := fmt.Sprintf(format, auth)
		if strings.Contains(out, "hunter2-secret") || strings.Contains(out, "someuser") {
			t.Fatalf("format %s leaked credentials: %s", format, out)
		}
	}
}

func TestRegistryCredentialsKeepsFirstDuplicateAndSkipsEmpty(t *testing.T) {
	creds := registryCredentials([]RegistryAuth{
		{Registry: " ghcr.io/myorg ", Username: "first", Password: "p1"},
		{Registry: "ghcr.io/myorg", Username: "second", Password: "p2"},
		{Registry: "  ", Username: "blank", Password: "p3"},
	})

	if len(creds) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(creds))
	}
	if creds["ghcr.io/myorg"].Username != "first" {
		t.Fatalf("expected first duplicate to win, got %q", creds["ghcr.io/myorg"].Username)
	}
}

func newConfiguredServer(t *testing.T) *Server {
	t.Helper()
	setTestConfig(t)

	s, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SyncWithConfiguration(diskSpaceConfiguration(t, 1)); err != nil {
		t.Fatal(err)
	}
	return s
}

func diskSpaceConfiguration(t *testing.T, disk int64) remote.ServerConfigurationResponse {
	t.Helper()
	settings, err := json.Marshal(map[string]any{
		"uuid":  "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		"build": map[string]any{"disk_space": disk},
	})
	if err != nil {
		t.Fatal(err)
	}
	return remote.ServerConfigurationResponse{
		Settings:             settings,
		ProcessConfiguration: &remote.ProcessConfiguration{},
	}
}

// Syncing replaces the configuration while other goroutines may be waiting to
// read it, and none of them should be left waiting forever.
func TestSyncWithConfigurationWhileReading(t *testing.T) {
	s := newConfiguredServer(t)
	responses := []remote.ServerConfigurationResponse{diskSpaceConfiguration(t, 1), diskSpaceConfiguration(t, 2)}

	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				for j := 0; j < 500; j++ {
					if err := s.SyncWithConfiguration(responses[j%2]); err != nil {
						t.Error(err)
						return
					}
				}
			}()
			go func() {
				defer wg.Done()
				for j := 0; j < 500; j++ {
					_ = s.DiskSpace()
					_ = s.Config().GetUuid()
					_ = s.cfg.snapshot()
				}
			}()
		}
		wg.Wait()
	}()

	select {
	case <-done:
	case <-time.After(time.Second * 30):
		t.Fatal("timed out waiting for configuration readers and writers to finish")
	}
	if d := s.DiskSpace(); d != 1024*1024 && d != 2*1024*1024 {
		t.Fatalf("expected disk space from one of the synced configurations, got %d", d)
	}
}

// The configuration is returned by the API, so it must keep encoding its
// values at the top level of the object.
func TestConfigurationSnapshotJSON(t *testing.T) {
	s := newConfiguredServer(t)

	b, err := json.Marshal(s.cfg.snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]json.RawMessage
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if string(v["uuid"]) != `"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"` {
		t.Fatalf("expected uuid at the top level of the configuration, got %s", b)
	}
	if _, ok := v["build"]; !ok {
		t.Fatalf("expected build at the top level of the configuration, got %s", b)
	}
}
