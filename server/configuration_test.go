package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
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
