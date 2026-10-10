package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestDockerRegistryCredentialsForImage(t *testing.T) {
	cfg := DockerConfiguration{
		Registries: map[string]RegistryConfiguration{
			"registry.example.com": {
				Username: "registry",
				Password: "secret",
			},
			"registry.example.com/team": {
				Username: "team",
				Password: "secret",
			},
			"registry.example.com:5000": {
				Username: "port",
				Password: "secret",
			},
			"https://index.docker.io/v1/": {
				Username: "docker",
				Password: "secret",
			},
		},
	}

	tests := []struct {
		name     string
		image    string
		username string
	}{
		{
			name:     "registry domain",
			image:    "registry.example.com/project/image:latest",
			username: "registry",
		},
		{
			name:     "registry with port",
			image:    "registry.example.com:5000/project/image:latest",
			username: "port",
		},
		{
			name:     "registry path",
			image:    "registry.example.com/team/image:latest",
			username: "team",
		},
		{
			name:  "registry prefix is not domain",
			image: "registry.example.com.evil/project/image:latest",
		},
		{
			name:     "registry path prefix falls back to domain",
			image:    "registry.example.com/team-evil/image:latest",
			username: "registry",
		},
		{
			name:     "legacy docker hub registry",
			image:    "docker.io/library/busybox:latest",
			username: "docker",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, registry := cfg.RegistryCredentialsForImage(tt.image)
			if tt.username == "" {
				if registry != nil {
					t.Fatalf("expected no registry credentials, got username %q", registry.Username)
				}

				return
			}

			if registry == nil {
				t.Fatalf("expected registry credentials for %q", tt.image)
			}

			if registry.Username != tt.username {
				t.Fatalf("expected username %q, got %q", tt.username, registry.Username)
			}
		})
	}
}

func TestCpuPeriodMicroseconds(t *testing.T) {
	tests := []struct {
		name     string
		period   int64
		expected int64
	}{
		{name: "default period", period: 100_000, expected: 100_000},
		{name: "shorter period", period: 20_000, expected: 20_000},
		{name: "below kernel minimum", period: 500, expected: 1_000},
		{name: "above kernel maximum", period: 5_000_000, expected: 1_000_000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DockerConfiguration{CpuPeriod: tt.period}
			if v := cfg.CpuPeriodMicroseconds(); v != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, v)
			}
		})
	}
}

func TestDockerRegistryPathCredentialsDoNotMatchSiblingPath(t *testing.T) {
	cfg := DockerConfiguration{
		Registries: map[string]RegistryConfiguration{
			"registry.example.com/team": {
				Username: "team",
				Password: "secret",
			},
		},
	}

	_, registry := cfg.RegistryCredentialsForImage("registry.example.com/team-evil/image:latest")
	if registry != nil {
		t.Fatalf("expected no registry credentials, got username %q", registry.Username)
	}
}

// setGlobalConfig installs c as the global configuration until the end of t and
// restores the previous configuration and JWT algorithm during cleanup.
func setGlobalConfig(t *testing.T, c *Configuration) {
	t.Helper()

	mu.RLock()
	prevConfig, prevAlgo := _config, _jwtAlgo
	mu.RUnlock()

	t.Cleanup(func() {
		mu.Lock()
		_config, _jwtAlgo = prevConfig, prevAlgo
		mu.Unlock()
	})

	Set(c)
}

func TestCredentialsForImage(t *testing.T) {
	node := RegistryConfiguration{Username: "node-user", Password: "node-pass"}
	server := RegistryConfiguration{Username: "server-user", Password: "server-pass"}

	tests := []struct {
		name     string
		nodeRegs map[string]RegistryConfiguration
		extra    map[string]RegistryConfiguration
		image    string
		// want is the username expected on the returned credentials, empty when
		// no credentials are expected.
		want string
	}{
		{
			name:     "node config wins over server supplied credentials",
			nodeRegs: map[string]RegistryConfiguration{"ghcr.io/myorg": node},
			extra:    map[string]RegistryConfiguration{"ghcr.io/myorg": server},
			image:    "ghcr.io/myorg/img:tag",
			want:     "node-user",
		},
		{
			name:  "server supplied credentials match registry path",
			extra: map[string]RegistryConfiguration{"ghcr.io/myorg": server},
			image: "ghcr.io/myorg/img:tag",
			want:  "server-user",
		},
		{
			name:     "server supplied credentials used when node config does not match",
			nodeRegs: map[string]RegistryConfiguration{"ghcr.io/other": node},
			extra:    map[string]RegistryConfiguration{"ghcr.io/myorg": server},
			image:    "ghcr.io/myorg/img:tag",
			want:     "server-user",
		},
		{
			name:  "server supplied credentials do not match a sibling path",
			extra: map[string]RegistryConfiguration{"ghcr.io/myorg": server},
			image: "ghcr.io/other/img:tag",
		},
		{
			name:  "server supplied credentials do not match a host embedded in another domain",
			extra: map[string]RegistryConfiguration{"ghcr.io/myorg": server},
			image: "evil.com/ghcr.io/myorg/img:tag",
		},
		{
			name:  "server supplied credentials do not match a path prefix of a longer name",
			extra: map[string]RegistryConfiguration{"ghcr.io/myorg": server},
			image: "ghcr.io/myorg-evil/img:tag",
		},
		{
			name:  "docker hub short name matches docker.io registry",
			extra: map[string]RegistryConfiguration{"docker.io": server},
			image: "nginx:latest",
			want:  "server-user",
		},
		{
			name:  "docker hub short name matches full repository path",
			extra: map[string]RegistryConfiguration{"docker.io/myorg/img": server},
			image: "myorg/img:tag",
			want:  "server-user",
		},
		{
			name:  "docker hub short name does not match another repository",
			extra: map[string]RegistryConfiguration{"docker.io/myorg/img": server},
			image: "myorg/img2:tag",
		},
		{
			name:  "docker hub short name does not match a private registry",
			extra: map[string]RegistryConfiguration{"ghcr.io/myorg": server},
			image: "nginx:latest",
		},
		{
			name:  "no server supplied credentials",
			image: "ghcr.io/myorg/img:tag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setGlobalConfig(t, &Configuration{
				AuthenticationToken: "test-token",
				Docker:              DockerConfiguration{Registries: tt.nodeRegs},
			})

			_, creds := CredentialsForImage(tt.image, tt.extra)
			if tt.want == "" {
				if creds != nil {
					t.Fatalf("expected no registry credentials, got username %q", creds.Username)
				}
				return
			}

			if creds == nil {
				t.Fatalf("expected registry credentials for %q", tt.image)
			}
			if creds.Username != tt.want {
				t.Fatalf("expected username %q, got %q", tt.want, creds.Username)
			}
		})
	}
}

func TestDockerHubNamespaceMatchingRules(t *testing.T) {
	tests := []struct {
		registry string
		image    string
		match    bool
	}{
		{"docker.io/myorg", "myorg/img:tag", true},
		{"docker.io/myorg", "docker.io/myorg/img:tag", true},
		{"docker.io/myorg", "myorg/sub/img", true},
		{"index.docker.io/myorg", "myorg/img", true},
		{"https://index.docker.io/myorg", "myorg/img", true},
		{"docker.io/myorg", "otherorg/img", false},
		{"docker.io/myorg", "myorg-evil/img", false},
		{"docker.io/myorg", "nginx", false},
		{"docker.io/myorg", "ghcr.io/myorg/img", false},
		{"docker.io/myorg", "quay.io/myorg/img", false},
		{"docker.io/myorg", "evil.com/docker.io/myorg/img", false},
		{"docker.io/myorg", "docker.io/library/myorg", true},
		{"docker.io/library/myorg", "myorg/img", false},
		{"docker.io/library/myorg", "myorg", true},
		{"docker.io/nginx", "nginx:latest", true},
		{"docker.io/myorg/img", "myorg/img2", false},
		{"docker.io", "anything/else", true},
		{"docker.io", "nginx", true},
		{"ghcr.io/myorg", "ghcr.io/other/img", false},
	}

	for _, tt := range tests {
		t.Run(tt.registry+" vs "+tt.image, func(t *testing.T) {
			cfg := DockerConfiguration{
				Registries: map[string]RegistryConfiguration{
					tt.registry: {Username: "user", Password: "secret"},
				},
			}

			_, creds := cfg.RegistryCredentialsForImage(tt.image)
			if got := creds != nil; got != tt.match {
				t.Fatalf("registry %q vs image %q: expected match=%t, got match=%t", tt.registry, tt.image, tt.match, got)
			}
		})
	}
}

func TestRegistryCredentialsTieBreakIsDeterministic(t *testing.T) {
	// Both keys parse to ghcr.io/myorg and therefore score the same. The lexicographically
	// smallest key must win on every call.
	cfg := DockerConfiguration{
		Registries: map[string]RegistryConfiguration{
			"https://ghcr.io/myorg": {Username: "large"},
			"ghcr.io/myorg":         {Username: "small"},
		},
	}

	for i := 0; i < 50; i++ {
		registry, creds := cfg.RegistryCredentialsForImage("ghcr.io/myorg/img:tag")
		if registry != "ghcr.io/myorg" || creds == nil || creds.Username != "small" {
			t.Fatalf("iteration %d: expected smallest key to win, got registry %q", i, registry)
		}
	}
}

func TestRegistryConfigurationDoesNotPrintPassword(t *testing.T) {
	c := RegistryConfiguration{Username: "someuser", Password: "hunter2-secret"}

	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		out := fmt.Sprintf(format, c)
		if strings.Contains(out, "hunter2-secret") || strings.Contains(out, "someuser") {
			t.Fatalf("format %s leaked credentials: %s", format, out)
		}
	}

	// Values in exported fields and map elements are formatted through String/GoString
	// as well, which is the only nesting fmt reaches. Unexported fields are not covered.
	wrapped := struct {
		Registries map[string]RegistryConfiguration
	}{
		Registries: map[string]RegistryConfiguration{"ghcr.io/myorg": c},
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		out := fmt.Sprintf(format, wrapped)
		if strings.Contains(out, "hunter2-secret") || strings.Contains(out, "someuser") {
			t.Fatalf("format %s of wrapping struct leaked credentials: %s", format, out)
		}
	}
}
