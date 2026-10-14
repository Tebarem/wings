package server

import (
	"encoding/json"
	"strings"
	"sync"

	"github.com/pterodactyl/wings/config"
	"github.com/pterodactyl/wings/environment"
)

type EggConfiguration struct {
	// The internal UUID of the Egg on the Panel.
	ID string `json:"id"`

	// Maintains a list of files that are blacklisted for opening/editing/downloading
	// or basically any type of access on the server by any user. This is NOT the same
	// as a per-user denylist, this is defined at the Egg level.
	//
	// Protected files are visible in listings, but cannot be accessed through Wings.
	FileDenylist []string `json:"file_denylist"`

	// FileHidden is a list of gitignore-style patterns for files that are completely
	// hidden from users going through Wings. They are not listed, and any attempt to
	// access them behaves as if they do not exist. Hidden takes precedence over protected.
	FileHidden []string `json:"file_hidden"`
}

type ConfigurationMeta struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Configuration is the configuration of a server, as provided by the Panel. The
// values are kept in an embedded struct so that a new configuration can replace
// them without also overwriting the mutex that guards them.
type Configuration struct {
	mu sync.RWMutex

	configurationData
}

type configurationData struct {
	// The unique identifier for the server that should be used when referencing
	// it against the Panel API (and internally). This will be used when naming
	// docker containers as well as in log output.
	Uuid string `json:"uuid"`

	Meta ConfigurationMeta `json:"meta"`

	// Whether or not the server is in a suspended state. Suspended servers cannot
	// be started or modified except in certain scenarios by an admin user.
	Suspended bool `json:"suspended"`

	// The command that should be used when booting up the server instance.
	Invocation string `json:"invocation"`

	// By default this is false, however if selected within the Panel while installing or re-installing a
	// server, specific installation scripts will be skipped for the server process.
	SkipEggScripts bool `json:"skip_egg_scripts"`

	// An array of environment variables that should be passed along to the running
	// server process.
	EnvVars environment.Variables `json:"environment"`

	// Labels is a map of container labels that should be applied to the running server process.
	Labels map[string]string `json:"labels"`

	Allocations           environment.Allocations `json:"allocations"`
	Build                 environment.Limits      `json:"build"`
	CrashDetectionEnabled bool                    `json:"crash_detection_enabled"`
	Mounts                []Mount                 `json:"mounts"`
	Egg                   EggConfiguration        `json:"egg,omitempty"`

	Container struct {
		// Defines the Docker image that will be used for this server
		Image string `json:"image,omitempty"`

		// RegistryAuth holds Docker registry credentials supplied by the Panel for this
		// server. They are only used when no node-level registry credential matches the
		// image being pulled.
		RegistryAuth []RegistryAuth `json:"registry_auth,omitempty"`
	} `json:"container,omitempty"`
}

// RegistryAuth is a set of Docker registry credentials for a single registry.
type RegistryAuth struct {
	Registry string `json:"registry"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// String redacts the credentials when formatted with %v, %+v or %s. fmt only calls it
// for this value and for exported fields or elements it reaches, never through
// unexported fields. Never log these structs, or any struct containing them, directly.
func (r RegistryAuth) String() string {
	return "{Registry:" + r.Registry + " Username:[REDACTED] Password:[REDACTED]}"
}

// GoString redacts the credentials when formatted with %#v. The same limits as String
// apply, so never log these structs directly.
func (r RegistryAuth) GoString() string {
	return "server.RegistryAuth{Registry:\"" + r.Registry + "\", Username:\"[REDACTED]\", Password:\"[REDACTED]\"}"
}

// MarshalJSON emits the registry with the credentials redacted. Wings serializes the
// full server configuration in its API responses, so the password must never be
// written out this way. Unmarshalling still reads the real values sent by the Panel.
func (r RegistryAuth) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Registry string `json:"registry"`
		Username string `json:"username"`
		Password string `json:"password"`
	}{
		Registry: r.Registry,
		Username: "[REDACTED]",
		Password: "[REDACTED]",
	})
}

// registryCredentials converts the Panel supplied registry credentials into the
// lookup map used by config.CredentialsForImage. Registry names are trimmed, entries
// without a registry are ignored and, if a registry is listed more than once, the
// first entry wins.
func registryCredentials(auth []RegistryAuth) map[string]config.RegistryConfiguration {
	if len(auth) == 0 {
		return nil
	}

	creds := make(map[string]config.RegistryConfiguration, len(auth))
	for _, a := range auth {
		registry := strings.TrimSpace(a.Registry)
		if registry == "" {
			continue
		}
		if _, ok := creds[registry]; ok {
			continue
		}
		creds[registry] = config.RegistryConfiguration{Username: a.Username, Password: a.Password}
	}

	return creds
}

// RegistryCredentials returns the Panel supplied registry credentials for this server
// as a lookup map. The configuration is read under its lock.
func (s *Server) RegistryCredentials() map[string]config.RegistryConfiguration {
	s.cfg.mu.RLock()
	defer s.cfg.mu.RUnlock()

	return registryCredentials(s.cfg.Container.RegistryAuth)
}

func (s *Server) Config() *Configuration {
	s.cfg.mu.RLock()
	defer s.cfg.mu.RUnlock()
	return &s.cfg
}

// snapshot returns a copy of the configuration that is read while holding the
// lock, so it is consistent and safe to use without holding the lock.
func (c *Configuration) snapshot() Configuration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return Configuration{configurationData: c.configurationData}
}

// DiskSpace returns the amount of disk space available to a server in bytes.
func (s *Server) DiskSpace() int64 {
	s.cfg.mu.RLock()
	defer s.cfg.mu.RUnlock()
	return s.cfg.Build.DiskSpace * 1024.0 * 1024.0
}

func (s *Server) MemoryLimit() int64 {
	s.cfg.mu.RLock()
	defer s.cfg.mu.RUnlock()
	return s.cfg.Build.MemoryLimit
}

func (c *Configuration) GetUuid() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Uuid
}

func (c *Configuration) SetSuspended(s bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Suspended = s
}
