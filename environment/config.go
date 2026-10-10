package environment

import (
	"sync"

	"github.com/pterodactyl/wings/config"
)

type Settings struct {
	Mounts      []Mount
	Allocations Allocations
	Limits      Limits
	Labels      map[string]string

	// RegistryAuth holds the Docker registry credentials the Panel supplied for this
	// server, keyed by registry (host or host/path). The map is replaced as a whole on
	// every settings update and must never be modified in place.
	RegistryAuth map[string]config.RegistryConfiguration
}

// Defines the actual configuration struct for the environment with all of the settings
// defined within it.
type Configuration struct {
	mu sync.RWMutex

	environmentVariables []string
	settings             Settings
}

// Returns a new environment configuration with the given settings and environment variables
// defined within it.
func NewConfiguration(s Settings, envVars []string) *Configuration {
	return &Configuration{
		environmentVariables: envVars,
		settings:             s,
	}
}

// Updates the settings struct for this environment on the fly. This allows modified servers to
// automatically push those changes to the environment.
func (c *Configuration) SetSettings(s Settings) {
	c.mu.Lock()
	c.settings = s
	c.mu.Unlock()
}

// Updates the environment variables associated with this environment by replacing the entire
// array of them with a new one.
func (c *Configuration) SetEnvironmentVariables(ev []string) {
	c.mu.Lock()
	c.environmentVariables = ev
	c.mu.Unlock()
}

// Returns the limits assigned to this environment.
func (c *Configuration) Limits() Limits {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.settings.Limits
}

// Returns the allocations associated with this environment.
func (c *Configuration) Allocations() Allocations {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.settings.Allocations
}

// Returns all of the mounts associated with this environment.
func (c *Configuration) Mounts() []Mount {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.settings.Mounts
}

// Labels returns the container labels associated with this instance.
func (c *Configuration) Labels() map[string]string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.settings.Labels
}

// Returns the environment variables associated with this instance.
func (c *Configuration) EnvironmentVariables() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.environmentVariables
}

// RegistryCredentials returns the Docker registry credentials supplied for this
// server. The returned map must be treated as read-only.
func (c *Configuration) RegistryCredentials() map[string]config.RegistryConfiguration {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.settings.RegistryAuth
}
