package check

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// Session is the per-scan context a check needs: the provider, its
// configuration and the collected services. It is defined by the scan
// package and reaches checks as an opaque handle they type-assert.
type Session interface {
	Provider() string
	Config() map[string]any
	Service(name string) (any, error)
}

// Check evaluates one security control against the resources a service has
// already collected.
type Check interface {
	Metadata() *Metadata
	Requires() []string
	Execute(ctx context.Context, s Session) ([]*Report, error)
}

// Fixer is implemented by checks that can remediate their own findings.
type Fixer interface {
	Fix(ctx context.Context, s Session, resourceID, region string) error
}

// Registry holds every check compiled into the binary, keyed by check ID.
type Registry struct {
	mu       sync.RWMutex
	checks   map[string]Check
	byServ   map[string][]string
	provider map[string][]string
}

// NewRegistry returns an empty registry, which is what tests and embedders
// use when they want a check set independent of the compiled-in one.
func NewRegistry() *Registry {
	return &Registry{
		checks:   make(map[string]Check),
		byServ:   make(map[string][]string),
		provider: make(map[string][]string),
	}
}

var global = NewRegistry()

// Register adds a check to the global registry. Checks call it from their
// package init, and the generated import barrels make sure those packages
// are linked in.
func Register(c Check) { global.Add(c) }

// Add registers a check into this registry.
func (r *Registry) Add(c Check) {
	r.mu.Lock()
	defer r.mu.Unlock()

	m := c.Metadata()
	key := qualify(m.Provider, m.CheckID)
	if _, dup := r.checks[key]; dup {
		panic(fmt.Sprintf("check %s registered twice", key))
	}
	r.checks[key] = c
	service := qualify(m.Provider, m.ServiceName)
	r.byServ[service] = append(r.byServ[service], m.CheckID)
	r.provider[m.Provider] = append(r.provider[m.Provider], m.CheckID)
}

// Global returns the registry every compiled check registered itself into.
func Global() *Registry { return global }

// qualify scopes a check or service name to its provider, since IDs are
// only unique within a provider.
func qualify(provider, name string) string { return provider + "/" + name }

func (r *Registry) Get(provider, checkID string) (Check, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.checks[qualify(provider, checkID)]
	return c, ok
}

// ForProvider returns the check IDs of a provider in stable order.
func (r *Registry) ForProvider(provider string) []string {
	r.mu.RLock()
	ids := append([]string(nil), r.provider[provider]...)
	r.mu.RUnlock()
	sort.Strings(ids)
	return ids
}

// ForService returns the check IDs of a service in stable order.
func (r *Registry) ForService(provider, service string) []string {
	r.mu.RLock()
	ids := append([]string(nil), r.byServ[qualify(provider, service)]...)
	r.mu.RUnlock()
	sort.Strings(ids)
	return ids
}

// Services returns the services a provider covers, in stable order.
func (r *Registry) Services(provider string) []string {
	r.mu.RLock()
	seen := make(map[string]struct{}, len(r.provider[provider]))
	for _, id := range r.provider[provider] {
		seen[r.checks[qualify(provider, id)].Metadata().ServiceName] = struct{}{}
	}
	r.mu.RUnlock()

	services := make([]string, 0, len(seen))
	for name := range seen {
		services = append(services, name)
	}
	sort.Strings(services)
	return services
}

// Metadata returns the metadata of every check of a provider, keyed by ID.
func (r *Registry) Metadata(provider string) map[string]*Metadata {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := r.provider[provider]
	out := make(map[string]*Metadata, len(ids))
	for _, id := range ids {
		out[id] = r.checks[qualify(provider, id)].Metadata()
	}
	return out
}

// Categories returns every category declared by a provider's checks.
func (r *Registry) Categories(provider string) []string {
	r.mu.RLock()
	seen := make(map[string]struct{})
	for _, id := range r.provider[provider] {
		for _, category := range r.checks[qualify(provider, id)].Metadata().Categories {
			seen[category] = struct{}{}
		}
	}
	r.mu.RUnlock()

	categories := make([]string, 0, len(seen))
	for category := range seen {
		categories = append(categories, category)
	}
	sort.Strings(categories)
	return categories
}

// Len reports how many checks are compiled in.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.checks)
}
