package scan

import (
	"context"
	"sync"
)

// serviceStore lazily collects the services a plan needs and releases each
// one as soon as no pending check still requires it.
//
// Demand is counted up front from the plan, so a service shared by several
// checks is collected once and stays alive exactly as long as it is needed.
type serviceStore struct {
	provider Provider

	mu      sync.Mutex
	demand  map[string]int
	entries map[string]*serviceEntry

	// peakLive is the high-water mark of simultaneously collected services.
	// It is what the release design promises to keep small, and what the
	// memory regression test asserts on.
	peakLive int
}

type serviceEntry struct {
	once      sync.Once
	resources any
	err       error
}

func newServiceStore(provider Provider, demand map[string]int) *serviceStore {
	return &serviceStore{
		provider: provider,
		demand:   demand,
		entries:  make(map[string]*serviceEntry, len(demand)),
	}
}

// get collects the service on first use and returns the same resources to
// every later caller.
func (s *serviceStore) get(ctx context.Context, name string) (any, error) {
	s.mu.Lock()
	entry, ok := s.entries[name]
	if !ok {
		entry = &serviceEntry{}
		s.entries[name] = entry
		if len(s.entries) > s.peakLive {
			s.peakLive = len(s.entries)
		}
	}
	s.mu.Unlock()

	entry.once.Do(func() {
		entry.resources, entry.err = s.provider.Collect(ctx, name)
	})
	return entry.resources, entry.err
}

// release records that one check that needed these services has finished,
// dropping the resources of any service nothing else is waiting on.
func (s *serviceStore) release(names []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, name := range names {
		s.demand[name]--
		if s.demand[name] > 0 {
			continue
		}
		delete(s.demand, name)
		if entry, ok := s.entries[name]; ok {
			entry.resources = nil
			delete(s.entries, name)
		}
	}
}

// live reports how many services currently hold collected resources.
func (s *serviceStore) live() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// peak reports the most services that ever held resources at once.
func (s *serviceStore) peak() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peakLive
}
