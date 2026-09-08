// Package service holds the registry of AWS service collectors the scan
// engine draws resources from.
package service

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/prowler-cloud/prowler/prowler-go/pkg/provider/aws/session"
)

// Scope is what a collector needs to know beyond the AWS session: which
// regions to sweep and which resources the user narrowed the scan to.
type Scope struct {
	Session      *session.Session
	Regions      []string
	ResourceARNs []string
	ResourceTags []string
	Concurrency  int
}

// Collector builds one service's resource set.
type Collector func(ctx context.Context, scope Scope) (any, error)

var (
	mu         sync.RWMutex
	collectors = make(map[string]Collector, 96)
)

// Register makes a service collectable by name. Services call it from init.
func Register(name string, c Collector) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := collectors[name]; dup {
		panic("aws service " + name + " registered twice")
	}
	collectors[name] = c
}

// Collect runs the named service's collector.
func Collect(ctx context.Context, name string, scope Scope) (any, error) {
	mu.RLock()
	collector, ok := collectors[name]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("aws service %q has no collector", name)
	}
	return collector(ctx, scope)
}

// Registered lists the collectable services in stable order.
func Registered() []string {
	mu.RLock()
	names := make([]string, 0, len(collectors))
	for name := range collectors {
		names = append(names, name)
	}
	mu.RUnlock()
	sort.Strings(names)
	return names
}
