// Package scan plans and runs a set of checks against a provider, streaming
// findings to the writers as they are produced.
package scan

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/prowler-cloud/prowler/prowler-go/pkg/check"
	"github.com/prowler-cloud/prowler/prowler-go/pkg/finding"
)

// Provider supplies the identity a finding is stamped with and the services
// checks read their resources from.
type Provider interface {
	Type() string
	Identity() Identity
	Config() map[string]any
	// Collect builds a service's resource set. The engine calls it once per
	// service and releases the result as soon as that service's checks end.
	Collect(ctx context.Context, service string) (any, error)
}

// Identity is the account context every finding is attributed to.
type Identity struct {
	AuthMethod       string
	AccountUID       string
	AccountName      string
	AccountEmail     string
	OrganizationUID  string
	OrganizationName string
	AccountTags      map[string]string
	Partition        string
}

// Muter decides whether a finding should be reported as muted.
type Muter interface {
	Muted(f *finding.Finding) bool
}

// Sink consumes findings in the order the engine emits them. Implementations
// are called from a single goroutine and need no locking of their own.
type Sink interface {
	Write(f *finding.Finding) error
}

// Limits bounds the concurrency and therefore the peak memory of a scan.
type Limits struct {
	// CheckWorkers caps how many checks of the same service run at once.
	CheckWorkers int
	// Buffer is the depth of the findings channel between producers and the
	// sink goroutine. It absorbs bursts without letting them grow unbounded.
	Buffer int
}

func (l Limits) withDefaults() Limits {
	if l.CheckWorkers <= 0 {
		l.CheckWorkers = runtime.GOMAXPROCS(0)
	}
	if l.Buffer <= 0 {
		l.Buffer = 256
	}
	return l
}

// Progress reports how far a scan has got, service by service.
type Progress struct {
	Service         string
	ChecksCompleted int
	ChecksTotal     int
}

// Engine executes a resolved plan against a provider.
type Engine struct {
	provider Provider
	registry *check.Registry
	version  string

	muter      Muter
	limits     Limits
	statuses   map[check.Status]struct{}
	onProgress func(Progress)

	// startedAt stamps every finding of the scan, matching the single
	// scan-wide timestamp the Python implementation reports.
	startedAt time.Time
}

// Option configures an Engine.
type Option func(*Engine)

func WithMuter(m Muter) Option             { return func(e *Engine) { e.muter = m } }
func WithLimits(l Limits) Option           { return func(e *Engine) { e.limits = l.withDefaults() } }
func WithProgress(f func(Progress)) Option { return func(e *Engine) { e.onProgress = f } }

// WithStatusFilter keeps only findings whose status is listed.
func WithStatusFilter(statuses []check.Status) Option {
	return func(e *Engine) {
		if len(statuses) == 0 {
			e.statuses = nil
			return
		}
		e.statuses = make(map[check.Status]struct{}, len(statuses))
		for _, s := range statuses {
			e.statuses[s] = struct{}{}
		}
	}
}

func New(provider Provider, registry *check.Registry, version string, opts ...Option) *Engine {
	e := &Engine{
		provider:  provider,
		registry:  registry,
		version:   version,
		limits:    Limits{}.withDefaults(),
		startedAt: time.Now(),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Run executes the given checks and streams every finding to the sink.
//
// Checks are grouped by service and services are processed one at a time:
// a service's resources are collected, its checks run concurrently against
// them, and the resource set is dropped before the next service starts. Peak
// memory therefore tracks the heaviest single service, not the whole scan.
func (e *Engine) Run(ctx context.Context, checkIDs []string, sink Sink) (*finding.Stats, error) {
	groups := e.groupByService(checkIDs)
	store := newServiceStore(e.provider, demandOf(groups))
	stats := finding.NewStats()

	findings := make(chan *finding.Finding, e.limits.Buffer)
	var sinkErr error
	var consumer sync.WaitGroup
	consumer.Add(1)
	go func() {
		defer consumer.Done()
		for f := range findings {
			stats.Add(f)
			if sinkErr == nil {
				sinkErr = sink.Write(f)
			}
		}
	}()

	var runErr error
	for _, group := range groups {
		if err := ctx.Err(); err != nil {
			runErr = err
			break
		}
		if err := e.runService(ctx, group, store, findings); err != nil {
			runErr = errors.Join(runErr, err)
		}
	}

	close(findings)
	consumer.Wait()

	return stats, errors.Join(runErr, sinkErr)
}

type serviceGroup struct {
	service string
	checks  []check.Check
}

func (e *Engine) groupByService(checkIDs []string) []serviceGroup {
	byService := make(map[string][]check.Check, 32)
	for _, id := range checkIDs {
		c, ok := e.registry.Get(e.provider.Type(), id)
		if !ok {
			continue
		}
		service := c.Metadata().ServiceName
		byService[service] = append(byService[service], c)
	}

	groups := make([]serviceGroup, 0, len(byService))
	for service, checks := range byService {
		sort.Slice(checks, func(i, j int) bool {
			return checks[i].Metadata().CheckID < checks[j].Metadata().CheckID
		})
		groups = append(groups, serviceGroup{service: service, checks: checks})
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].service < groups[j].service })
	return groups
}

// runService runs one service's checks, collecting whatever services they
// require and releasing each one as its last consumer finishes.
func (e *Engine) runService(ctx context.Context, group serviceGroup, store *serviceStore, out chan<- *finding.Finding) error {
	workers := min(e.limits.CheckWorkers, len(group.checks))
	slots := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs error
	completed := 0

	for _, c := range group.checks {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		slots <- struct{}{}
		go func(c check.Check) {
			defer wg.Done()
			defer func() { <-slots }()

			required := requiredServices(c)
			defer store.release(required)

			reports, err := e.execute(ctx, c, &session{provider: e.provider, store: store, ctx: ctx, allowed: required})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = errors.Join(errs, err)
			}
			for _, r := range reports {
				if f := e.toFinding(c.Metadata(), r); f != nil {
					out <- f
				}
			}
			completed++
			if e.onProgress != nil {
				e.onProgress(Progress{Service: group.service, ChecksCompleted: completed, ChecksTotal: len(group.checks)})
			}
		}(c)
	}

	wg.Wait()
	return errs
}

// requiredServices returns the services a check reads, defaulting to its own
// service when it declares none.
func requiredServices(c check.Check) []string {
	if required := c.Requires(); len(required) > 0 {
		return required
	}
	return []string{c.Metadata().ServiceName}
}

// demandOf counts how many checks require each service, which is what lets
// the store know when a service can be dropped.
func demandOf(groups []serviceGroup) map[string]int {
	demand := make(map[string]int, len(groups))
	for _, group := range groups {
		for _, c := range group.checks {
			for _, service := range requiredServices(c) {
				demand[service]++
			}
		}
	}
	return demand
}

// execute isolates a check so a panic in one does not abort the scan, which
// is the behaviour the Python implementation gets from its try/except.
func (e *Engine) execute(ctx context.Context, c check.Check, s check.Session) (reports []*check.Report, err error) {
	defer func() {
		if r := recover(); r != nil {
			reports = nil
			err = fmt.Errorf("check %s panicked: %v", c.Metadata().CheckID, r)
		}
	}()
	return c.Execute(ctx, s)
}

func (e *Engine) toFinding(m *check.Metadata, r *check.Report) *finding.Finding {
	if r == nil {
		return nil
	}
	identity := e.provider.Identity()
	f := &finding.Finding{
		AuthMethod:              identity.AuthMethod,
		Timestamp:               e.startedAt,
		AccountUID:              identity.AccountUID,
		AccountName:             identity.AccountName,
		AccountEmail:            identity.AccountEmail,
		AccountOrganizationUID:  identity.OrganizationUID,
		AccountOrganizationName: identity.OrganizationName,
		AccountTags:             identity.AccountTags,
		Metadata:                m,
		UID:                     buildUID(e.provider.Type(), m.CheckID, r),
		Status:                  r.Status,
		StatusExtended:          r.StatusExtended,
		Muted:                   r.Muted,
		ResourceUID:             resourceUID(r),
		ResourceName:            r.ResourceName,
		ResourceDetails:         r.ResourceDetails,
		ResourceTags:            r.ResourceTags,
		ResourceMetadata:        r.Resource,
		Partition:               firstNonEmpty(r.Partition, identity.Partition),
		Region:                  r.Region,
		ProwlerVersion:          e.version,
	}

	if e.muter != nil && e.muter.Muted(f) {
		f.Muted = true
	}
	if !e.keep(f.Status) {
		return nil
	}
	return f
}

func (e *Engine) keep(status check.Status) bool {
	if e.statuses == nil {
		return true
	}
	_, ok := e.statuses[status]
	return ok
}

func buildUID(provider, checkID string, r *check.Report) string {
	return fmt.Sprintf("prowler-%s-%s-%s-%s-%s", provider, checkID, r.ResourceID, r.Region, r.ResourceName)
}

func resourceUID(r *check.Report) string {
	return firstNonEmpty(r.ResourceARN, r.ResourceID, r.ResourceName)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// session is the per-check view of the scan: it can reach exactly the
// services that check declared it needs.
type session struct {
	provider Provider
	store    *serviceStore
	ctx      context.Context
	allowed  []string
}

func (s *session) Provider() string       { return s.provider.Type() }
func (s *session) Config() map[string]any { return s.provider.Config() }

func (s *session) Service(name string) (any, error) {
	for _, allowed := range s.allowed {
		if allowed == name {
			return s.store.get(s.ctx, name)
		}
	}
	return nil, fmt.Errorf("service %q is not declared in the check's Requires()", name)
}
