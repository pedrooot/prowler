package scan

import (
	"context"
	"sync"
	"testing"

	"github.com/prowler-cloud/prowler/prowler-go/pkg/check"
	"github.com/prowler-cloud/prowler/prowler-go/pkg/finding"
)

type fakeProvider struct {
	mu        sync.Mutex
	collected []string
}

func (p *fakeProvider) Type() string           { return "test" }
func (p *fakeProvider) Config() map[string]any { return nil }
func (p *fakeProvider) Identity() Identity     { return Identity{AccountUID: "123", AuthMethod: "static"} }

func (p *fakeProvider) Collect(_ context.Context, service string) (any, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.collected = append(p.collected, service)
	return service + "-resources", nil
}

type fakeCheck struct {
	meta     *check.Metadata
	requires []string
	run      func(check.Session) []*check.Report
}

func (c *fakeCheck) Metadata() *check.Metadata { return c.meta }
func (c *fakeCheck) Requires() []string        { return c.requires }
func (c *fakeCheck) Execute(_ context.Context, s check.Session) ([]*check.Report, error) {
	return c.run(s), nil
}

func newCheck(id, service string, requires []string, run func(check.Session) []*check.Report) *fakeCheck {
	return &fakeCheck{
		meta:     &check.Metadata{Provider: "test", CheckID: id, ServiceName: service, Severity: check.SeverityHigh},
		requires: requires,
		run:      run,
	}
}

type collectSink struct{ findings []*finding.Finding }

func (s *collectSink) Write(f *finding.Finding) error {
	s.findings = append(s.findings, f)
	return nil
}

func registryWith(checks ...check.Check) *check.Registry {
	r := check.NewRegistry()
	for _, c := range checks {
		r.Add(c)
	}
	return r
}

// passing reads its service, as a real check does, and reports one PASS.
func passing(id, service string) func(check.Session) []*check.Report {
	return func(s check.Session) []*check.Report {
		if _, err := s.Service(service); err != nil {
			return nil
		}
		return []*check.Report{{Status: check.StatusPass, StatusExtended: id + " ok", ResourceID: "r-" + id}}
	}
}

func TestRunStreamsFindingsAndCounts(t *testing.T) {
	provider := &fakeProvider{}
	registry := registryWith(
		newCheck("s3_one", "s3", nil, passing("s3_one", "s3")),
		newCheck("s3_two", "s3", nil, func(check.Session) []*check.Report {
			return []*check.Report{{Status: check.StatusFail, StatusExtended: "bad", ResourceID: "r2"}}
		}),
		newCheck("iam_one", "iam", nil, passing("iam_one", "iam")),
	)

	sink := &collectSink{}
	engine := New(provider, registry, "test", WithLimits(Limits{CheckWorkers: 2}))
	stats, err := engine.Run(context.Background(), []string{"s3_one", "s3_two", "iam_one"}, sink)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if stats.Total != 3 || stats.Pass != 2 || stats.Fail != 1 {
		t.Errorf("stats = %+v, want 3 total / 2 pass / 1 fail", stats)
	}
	if got := stats.FailBySeverity[check.SeverityHigh]; got != 1 {
		t.Errorf("high failures = %d, want 1", got)
	}
	if len(sink.findings) != 3 {
		t.Fatalf("sink received %d findings, want 3", len(sink.findings))
	}
}

func TestServiceCollectedOncePerScan(t *testing.T) {
	provider := &fakeProvider{}
	registry := registryWith(
		newCheck("s3_one", "s3", nil, passing("s3_one", "s3")),
		newCheck("s3_two", "s3", nil, passing("s3_two", "s3")),
		newCheck("s3_three", "s3", nil, passing("s3_three", "s3")),
	)

	engine := New(provider, registry, "test", WithLimits(Limits{CheckWorkers: 3}))
	if _, err := engine.Run(context.Background(), []string{"s3_one", "s3_two", "s3_three"}, &collectSink{}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(provider.collected) != 1 || provider.collected[0] != "s3" {
		t.Errorf("collected = %v, want exactly one s3 collection", provider.collected)
	}
}

func TestUnneededServiceIsNeverCollected(t *testing.T) {
	provider := &fakeProvider{}
	registry := registryWith(
		newCheck("s3_one", "s3", nil, passing("s3_one", "s3")),
		newCheck("ec2_one", "ec2", nil, passing("ec2_one", "ec2")),
	)

	engine := New(provider, registry, "test")
	if _, err := engine.Run(context.Background(), []string{"s3_one"}, &collectSink{}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(provider.collected) != 1 || provider.collected[0] != "s3" {
		t.Errorf("collected = %v, want only s3", provider.collected)
	}
}

func TestResourcesAreReleasedWhenLastConsumerFinishes(t *testing.T) {
	provider := &fakeProvider{}
	groups := []serviceGroup{{service: "s3", checks: []check.Check{
		newCheck("s3_one", "s3", []string{"s3", "s3control"}, nil),
		newCheck("s3_two", "s3", []string{"s3"}, nil),
	}}}

	store := newServiceStore(provider, demandOf(groups))
	ctx := context.Background()

	if _, err := store.get(ctx, "s3"); err != nil {
		t.Fatalf("get s3: %v", err)
	}
	if _, err := store.get(ctx, "s3control"); err != nil {
		t.Fatalf("get s3control: %v", err)
	}
	if store.live() != 2 {
		t.Fatalf("live services = %d, want 2", store.live())
	}

	store.release([]string{"s3", "s3control"})
	if store.live() != 1 {
		t.Errorf("after first release live = %d, want 1 (s3 still needed)", store.live())
	}

	store.release([]string{"s3"})
	if store.live() != 0 {
		t.Errorf("after last release live = %d, want 0", store.live())
	}
}

func TestCheckCannotReachUndeclaredService(t *testing.T) {
	provider := &fakeProvider{}
	var reachErr error
	registry := registryWith(newCheck("s3_one", "s3", []string{"s3"}, func(s check.Session) []*check.Report {
		_, reachErr = s.Service("iam")
		return nil
	}))

	engine := New(provider, registry, "test")
	if _, err := engine.Run(context.Background(), []string{"s3_one"}, &collectSink{}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if reachErr == nil {
		t.Error("reaching an undeclared service should fail")
	}
}

func TestPanicInCheckDoesNotAbortScan(t *testing.T) {
	provider := &fakeProvider{}
	registry := registryWith(
		newCheck("s3_boom", "s3", nil, func(check.Session) []*check.Report { panic("boom") }),
		newCheck("s3_fine", "s3", nil, passing("s3_fine", "s3")),
	)

	sink := &collectSink{}
	engine := New(provider, registry, "test", WithLimits(Limits{CheckWorkers: 1}))
	stats, err := engine.Run(context.Background(), []string{"s3_boom", "s3_fine"}, sink)
	if err == nil {
		t.Error("expected the panicking check to surface an error")
	}
	if stats.Total != 1 {
		t.Errorf("stats.Total = %d, want 1 finding from the surviving check", stats.Total)
	}
}

func TestStatusFilterDropsFindings(t *testing.T) {
	provider := &fakeProvider{}
	registry := registryWith(
		newCheck("s3_pass", "s3", nil, passing("s3_pass", "s3")),
		newCheck("s3_fail", "s3", nil, func(check.Session) []*check.Report {
			return []*check.Report{{Status: check.StatusFail, StatusExtended: "bad", ResourceID: "r"}}
		}),
	)

	sink := &collectSink{}
	engine := New(provider, registry, "test", WithStatusFilter([]check.Status{check.StatusFail}))
	stats, err := engine.Run(context.Background(), []string{"s3_pass", "s3_fail"}, sink)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if stats.Total != 1 || stats.Fail != 1 {
		t.Errorf("stats = %+v, want only the failing finding", stats)
	}
}
