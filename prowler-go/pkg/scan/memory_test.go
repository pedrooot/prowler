package scan

import (
	"context"
	"fmt"
	"runtime"
	"testing"

	"github.com/prowler-cloud/prowler/prowler-go/pkg/check"
	"github.com/prowler-cloud/prowler/prowler-go/pkg/finding"
)

// heavyProvider hands out a large resource set per service so the test can
// observe whether the engine keeps them alive across services.
type heavyProvider struct{ resourcesPerService int }

func (*heavyProvider) Type() string           { return "test" }
func (*heavyProvider) Config() map[string]any { return nil }
func (*heavyProvider) Identity() Identity     { return Identity{AccountUID: "123"} }

func (p *heavyProvider) Collect(_ context.Context, service string) (any, error) {
	resources := make([][]byte, p.resourcesPerService)
	for i := range resources {
		resources[i] = make([]byte, 1024)
	}
	return resources, nil
}

// discard counts findings without retaining them, like a real writer.
type discard struct{ n int }

func (d *discard) Write(*finding.Finding) error {
	d.n++
	return nil
}

func heavyPlan(services, checksPerService int) (*check.Registry, []string) {
	registry := check.NewRegistry()
	ids := make([]string, 0, services*checksPerService)
	for s := range services {
		service := fmt.Sprintf("svc%02d", s)
		for c := range checksPerService {
			id := fmt.Sprintf("%s_check%02d", service, c)
			ids = append(ids, id)
			registry.Add(newCheck(id, service, []string{service}, func(s check.Session) []*check.Report {
				resources, err := s.Service(service)
				if err != nil {
					return nil
				}
				reports := make([]*check.Report, 0, 8)
				for i := range 8 {
					reports = append(reports, &check.Report{
						Status:         check.StatusPass,
						StatusExtended: "ok",
						ResourceID:     fmt.Sprintf("r-%d", i),
					})
				}
				runtime.KeepAlive(resources)
				return reports
			}))
		}
	}
	return registry, ids
}

// TestServicesAreReleasedAsTheScanProgresses is the regression test for the
// release-as-you-go design. A scan over many services must never hold more
// than a couple of them in memory at once, however many it visits.
func TestServicesAreReleasedAsTheScanProgresses(t *testing.T) {
	const services = 20

	registry, ids := heavyPlan(services, 3)
	provider := &heavyProvider{resourcesPerService: 64}
	engine := New(provider, registry, "test", WithLimits(Limits{CheckWorkers: 2}))

	if _, err := engine.Run(context.Background(), ids, &discard{}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Each check here declares exactly one service, so at most the checks
	// running concurrently can hold one each.
	if peak := engine.PeakServicesInFlight(); peak > 2 {
		t.Errorf("peak services in flight = %d over %d services scanned; resources are not being released",
			peak, services)
	}
}

// TestSharedServiceStaysAliveUntilItsLastConsumer guards the other half of
// the design: a service several checks read must not be collected twice.
func TestSharedServiceStaysAliveUntilItsLastConsumer(t *testing.T) {
	provider := &heavyProvider{resourcesPerService: 8}
	registry := check.NewRegistry()
	ids := []string{"shared_one", "shared_two", "shared_three"}
	for _, id := range ids {
		registry.Add(newCheck(id, "shared", []string{"shared"}, func(s check.Session) []*check.Report {
			if _, err := s.Service("shared"); err != nil {
				return nil
			}
			return []*check.Report{{Status: check.StatusPass, ResourceID: "r"}}
		}))
	}

	engine := New(provider, registry, "test", WithLimits(Limits{CheckWorkers: 3}))
	if _, err := engine.Run(context.Background(), ids, &discard{}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if peak := engine.PeakServicesInFlight(); peak != 1 {
		t.Errorf("peak services in flight = %d, want 1", peak)
	}
}

func BenchmarkScan(b *testing.B) {
	registry, ids := heavyPlan(20, 5)
	provider := &heavyProvider{resourcesPerService: 1024}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		engine := New(provider, registry, "test")
		if _, err := engine.Run(context.Background(), ids, &discard{}); err != nil {
			b.Fatal(err)
		}
	}
}
