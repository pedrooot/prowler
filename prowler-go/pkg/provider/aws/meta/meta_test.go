package meta

import "testing"

func TestBundleLoads(t *testing.T) {
	if got := len(All()); got != 580 {
		t.Fatalf("aws checks = %d, want 580", got)
	}
	m := Get("s3_bucket_public_access")
	if m.ServiceName != "s3" {
		t.Errorf("ServiceName = %q, want s3", m.ServiceName)
	}
	if m.Severity != "critical" {
		t.Errorf("Severity = %q, want critical", m.Severity)
	}
	if m.Provider != "aws" {
		t.Errorf("Provider = %q, want aws", m.Provider)
	}
}

func TestEveryCheckHasServicePrefix(t *testing.T) {
	for id, m := range All() {
		if len(id) <= len(m.ServiceName) || id[:len(m.ServiceName)+1] != m.ServiceName+"_" {
			t.Errorf("check %s does not start with its service %s", id, m.ServiceName)
		}
	}
}
