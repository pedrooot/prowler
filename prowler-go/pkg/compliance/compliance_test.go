package compliance

import "testing"

func TestEveryProviderLoads(t *testing.T) {
	providers := Providers()
	if len(providers) == 0 {
		t.Fatal("no compliance frameworks are embedded")
	}

	total := 0
	for _, provider := range providers {
		set, err := ForProvider(provider)
		if err != nil {
			t.Errorf("%s: %v", provider, err)
			continue
		}
		total += len(set)
		for name, framework := range set {
			if len(framework.Requirements) == 0 {
				t.Errorf("%s: framework %s has no requirements", provider, name)
			}
		}
	}
	if total != 86 {
		t.Errorf("loaded %d frameworks, want 86", total)
	}
}

func TestFrameworkKeys(t *testing.T) {
	set, err := ForProvider("aws")
	if err != nil {
		t.Fatalf("ForProvider: %v", err)
	}
	if _, ok := set["cis_3.0_aws"]; !ok {
		t.Errorf("cis_3.0_aws is missing from %v", set.Names())
	}
}

func TestChecksAndIndexAgree(t *testing.T) {
	set, err := ForProvider("aws")
	if err != nil {
		t.Fatalf("ForProvider: %v", err)
	}
	checks := set.Checks("cis_3.0_aws")
	if len(checks) == 0 {
		t.Fatal("cis_3.0_aws covers no checks")
	}
	if got := len(set.Index()["cis_3.0_aws"]); got != len(checks) {
		t.Errorf("Index has %d checks, Checks has %d", got, len(checks))
	}
}

func TestByCheckInvertsTheSet(t *testing.T) {
	set, err := ForProvider("aws")
	if err != nil {
		t.Fatalf("ForProvider: %v", err)
	}
	byCheck := set.ByCheck()
	for _, id := range set.Checks("cis_3.0_aws") {
		requirements, ok := byCheck[id]["cis_3.0_aws"]
		if !ok || len(requirements) == 0 {
			t.Errorf("check %s is not mapped back to cis_3.0_aws", id)
		}
	}
}
