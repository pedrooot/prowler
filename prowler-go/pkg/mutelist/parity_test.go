package mutelist

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/prowler-cloud/prowler/prowler-go/pkg/check"
	"github.com/prowler-cloud/prowler/prowler-go/pkg/finding"
)

// TestPythonParity replays cases whose expected outcome was produced by the
// Python Mutelist implementation, so the two stay in step.
//
// Regenerate testdata/mutelist_parity.json with scripts/mutelist_golden.py
// whenever the Python mutelist changes.
func TestPythonParity(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/mutelist_parity.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}

	var cases []struct {
		Name     string            `json:"name"`
		Doc      string            `json:"doc"`
		Account  string            `json:"account"`
		Check    string            `json:"check"`
		Region   string            `json:"region"`
		Resource string            `json:"resource"`
		Tags     map[string]string `json:"tags"`
		Expected bool              `json:"expected"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("golden file is empty")
	}

	for _, c := range cases {
		m, err := Parse([]byte(c.Doc))
		if err != nil {
			t.Errorf("%s: parse: %v", c.Name, err)
			continue
		}
		f := &finding.Finding{
			AccountUID:   c.Account,
			Region:       c.Region,
			ResourceUID:  c.Resource,
			ResourceTags: c.Tags,
			Metadata:     &check.Metadata{CheckID: c.Check},
		}
		if got := m.Muted(f); got != c.Expected {
			t.Errorf("%s: Muted = %v, Python says %v", c.Name, got, c.Expected)
		}
	}
}
