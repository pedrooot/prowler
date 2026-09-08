// Package mutelist decides which findings are reported as muted.
package mutelist

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/prowler-cloud/prowler/prowler-go/pkg/finding"
	"github.com/prowler-cloud/prowler/prowler-go/pkg/output"
)

// Document is the parsed mutelist file.
type Document struct {
	Mutelist struct {
		Accounts map[string]Account `yaml:"Accounts"`
	} `yaml:"Mutelist"`
}

// Account groups the muted checks of one account, or of every account under "*".
type Account struct {
	Checks map[string]Entry `yaml:"Checks"`
}

// Entry is one muted check with the scope it applies to.
type Entry struct {
	Regions     []string   `yaml:"Regions"`
	Resources   []string   `yaml:"Resources"`
	Tags        []string   `yaml:"Tags"`
	Exceptions  *Exception `yaml:"Exceptions"`
	Description string     `yaml:"Description"`
}

// Exception narrows an entry: a finding matching it is not muted.
type Exception struct {
	Accounts  []string `yaml:"Accounts"`
	Regions   []string `yaml:"Regions"`
	Resources []string `yaml:"Resources"`
	Tags      []string `yaml:"Tags"`
}

// Mutelist evaluates findings against a parsed document.
//
// Patterns are compiled on first use and cached, since a scan evaluates the
// same handful of patterns against every finding it produces.
type Mutelist struct {
	accounts map[string]Account

	mu       sync.RWMutex
	compiled map[string]*regexp.Regexp
}

// Load reads and validates a mutelist file.
func Load(path string) (*Mutelist, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read mutelist: %w", err)
	}
	return Parse(raw)
}

// Parse builds a mutelist from YAML content.
func Parse(raw []byte) (*Mutelist, error) {
	var doc Document
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse mutelist: %w", err)
	}
	if doc.Mutelist.Accounts == nil {
		return nil, fmt.Errorf("mutelist: the Accounts key is required")
	}
	for name, account := range doc.Mutelist.Accounts {
		if account.Checks == nil {
			return nil, fmt.Errorf("mutelist: account %q is missing the Checks key", name)
		}
		for id, entry := range account.Checks {
			if entry.Regions == nil || entry.Resources == nil {
				return nil, fmt.Errorf("mutelist: check %q needs both Regions and Resources", id)
			}
		}
	}
	return &Mutelist{accounts: doc.Mutelist.Accounts, compiled: make(map[string]*regexp.Regexp)}, nil
}

// Muted reports whether a finding is covered by the mutelist. Every field is
// ANDed: the check, region, resource and tags must all match, and the entry's
// exceptions must not.
func (m *Mutelist) Muted(f *finding.Finding) bool {
	if m == nil {
		return false
	}
	tags := output.UnrollMap(f.ResourceTags, "=")
	for name, account := range m.accounts {
		if name != "*" && name != f.AccountUID {
			continue
		}
		if m.mutedInChecks(account.Checks, f.AccountUID, f.Metadata.CheckID, f.Region, f.ResourceUID, tags) {
			return true
		}
	}
	return false
}

func (m *Mutelist) mutedInChecks(checks map[string]Entry, account, checkID, region, resource, tags string) bool {
	muted := false
	for pattern, entry := range checks {
		// The mutelist format accepts "lambda" as a prefix for the
		// awslambda service.
		if after, found := strings.CutPrefix(pattern, "lambda"); found {
			pattern = "awslambda" + after
		}

		if pattern != "*" && pattern != checkID && !m.anyMatches([]string{pattern}, checkID) {
			continue
		}
		// An exception stops the evaluation for this account and keeps
		// whatever an earlier entry already decided.
		if m.excepted(entry.Exceptions, account, region, resource, tags) {
			return muted
		}

		mutedTags := entry.Tags
		if len(mutedTags) == 0 {
			mutedTags = []string{"*"}
		}
		if m.anyMatches(entry.Regions, region) &&
			m.anyMatches(entry.Resources, resource) &&
			m.allMatch(mutedTags, tags) {
			muted = true
		}
	}
	return muted
}

// excepted reports whether every field the exception constrains matches, with
// unconstrained fields treated as wildcards.
func (m *Mutelist) excepted(e *Exception, account, region, resource, tags string) bool {
	if e == nil {
		return false
	}
	accountExcepted := m.anyMatches(e.Accounts, account)
	regionExcepted := m.anyMatches(e.Regions, region)
	resourceExcepted := m.anyMatches(e.Resources, resource)
	tagExcepted := m.allMatch(e.Tags, tags)

	if !accountExcepted && !regionExcepted && !resourceExcepted && !tagExcepted {
		return false
	}
	return (accountExcepted || len(e.Accounts) == 0) &&
		(regionExcepted || len(e.Regions) == 0) &&
		(resourceExcepted || len(e.Resources) == 0) &&
		(tagExcepted || len(e.Tags) == 0)
}

// anyMatches is the OR form used for checks, regions, resources and accounts.
func (m *Mutelist) anyMatches(patterns []string, value string) bool {
	if len(patterns) == 0 {
		return false
	}
	for _, pattern := range patterns {
		if re := m.compile(pattern); re != nil && re.MatchString(value) {
			return true
		}
	}
	return false
}

// allMatch is the AND form used for tags: every listed pattern must match, so
// OR is expressed with regex alternation inside a single pattern.
func (m *Mutelist) allMatch(patterns []string, value string) bool {
	if len(patterns) == 0 {
		return false
	}
	for _, pattern := range patterns {
		re := m.compile(pattern)
		if re == nil || !re.MatchString(value) {
			return false
		}
	}
	return true
}

// compile turns a mutelist pattern into a regexp, expanding the shell-style
// star the format uses.
func (m *Mutelist) compile(pattern string) *regexp.Regexp {
	m.mu.RLock()
	re, ok := m.compiled[pattern]
	m.mu.RUnlock()
	if ok {
		return re
	}

	expanded := strings.ReplaceAll(pattern, "*", ".*")
	re, err := regexp.Compile(expanded)
	if err != nil {
		re = nil
	}

	m.mu.Lock()
	m.compiled[pattern] = re
	m.mu.Unlock()
	return re
}
