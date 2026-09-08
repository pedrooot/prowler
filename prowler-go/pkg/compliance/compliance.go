// Package compliance loads the compliance frameworks and maps them onto the
// checks that satisfy their requirements.
package compliance

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// Framework is one compliance specification for one provider.
type Framework struct {
	Framework    string        `json:"Framework"`
	Name         string        `json:"Name"`
	Version      string        `json:"Version"`
	Provider     string        `json:"Provider"`
	Description  string        `json:"Description"`
	Requirements []Requirement `json:"Requirements"`
}

// Requirement is a single control, with the checks that cover it.
type Requirement struct {
	Id            string            `json:"Id"`
	Name          string            `json:"Name,omitempty"`
	Description   string            `json:"Description"`
	Checks        []string          `json:"Checks"`
	Attributes    []json.RawMessage `json:"Attributes,omitempty"`
	Tactics       []string          `json:"Tactics,omitempty"`
	SubTechniques []json.RawMessage `json:"SubTechniques,omitempty"`
}

// Set is every framework of one provider, keyed by the name the CLI accepts.
type Set map[string]*Framework

// Load reads every framework JSON of a provider from the compliance tree.
func Load(root fs.FS, provider string) (Set, error) {
	entries, err := fs.ReadDir(root, provider)
	if err != nil {
		return nil, fmt.Errorf("read compliance dir for %s: %w", provider, err)
	}

	set := make(Set, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := fs.ReadFile(root, path.Join(provider, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", entry.Name(), err)
		}
		var framework Framework
		if err := json.Unmarshal(raw, &framework); err != nil {
			return nil, fmt.Errorf("parse %s: %w", entry.Name(), err)
		}
		set[strings.TrimSuffix(entry.Name(), ".json")] = &framework
	}
	return set, nil
}

// Names lists the frameworks of the set in stable order.
func (s Set) Names() []string {
	names := make([]string, 0, len(s))
	for name := range s {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Checks returns the checks a framework's requirements cover.
func (s Set) Checks(framework string) []string {
	f, ok := s[framework]
	if !ok {
		return nil
	}
	seen := make(map[string]struct{})
	for _, requirement := range f.Requirements {
		for _, id := range requirement.Checks {
			seen[id] = struct{}{}
		}
	}
	checks := make([]string, 0, len(seen))
	for id := range seen {
		checks = append(checks, id)
	}
	sort.Strings(checks)
	return checks
}

// Index maps every framework name to the checks it covers, which is what the
// --compliance selection needs.
func (s Set) Index() map[string][]string {
	index := make(map[string][]string, len(s))
	for name := range s {
		index[name] = s.Checks(name)
	}
	return index
}

// ByCheck inverts the set: for each check, the requirements of each framework
// that reference it. This is what stamps a finding's compliance field.
func (s Set) ByCheck() map[string]map[string][]string {
	byCheck := make(map[string]map[string][]string, 1024)
	for name, framework := range s {
		for _, requirement := range framework.Requirements {
			for _, id := range requirement.Checks {
				frameworks, ok := byCheck[id]
				if !ok {
					frameworks = make(map[string][]string, 4)
					byCheck[id] = frameworks
				}
				frameworks[name] = append(frameworks[name], requirement.Id)
			}
		}
	}
	for _, frameworks := range byCheck {
		for name := range frameworks {
			sort.Strings(frameworks[name])
		}
	}
	return byCheck
}
