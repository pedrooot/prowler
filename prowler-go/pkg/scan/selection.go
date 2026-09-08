package scan

import (
	"fmt"
	"sort"
	"strings"

	"github.com/prowler-cloud/prowler/prowler-go/pkg/check"
)

// Selection is the user's answer to "which checks should run".
//
// The fields are mutually exclusive in the same order the CLI enforces:
// explicit checks win over severities, then a checks file, then services,
// then compliance frameworks, then categories. With none of them set, every
// check of the provider runs.
type Selection struct {
	Checks               []string
	Severities           []check.Severity
	ChecksFile           []string
	Services             []string
	ComplianceFrameworks []string
	Categories           []string

	ExcludedChecks   []string
	ExcludedServices []string
}

// threatDetection checks are expensive and only run when explicitly asked
// for, either by check name or by selecting their category.
const threatDetectionCategory = "threat-detection"

// Resolve turns a selection into the concrete, ordered set of check IDs.
func Resolve(provider string, metadata map[string]*check.Metadata, frameworks ComplianceIndex, sel Selection) ([]string, error) {
	index := newIndex(metadata)

	selected, err := index.apply(sel, frameworks)
	if err != nil {
		return nil, err
	}

	explicitChecks := len(sel.Checks) > 0
	if !explicitChecks && !contains(sel.Categories, threatDetectionCategory) {
		for _, id := range index.byCategory[threatDetectionCategory] {
			delete(selected, id)
		}
	}

	index.resolveAliases(selected)

	for _, id := range sel.ExcludedChecks {
		delete(selected, id)
	}
	for _, service := range sel.ExcludedServices {
		for _, id := range index.byService[service] {
			delete(selected, id)
		}
	}

	out := make([]string, 0, len(selected))
	for id := range selected {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

type index struct {
	metadata   map[string]*check.Metadata
	aliases    map[string][]string
	byCategory map[string][]string
	byService  map[string][]string
	bySeverity map[check.Severity][]string
	services   map[string]struct{}
}

func newIndex(metadata map[string]*check.Metadata) *index {
	ix := &index{
		metadata:   metadata,
		aliases:    make(map[string][]string),
		byCategory: make(map[string][]string),
		byService:  make(map[string][]string),
		bySeverity: make(map[check.Severity][]string, 5),
		services:   make(map[string]struct{}),
	}
	for id, m := range metadata {
		for _, alias := range m.CheckAliases {
			ix.aliases[alias] = append(ix.aliases[alias], id)
		}
		for _, category := range m.Categories {
			ix.byCategory[category] = append(ix.byCategory[category], id)
		}
		ix.byService[m.ServiceName] = append(ix.byService[m.ServiceName], id)
		ix.bySeverity[m.Severity] = append(ix.bySeverity[m.Severity], id)
		ix.services[m.ServiceName] = struct{}{}
	}
	return ix
}

func (ix *index) apply(sel Selection, frameworks ComplianceIndex) (map[string]struct{}, error) {
	selected := make(map[string]struct{}, len(ix.metadata))

	switch {
	case len(sel.Checks) > 0:
		var invalid []string
		for _, name := range sel.Checks {
			_, isCheck := ix.metadata[name]
			_, isAlias := ix.aliases[name]
			if !isCheck && !isAlias {
				invalid = append(invalid, name)
				continue
			}
			selected[name] = struct{}{}
		}
		if len(invalid) > 0 {
			return nil, fmt.Errorf("invalid check(s) specified: %s", strings.Join(invalid, ", "))
		}

	case len(sel.Severities) > 0:
		for _, severity := range sel.Severities {
			addAll(selected, ix.bySeverity[severity])
		}
		if len(sel.Services) > 0 {
			if err := ix.validateServices(sel.Services); err != nil {
				return nil, err
			}
			fromServices := make(map[string]struct{})
			for _, service := range sel.Services {
				addAll(fromServices, ix.byService[service])
			}
			intersect(selected, fromServices)
		}

	case len(sel.ChecksFile) > 0:
		for _, name := range sel.ChecksFile {
			selected[name] = struct{}{}
		}

	case len(sel.Services) > 0:
		if err := ix.validateServices(sel.Services); err != nil {
			return nil, err
		}
		for _, service := range sel.Services {
			addAll(selected, ix.byService[service])
		}

	case len(sel.ComplianceFrameworks) > 0:
		for _, name := range sel.ComplianceFrameworks {
			ids, ok := frameworks[name]
			if !ok {
				return nil, fmt.Errorf("invalid compliance framework specified: %s", name)
			}
			addAll(selected, ids)
		}

	case len(sel.Categories) > 0:
		var invalid []string
		for _, category := range sel.Categories {
			ids, ok := ix.byCategory[category]
			if !ok {
				invalid = append(invalid, category)
				continue
			}
			addAll(selected, ids)
		}
		if len(invalid) > 0 {
			return nil, fmt.Errorf("invalid category(ies) specified: %s", strings.Join(invalid, ", "))
		}

	default:
		for id := range ix.metadata {
			selected[id] = struct{}{}
		}
	}

	return selected, nil
}

// resolveAliases replaces any alias the user typed with the checks it stands for.
func (ix *index) resolveAliases(selected map[string]struct{}) {
	for name := range selected {
		targets, ok := ix.aliases[name]
		if !ok {
			continue
		}
		delete(selected, name)
		addAll(selected, targets)
	}
}

func (ix *index) validateServices(services []string) error {
	var invalid []string
	for _, service := range services {
		if _, ok := ix.services[service]; !ok {
			invalid = append(invalid, service)
		}
	}
	if len(invalid) > 0 {
		return fmt.Errorf("invalid service(s) specified: %s", strings.Join(invalid, ", "))
	}
	return nil
}

// ComplianceIndex maps a framework name to the checks its requirements cover.
type ComplianceIndex map[string][]string

func addAll(set map[string]struct{}, ids []string) {
	for _, id := range ids {
		set[id] = struct{}{}
	}
}

func intersect(set, keep map[string]struct{}) {
	for id := range set {
		if _, ok := keep[id]; !ok {
			delete(set, id)
		}
	}
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
