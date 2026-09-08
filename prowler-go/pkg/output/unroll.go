package output

import (
	"sort"
	"strings"
)

// UnrollList joins values the way the CSV and HTML outputs expect. The pipe
// separator is padded on both sides; any other separator is only trailed by a
// space, which is the behaviour the Python implementation settled on.
func UnrollList(values []string, separator string) string {
	if len(values) == 0 {
		return ""
	}
	join := separator + " "
	if separator == "|" {
		join = " " + separator + " "
	}
	return strings.Join(values, join)
}

// UnrollMap renders a map as "key<separator>value" pairs joined by " | ",
// with keys sorted so the same scan always produces the same bytes.
func UnrollMap(values map[string]string, separator string) string {
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var b strings.Builder
	for i, key := range keys {
		if i > 0 {
			b.WriteString(" | ")
		}
		b.WriteString(key)
		b.WriteString(separator)
		b.WriteString(values[key])
	}
	return b.String()
}

// UnrollMapOfLists renders the compliance map, whose values are lists.
func UnrollMapOfLists(values map[string][]string, separator string) string {
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var b strings.Builder
	for i, key := range keys {
		if i > 0 {
			b.WriteString(" | ")
		}
		b.WriteString(key)
		b.WriteString(separator)
		b.WriteString(strings.Join(values[key], ", "))
	}
	return b.String()
}
