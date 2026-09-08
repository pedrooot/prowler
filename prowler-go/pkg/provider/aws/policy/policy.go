// Package policy reads AWS resource policies well enough to answer the
// questions the checks ask of them.
package policy

import (
	"encoding/json"
	"strings"
)

// Document is an AWS policy document.
type Document struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

// Statement is one policy statement. Principal and the action and resource
// lists are all shapes AWS accepts either as a string or as a list.
type Statement struct {
	Sid       string          `json:"Sid,omitempty"`
	Effect    string          `json:"Effect"`
	Principal Principal       `json:"Principal,omitempty"`
	Action    StringOrSlice   `json:"Action,omitempty"`
	NotAction StringOrSlice   `json:"NotAction,omitempty"`
	Resource  StringOrSlice   `json:"Resource,omitempty"`
	Condition json.RawMessage `json:"Condition,omitempty"`
}

// Principal is the "Principal" element, which AWS writes either as the bare
// string "*" or as a map of principal types to one or many values.
type Principal struct {
	Wildcard bool
	ByType   map[string]StringOrSlice
}

func (p *Principal) UnmarshalJSON(data []byte) error {
	var bare string
	if err := json.Unmarshal(data, &bare); err == nil {
		p.Wildcard = bare == "*"
		p.ByType = nil
		return nil
	}
	return json.Unmarshal(data, &p.ByType)
}

// Values returns the principals of one type, e.g. "AWS" or "CanonicalUser".
func (p Principal) Values(kind string) []string {
	if p.ByType == nil {
		return nil
	}
	return p.ByType[kind]
}

// StringOrSlice decodes an AWS field that is either one string or a list.
type StringOrSlice []string

func (s *StringOrSlice) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*s = StringOrSlice{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

// Parse decodes a policy document, returning nil for an absent policy.
func Parse(raw json.RawMessage) (*Document, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

// anyRootARN is the principal form that names every account's root user.
const anyRootARN = "arn:aws:iam::*:root"

// HasPublicPrincipal reports whether a statement grants access to everyone.
func HasPublicPrincipal(s Statement) bool {
	if s.Principal.Wildcard {
		return true
	}
	for _, kind := range []string{"AWS", "CanonicalUser"} {
		for _, value := range s.Principal.Values(kind) {
			if value == "*" || strings.Contains(value, anyRootARN) {
				return true
			}
		}
	}
	return false
}

// IsPublic reports whether the policy allows access from outside the account.
func IsPublic(raw json.RawMessage) bool {
	doc, err := Parse(raw)
	if err != nil || doc == nil {
		return false
	}
	for _, statement := range doc.Statement {
		if statement.Effect == "Allow" && HasPublicPrincipal(statement) {
			return true
		}
	}
	return false
}
