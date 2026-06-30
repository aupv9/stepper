// Package rar implements Rich Authorization Requests as defined in RFC 9396.
// It provides types for the authorization_details claim that carries
// fine-grained authorization information in OAuth 2.0 access tokens.
package rar

import (
	"encoding/json"
	"fmt"
)

// AuthorizationDetail represents one element of the authorization_details
// JSON array (RFC 9396 §2). The "type" field is mandatory; all other fields
// are type-specific and preserved as raw JSON for downstream inspection.
type AuthorizationDetail struct {
	// Type identifies the kind of authorization (e.g. "payment_initiation").
	Type string `json:"type"`

	// Fields contains every field of this detail object, including "type",
	// keyed by field name. Values are raw JSON so callers can decode them
	// into concrete structs without losing information.
	Fields map[string]json.RawMessage
}

// UnmarshalJSON implements json.Unmarshaler. It captures all fields as raw
// JSON and separately extracts the mandatory "type" string.
func (a *AuthorizationDetail) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("authorization_detail must be a JSON object: %w", err)
	}
	a.Fields = raw

	t, ok := raw["type"]
	if !ok {
		return fmt.Errorf("authorization_detail missing required field \"type\"")
	}
	if err := json.Unmarshal(t, &a.Type); err != nil {
		return fmt.Errorf("authorization_detail \"type\" must be a string: %w", err)
	}
	return nil
}

// MarshalJSON implements json.Marshaler. It ensures the "type" field in
// Fields is always consistent with Type before serializing.
func (a AuthorizationDetail) MarshalJSON() ([]byte, error) {
	if a.Fields == nil {
		a.Fields = make(map[string]json.RawMessage)
	}
	t, err := json.Marshal(a.Type)
	if err != nil {
		return nil, err
	}
	a.Fields["type"] = t
	return json.Marshal(a.Fields)
}

// GetStringSlice extracts a named field as []string.
// Returns nil if the field is absent or not a string array.
func (a *AuthorizationDetail) GetStringSlice(field string) []string {
	raw, ok := a.Fields[field]
	if !ok {
		return nil
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

// GetString extracts a named field as a string.
// Returns ("", false) if absent or not a string.
func (a *AuthorizationDetail) GetString(field string) (string, bool) {
	raw, ok := a.Fields[field]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// --- AuthorizationDetailFilter (policy-side constraint) ---

// AuthorizationDetailFilter specifies what authorization_details a token must
// contain for a policy to be satisfied.
//
// Matching semantics (RFC 9396 §7):
//   - The token must contain at least one detail with the matching Type.
//   - If Actions is non-empty, the token detail must include all listed actions.
//   - If Fields is non-empty, each key-value pair must appear in the token
//     detail (subset/contains check, string values only).
//
// All filters in a policy must be satisfied (AND logic).
// Within a filter, all conditions must be met (AND logic).
type AuthorizationDetailFilter struct {
	// Type is the mandatory type identifier to match (e.g. "payment_initiation").
	Type string `yaml:"type" json:"type"`

	// Actions lists action strings that must ALL appear in the token detail's
	// "actions" field. Empty = no action constraint.
	Actions []string `yaml:"actions,omitempty" json:"actions,omitempty"`

	// Fields specifies additional key→value requirements. The token detail must
	// contain all listed keys with values that marshal to the given strings.
	Fields map[string]string `yaml:"fields,omitempty" json:"fields,omitempty"`
}

// Satisfies reports whether detail satisfies all constraints in the filter.
func (f *AuthorizationDetailFilter) Satisfies(detail *AuthorizationDetail) bool {
	if detail.Type != f.Type {
		return false
	}

	// Check required actions: all filter actions must appear in the detail.
	if len(f.Actions) > 0 {
		tokenActions := detail.GetStringSlice("actions")
		for _, required := range f.Actions {
			if !containsString(tokenActions, required) {
				return false
			}
		}
	}

	// Check additional field constraints.
	for key, wantStr := range f.Fields {
		gotStr, ok := detail.GetString(key)
		if !ok || gotStr != wantStr {
			return false
		}
	}

	return true
}

// MatchAll checks that details satisfies every filter in filters.
// Returns the unsatisfied filter description on failure.
func MatchAll(filters []AuthorizationDetailFilter, details []AuthorizationDetail) (ok bool, missing string) {
	for i := range filters {
		f := &filters[i]
		found := false
		for j := range details {
			if f.Satisfies(&details[j]) {
				found = true
				break
			}
		}
		if !found {
			return false, fmt.Sprintf("no authorization_detail satisfies type=%q", f.Type)
		}
	}
	return true, ""
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
