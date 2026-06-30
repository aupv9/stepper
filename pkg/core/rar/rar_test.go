package rar_test

import (
	"encoding/json"
	"testing"

	"github.com/common-iam/iam/pkg/core/rar"
)

// decode is a helper that parses a JSON string into []AuthorizationDetail.
func decode(t *testing.T, raw string) []rar.AuthorizationDetail {
	t.Helper()
	var details []rar.AuthorizationDetail
	if err := json.Unmarshal([]byte(raw), &details); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return details
}

func TestAuthorizationDetail_UnmarshalMarshal(t *testing.T) {
	const input = `[{"type":"payment_initiation","actions":["initiate"],"locations":["https://pay.example.com"]}]`
	details := decode(t, input)

	if len(details) != 1 {
		t.Fatalf("expected 1 detail, got %d", len(details))
	}
	d := details[0]
	if d.Type != "payment_initiation" {
		t.Errorf("Type = %q, want payment_initiation", d.Type)
	}

	actions := d.GetStringSlice("actions")
	if len(actions) != 1 || actions[0] != "initiate" {
		t.Errorf("actions = %v, want [initiate]", actions)
	}

	// Round-trip marshal.
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back rar.AuthorizationDetail
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	if back.Type != "payment_initiation" {
		t.Errorf("round-trip Type = %q", back.Type)
	}
}

func TestAuthorizationDetail_MissingType(t *testing.T) {
	var d rar.AuthorizationDetail
	if err := json.Unmarshal([]byte(`{"actions":["read"]}`), &d); err == nil {
		t.Error("expected error for missing 'type' field")
	}
}

func TestAuthorizationDetailFilter_TypeMatch(t *testing.T) {
	details := decode(t, `[{"type":"account_information","actions":["read_balances"]}]`)

	f := rar.AuthorizationDetailFilter{Type: "account_information"}
	if !f.Satisfies(&details[0]) {
		t.Error("filter should satisfy matching type")
	}

	fWrong := rar.AuthorizationDetailFilter{Type: "payment_initiation"}
	if fWrong.Satisfies(&details[0]) {
		t.Error("filter should not satisfy wrong type")
	}
}

func TestAuthorizationDetailFilter_ActionsSubset(t *testing.T) {
	details := decode(t, `[{"type":"payment_initiation","actions":["initiate","status","cancel"]}]`)

	// Require subset of actions present in token.
	f := rar.AuthorizationDetailFilter{
		Type:    "payment_initiation",
		Actions: []string{"initiate", "status"},
	}
	if !f.Satisfies(&details[0]) {
		t.Error("filter should satisfy when token actions are a superset")
	}

	// Require action not in token.
	fMissing := rar.AuthorizationDetailFilter{
		Type:    "payment_initiation",
		Actions: []string{"initiate", "refund"},
	}
	if fMissing.Satisfies(&details[0]) {
		t.Error("filter should not satisfy when required action is absent")
	}
}

func TestAuthorizationDetailFilter_FieldMatch(t *testing.T) {
	details := decode(t, `[{"type":"payment_initiation","currency":"EUR","creditor_name":"Acme Corp"}]`)

	f := rar.AuthorizationDetailFilter{
		Type:   "payment_initiation",
		Fields: map[string]string{"currency": "EUR"},
	}
	if !f.Satisfies(&details[0]) {
		t.Error("filter should satisfy matching field")
	}

	fWrong := rar.AuthorizationDetailFilter{
		Type:   "payment_initiation",
		Fields: map[string]string{"currency": "USD"},
	}
	if fWrong.Satisfies(&details[0]) {
		t.Error("filter should not satisfy wrong field value")
	}

	fMissing := rar.AuthorizationDetailFilter{
		Type:   "payment_initiation",
		Fields: map[string]string{"country": "DE"},
	}
	if fMissing.Satisfies(&details[0]) {
		t.Error("filter should not satisfy absent field")
	}
}

func TestMatchAll_AllFiltersRequired(t *testing.T) {
	details := decode(t, `[
		{"type":"payment_initiation","actions":["initiate"]},
		{"type":"account_information","actions":["read_balances"]}
	]`)

	// Both filters satisfied.
	filters := []rar.AuthorizationDetailFilter{
		{Type: "payment_initiation", Actions: []string{"initiate"}},
		{Type: "account_information"},
	}
	ok, miss := rar.MatchAll(filters, details)
	if !ok {
		t.Errorf("MatchAll should succeed; missing: %s", miss)
	}

	// Second filter unsatisfied (wrong action).
	filters2 := []rar.AuthorizationDetailFilter{
		{Type: "payment_initiation"},
		{Type: "account_information", Actions: []string{"write_transactions"}},
	}
	ok2, _ := rar.MatchAll(filters2, details)
	if ok2 {
		t.Error("MatchAll should fail when one filter is unsatisfied")
	}
}

func TestMatchAll_EmptyFilters(t *testing.T) {
	details := decode(t, `[{"type":"payment_initiation"}]`)
	ok, _ := rar.MatchAll(nil, details)
	if !ok {
		t.Error("MatchAll with empty filters should always succeed")
	}
}

func TestMatchAll_EmptyDetails(t *testing.T) {
	filters := []rar.AuthorizationDetailFilter{{Type: "payment_initiation"}}
	ok, miss := rar.MatchAll(filters, nil)
	if ok {
		t.Error("MatchAll should fail when no details present but filter required")
	}
	if miss == "" {
		t.Error("missing description should be non-empty")
	}
}
