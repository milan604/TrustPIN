package cli

import (
	"testing"

	"github.com/milan604/trustPIN/internal/trustpin"
)

func TestResolveInspectAccountPrefersExactMatch(t *testing.T) {
	accounts := []trustpin.Account{
		{Name: "AWS SSO:prod", Secret: "AAAA", Interval: 30, Digits: 6},
		{Name: "AWS SSO:staging", Secret: "BBBB", Interval: 30, Digits: 6},
	}

	account, suggestions, found, ambiguous := resolveInspectAccount(accounts, "AWS SSO:prod")
	if !found {
		t.Fatalf("expected exact match to be found")
	}
	if ambiguous {
		t.Fatalf("did not expect exact match to be ambiguous")
	}
	if len(suggestions) != 0 {
		t.Fatalf("expected no suggestions for exact match, got %v", suggestions)
	}
	if account.Name != "AWS SSO:prod" {
		t.Fatalf("unexpected match %q", account.Name)
	}
}

func TestNormalizeSortRejectsUnknownValues(t *testing.T) {
	if _, err := normalizeSort("latency"); err == nil {
		t.Fatalf("expected invalid sort to fail")
	}
}
