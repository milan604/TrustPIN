package trustpin

import "testing"

func TestAnalyzeAccountsFlagsInvalidSecretsAndUngroupedNames(t *testing.T) {
	accounts := []Account{
		{Name: "Standalone", Secret: "not-a-secret", Interval: 30, Digits: 6},
		{Name: "GitHub:work", Secret: "JBSWY3DPEHPK3PXP", Interval: 15, Digits: 4},
	}

	items := AnalyzeAccounts(accounts)
	if len(items) == 0 {
		t.Fatalf("expected audit findings")
	}

	summary := SummarizeHealth(items)
	if summary.Critical == 0 {
		t.Fatalf("expected at least one critical finding, got %+v", summary)
	}
	if summary.Warning == 0 {
		t.Fatalf("expected at least one warning finding, got %+v", summary)
	}
	if summary.Info == 0 {
		t.Fatalf("expected at least one informational finding, got %+v", summary)
	}
}

func TestSplitAccountName(t *testing.T) {
	issuer, label, hasIssuer := SplitAccountName("AWS SSO:prod")
	if !hasIssuer {
		t.Fatalf("expected issuer to be detected")
	}
	if issuer != "AWS SSO" || label != "prod" {
		t.Fatalf("unexpected split %q / %q", issuer, label)
	}
}
