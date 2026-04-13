package trustpin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpsertAccountsReplacesBySecret(t *testing.T) {
	existing := []Account{
		{Name: "GitHub:personal", Secret: "AAAA BBBB", Interval: 30, Digits: 6},
	}

	updated, summary := upsertAccounts(existing, []Account{
		{Name: "GitHub:work", Secret: "AAAABBBB", Interval: 60, Digits: 8},
	})

	if len(updated) != 1 {
		t.Fatalf("expected 1 account after replacement, got %d", len(updated))
	}
	if updated[0].Name != "GitHub:work" {
		t.Fatalf("expected replacement account name to be updated, got %q", updated[0].Name)
	}
	if summary.Added != 0 || summary.Replaced != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
}

func TestBuildAccountSnapshotSetsStandaloneIssuer(t *testing.T) {
	snapshot := BuildAccountSnapshot(Account{
		Name:     "Personal",
		Secret:   "JBSWY3DPEHPK3PXP",
		Interval: 30,
		Digits:   6,
	})

	if snapshot.Issuer != "Standalone" {
		t.Fatalf("expected standalone issuer, got %q", snapshot.Issuer)
	}
	if snapshot.DisplayName != "Personal" {
		t.Fatalf("expected display name to match label, got %q", snapshot.DisplayName)
	}
}

func TestServiceSaveLoadUsesEncryptedStore(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "accounts.enc")
	keyPath := filepath.Join(tmpDir, "accounts.key")
	service := Service{
		StorePath: storePath,
		KeyPath:   keyPath,
	}

	input := []Account{{
		Name:     "GitHub:work",
		Secret:   "JBSWY3DPEHPK3PXP",
		Interval: 30,
		Digits:   6,
	}}

	if err := service.SaveAccounts(input); err != nil {
		t.Fatalf("save accounts: %v", err)
	}

	raw, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	if !strings.HasPrefix(string(raw), storeMagic) {
		t.Fatalf("expected encrypted magic prefix")
	}
	if strings.Contains(string(raw), "GitHub:work") {
		t.Fatalf("expected store contents to be encrypted")
	}

	loaded, err := service.LoadAccounts()
	if err != nil {
		t.Fatalf("load accounts: %v", err)
	}
	if len(loaded) != 1 || loaded[0].Name != input[0].Name {
		t.Fatalf("unexpected loaded accounts: %+v", loaded)
	}
}

func TestServiceMigratesLegacyPlaintextStore(t *testing.T) {
	tmpDir := t.TempDir()
	legacyPath := filepath.Join(tmpDir, "accounts.json")
	storePath := filepath.Join(tmpDir, "secure", "accounts.enc")
	keyPath := filepath.Join(tmpDir, "secure", "accounts.key")

	if err := os.WriteFile(legacyPath, []byte(`[{"Name":"AWS SSO:prod","Secret":"JBSWY3DPEHPK3PXP","Interval":30,"Digits":6}]`), 0o600); err != nil {
		t.Fatalf("write legacy store: %v", err)
	}

	service := Service{
		StorePath:  storePath,
		KeyPath:    keyPath,
		LegacyPath: legacyPath,
	}

	loaded, err := service.LoadAccounts()
	if err != nil {
		t.Fatalf("load accounts: %v", err)
	}
	if len(loaded) != 1 || loaded[0].Name != "AWS SSO:prod" {
		t.Fatalf("unexpected migrated accounts: %+v", loaded)
	}

	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Fatalf("expected legacy store to be removed after migration")
	}

	raw, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatalf("read encrypted store: %v", err)
	}
	if !strings.HasPrefix(string(raw), storeMagic) {
		t.Fatalf("expected encrypted store magic prefix")
	}
}

func TestServiceMigratesLegacyWhenEncryptedStoreAlreadyExistsButIsEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "secure", "accounts.enc")
	keyPath := filepath.Join(tmpDir, "secure", "accounts.key")
	legacyPath := filepath.Join(tmpDir, "accounts.json")

	service := Service{
		StorePath:  storePath,
		KeyPath:    keyPath,
		LegacyPath: legacyPath,
	}

	if err := service.SaveAccounts([]Account{}); err != nil {
		t.Fatalf("seed empty encrypted store: %v", err)
	}
	if err := os.WriteFile(legacyPath, []byte(`[{"Name":"GitHub:legacy","Secret":"JBSWY3DPEHPK3PXP","Interval":30,"Digits":6}]`), 0o600); err != nil {
		t.Fatalf("write legacy store: %v", err)
	}

	loaded, err := service.LoadAccounts()
	if err != nil {
		t.Fatalf("load accounts: %v", err)
	}
	if len(loaded) != 1 || loaded[0].Name != "GitHub:legacy" {
		t.Fatalf("unexpected migrated accounts: %+v", loaded)
	}
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Fatalf("expected legacy store to be removed after migration")
	}
}

func TestServiceUpdateAccountRenamesAndUpdatesSecret(t *testing.T) {
	tmpDir := t.TempDir()
	service := Service{
		StorePath: filepath.Join(tmpDir, "accounts.enc"),
		KeyPath:   filepath.Join(tmpDir, "accounts.key"),
	}

	if err := service.SaveAccounts([]Account{
		{Name: "GitHub:personal", Secret: "JBSWY3DPEHPK3PXP", Interval: 30, Digits: 6},
	}); err != nil {
		t.Fatalf("seed accounts: %v", err)
	}

	if err := service.UpdateAccount("GitHub:personal", Account{
		Name:     "GitHub:work",
		Secret:   "MFRGGZDFMZTWQ2LK",
		Interval: 60,
		Digits:   8,
	}); err != nil {
		t.Fatalf("update account: %v", err)
	}

	accounts, err := service.LoadAccounts()
	if err != nil {
		t.Fatalf("load accounts: %v", err)
	}
	if len(accounts) != 1 {
		t.Fatalf("expected 1 account after update, got %d", len(accounts))
	}
	if accounts[0].Name != "GitHub:work" || accounts[0].Secret != "MFRGGZDFMZTWQ2LK" {
		t.Fatalf("unexpected updated account: %+v", accounts[0])
	}
	if accounts[0].Interval != 60 || accounts[0].Digits != 8 {
		t.Fatalf("expected policy changes to persist: %+v", accounts[0])
	}
}

func TestServiceUpdateAccountRejectsCollision(t *testing.T) {
	tmpDir := t.TempDir()
	service := Service{
		StorePath: filepath.Join(tmpDir, "accounts.enc"),
		KeyPath:   filepath.Join(tmpDir, "accounts.key"),
	}

	if err := service.SaveAccounts([]Account{
		{Name: "GitHub:personal", Secret: "JBSWY3DPEHPK3PXP", Interval: 30, Digits: 6},
		{Name: "GitHub:work", Secret: "MFRGGZDFMZTWQ2LK", Interval: 30, Digits: 6},
	}); err != nil {
		t.Fatalf("seed accounts: %v", err)
	}

	err := service.UpdateAccount("GitHub:personal", Account{
		Name:     "GitHub:work",
		Secret:   "NB2W45DFOIZA====",
		Interval: 30,
		Digits:   6,
	})
	if err == nil {
		t.Fatalf("expected duplicate-name update to fail")
	}
}

func TestServiceUpdateAccountKeepsExistingSecretWhenBlank(t *testing.T) {
	tmpDir := t.TempDir()
	service := Service{
		StorePath: filepath.Join(tmpDir, "accounts.enc"),
		KeyPath:   filepath.Join(tmpDir, "accounts.key"),
	}

	if err := service.SaveAccounts([]Account{
		{Name: "GitHub:personal", Secret: "JBSWY3DPEHPK3PXP", Interval: 30, Digits: 6},
	}); err != nil {
		t.Fatalf("seed accounts: %v", err)
	}

	if err := service.UpdateAccount("GitHub:personal", Account{
		Name:     "GitHub:renamed",
		Interval: 60,
		Digits:   8,
	}); err != nil {
		t.Fatalf("update account with blank secret: %v", err)
	}

	accounts, err := service.LoadAccounts()
	if err != nil {
		t.Fatalf("load accounts: %v", err)
	}
	if accounts[0].Secret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("expected secret to be preserved, got %+v", accounts[0])
	}
}

func TestGenerateTOTPWithSHA256(t *testing.T) {
	otp, remaining, err := GenerateTOTPWithAlgorithm("JBSWY3DPEHPK3PXP", 30, 6, AlgorithmSHA256)
	if err != nil {
		t.Fatalf("SHA256 TOTP failed: %v", err)
	}
	if len(otp) != 6 {
		t.Fatalf("expected 6 digits, got %q", otp)
	}
	if remaining <= 0 || remaining > 30 {
		t.Fatalf("unexpected remaining time: %d", remaining)
	}
}

func TestGenerateTOTPWithSHA512(t *testing.T) {
	otp, _, err := GenerateTOTPWithAlgorithm("JBSWY3DPEHPK3PXP", 30, 8, AlgorithmSHA512)
	if err != nil {
		t.Fatalf("SHA512 TOTP failed: %v", err)
	}
	if len(otp) != 8 {
		t.Fatalf("expected 8 digits, got %q", otp)
	}
}

func TestGenerateHOTP(t *testing.T) {
	otp, err := GenerateHOTP("JBSWY3DPEHPK3PXP", 0, 6, AlgorithmSHA1)
	if err != nil {
		t.Fatalf("HOTP failed: %v", err)
	}
	if len(otp) != 6 {
		t.Fatalf("expected 6 digits, got %q", otp)
	}

	// HOTP with same counter should always produce the same code
	otp2, err := GenerateHOTP("JBSWY3DPEHPK3PXP", 0, 6, AlgorithmSHA1)
	if err != nil {
		t.Fatalf("HOTP repeat failed: %v", err)
	}
	if otp != otp2 {
		t.Fatalf("same counter should produce same code: %q != %q", otp, otp2)
	}

	// Different counter should produce different code (almost certainly)
	otp3, err := GenerateHOTP("JBSWY3DPEHPK3PXP", 1, 6, AlgorithmSHA1)
	if err != nil {
		t.Fatalf("HOTP counter=1 failed: %v", err)
	}
	if otp == otp3 {
		t.Logf("warning: counter 0 and 1 produced same code (unlikely but possible)")
	}
}

func TestGenerateSteamCode(t *testing.T) {
	code, remaining, err := GenerateSteamCode("JBSWY3DPEHPK3PXP", 30)
	if err != nil {
		t.Fatalf("Steam code failed: %v", err)
	}
	if len(code) != 5 {
		t.Fatalf("expected 5 char Steam code, got %q", code)
	}
	if remaining <= 0 || remaining > 30 {
		t.Fatalf("unexpected remaining time: %d", remaining)
	}
	// Verify only valid Steam characters
	for _, c := range code {
		if !strings.ContainsRune("23456789BCDFGHJKMNPQRTVWXY", c) {
			t.Fatalf("invalid Steam character %q in code %q", string(c), code)
		}
	}
}

func TestBuildAccountSnapshotHOTP(t *testing.T) {
	snapshot := BuildAccountSnapshot(Account{
		Name:    "Service:test",
		Secret:  "JBSWY3DPEHPK3PXP",
		Digits:  6,
		Type:    TypeHOTP,
		Counter: 42,
	})
	if snapshot.Type != TypeHOTP {
		t.Fatalf("expected HOTP type, got %q", snapshot.Type)
	}
	if snapshot.Counter != 42 {
		t.Fatalf("expected counter 42, got %d", snapshot.Counter)
	}
	if snapshot.TimeRemaining != -1 {
		t.Fatalf("expected -1 time remaining for HOTP, got %d", snapshot.TimeRemaining)
	}
	if !strings.Contains(snapshot.PolicyLabel, "counter 42") {
		t.Fatalf("expected counter in policy label, got %q", snapshot.PolicyLabel)
	}
}

func TestBuildAccountSnapshotSteam(t *testing.T) {
	snapshot := BuildAccountSnapshot(Account{
		Name:   "Steam:myaccount",
		Secret: "JBSWY3DPEHPK3PXP",
		Type:   TypeSteam,
	})
	if snapshot.Type != TypeSteam {
		t.Fatalf("expected steam type, got %q", snapshot.Type)
	}
	if snapshot.Digits != 5 {
		t.Fatalf("expected 5 digits for Steam, got %d", snapshot.Digits)
	}
	if snapshot.PolicyLabel != "Steam Guard" {
		t.Fatalf("expected Steam Guard policy, got %q", snapshot.PolicyLabel)
	}
}

func TestBuildOTPAuthURI(t *testing.T) {
	uri := BuildOTPAuthURI(Account{
		Name:      "GitHub:work",
		Secret:    "JBSWY3DPEHPK3PXP",
		Interval:  30,
		Digits:    6,
		Algorithm: AlgorithmSHA1,
		Type:      TypeTOTP,
	})
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Fatalf("expected otpauth URI, got %q", uri)
	}
	if !strings.Contains(uri, "secret=JBSWY3DPEHPK3PXP") {
		t.Fatalf("expected secret in URI, got %q", uri)
	}
	if !strings.Contains(uri, "issuer=GitHub") {
		t.Fatalf("expected issuer in URI, got %q", uri)
	}
}

func TestBuildOTPAuthURIHOTP(t *testing.T) {
	uri := BuildOTPAuthURI(Account{
		Name:    "Service:test",
		Secret:  "JBSWY3DPEHPK3PXP",
		Digits:  6,
		Type:    TypeHOTP,
		Counter: 10,
	})
	if !strings.HasPrefix(uri, "otpauth://hotp/") {
		t.Fatalf("expected hotp URI, got %q", uri)
	}
	if !strings.Contains(uri, "counter=10") {
		t.Fatalf("expected counter in URI, got %q", uri)
	}
}

func TestNormalizeAlgorithm(t *testing.T) {
	cases := map[string]string{
		"":        AlgorithmSHA1,
		"sha1":    AlgorithmSHA1,
		"SHA256":  AlgorithmSHA256,
		"sha-256": AlgorithmSHA256,
		"SHA512":  AlgorithmSHA512,
		"sha-512": AlgorithmSHA512,
		"unknown": AlgorithmSHA1,
	}
	for input, expected := range cases {
		if got := NormalizeAlgorithm(input); got != expected {
			t.Fatalf("NormalizeAlgorithm(%q) = %q, want %q", input, got, expected)
		}
	}
}

func TestNormalizeType(t *testing.T) {
	cases := map[string]string{
		"":      TypeTOTP,
		"totp":  TypeTOTP,
		"HOTP":  TypeHOTP,
		"steam": TypeSteam,
		"other": TypeTOTP,
	}
	for input, expected := range cases {
		if got := NormalizeType(input); got != expected {
			t.Fatalf("NormalizeType(%q) = %q, want %q", input, got, expected)
		}
	}
}

func TestAccountTagsAndFavoritesPersist(t *testing.T) {
	tmpDir := t.TempDir()
	service := Service{
		StorePath: filepath.Join(tmpDir, "accounts.enc"),
		KeyPath:   filepath.Join(tmpDir, "accounts.key"),
	}

	input := []Account{{
		Name:     "GitHub:work",
		Secret:   "JBSWY3DPEHPK3PXP",
		Interval: 30,
		Digits:   6,
		Tags:     []string{"work", "dev"},
		Favorite: true,
		Notes:    "Recovery: ABC123",
	}}

	if err := service.SaveAccounts(input); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := service.LoadAccounts()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 account, got %d", len(loaded))
	}
	if len(loaded[0].Tags) != 2 || loaded[0].Tags[0] != "work" {
		t.Fatalf("tags not preserved: %v", loaded[0].Tags)
	}
	if !loaded[0].Favorite {
		t.Fatalf("favorite not preserved")
	}
	if loaded[0].Notes != "Recovery: ABC123" {
		t.Fatalf("notes not preserved: %q", loaded[0].Notes)
	}
}

func TestGenerateQRCodePNG(t *testing.T) {
	png, err := GenerateQRCodePNG(Account{
		Name:     "Test:account",
		Secret:   "JBSWY3DPEHPK3PXP",
		Interval: 30,
		Digits:   6,
	}, 128)
	if err != nil {
		t.Fatalf("QR generation failed: %v", err)
	}
	if len(png) < 100 {
		t.Fatalf("QR PNG too small: %d bytes", len(png))
	}
	// Check PNG magic bytes
	if png[0] != 0x89 || png[1] != 'P' || png[2] != 'N' || png[3] != 'G' {
		t.Fatalf("output is not valid PNG")
	}
}

func TestParseOtpauthURIWithHOTP(t *testing.T) {
	account, secret, interval, digits, algorithm, otpType, counter, err := ParseOtpauthURI("otpauth://hotp/Service:user?secret=JBSWY3DPEHPK3PXP&counter=5&digits=6")
	if err != nil {
		t.Fatalf("parse HOTP URI: %v", err)
	}
	if otpType != "hotp" {
		t.Fatalf("expected hotp type, got %q", otpType)
	}
	if counter != 5 {
		t.Fatalf("expected counter 5, got %d", counter)
	}
	if account == "" || secret == "" || interval <= 0 || digits <= 0 {
		t.Fatalf("unexpected parsed values: account=%q secret=%q interval=%d digits=%d algorithm=%q", account, secret, interval, digits, algorithm)
	}
}
