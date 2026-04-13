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
