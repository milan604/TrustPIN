package trustpin

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	DefaultLegacyAccountFile = "accounts.json"
	DefaultStoreFileName     = "accounts.enc"
	DefaultKeyFileName       = "accounts.key"
	DefaultInterval          = 30
	DefaultDigits            = 6

	storeMagic = "TRUSTPINv1"
)

type Service struct {
	StorePath  string
	KeyPath    string
	LegacyPath string
}

type Account struct {
	Name      string   `json:"Name"`
	Secret    string   `json:"Secret"`
	Interval  int64    `json:"Interval"`
	Digits    int      `json:"Digits"`
	Algorithm string   `json:"Algorithm,omitempty"`
	Type      string   `json:"Type,omitempty"`
	Counter   int64    `json:"Counter,omitempty"`
	Tags      []string `json:"Tags,omitempty"`
	Favorite  bool     `json:"Favorite,omitempty"`
	Notes     string   `json:"Notes,omitempty"`
	SortOrder int      `json:"SortOrder,omitempty"`
	Archived  bool     `json:"Archived,omitempty"`
}

const (
	AlgorithmSHA1   = "SHA1"
	AlgorithmSHA256 = "SHA256"
	AlgorithmSHA512 = "SHA512"

	TypeTOTP  = "totp"
	TypeHOTP  = "hotp"
	TypeSteam = "steam"
)

type AccountChange struct {
	Name   string `json:"name"`
	Action string `json:"action"`
}

type UpsertSummary struct {
	Added    int             `json:"added"`
	Replaced int             `json:"replaced"`
	Changes  []AccountChange `json:"changes"`
}

type ImportResult struct {
	Summary UpsertSummary `json:"summary"`
	Skipped []string      `json:"skipped"`
}

func NewService(storePath string) Service {
	legacyPath := currentLegacyPath()

	storePath = strings.TrimSpace(storePath)
	if storePath != "" {
		clean := filepath.Clean(storePath)
		return Service{
			StorePath:  clean,
			KeyPath:    derivedKeyPath(clean),
			LegacyPath: legacyPath,
		}
	}

	appDir := defaultAppDir()

	return Service{
		StorePath:  filepath.Join(appDir, DefaultStoreFileName),
		KeyPath:    filepath.Join(appDir, DefaultKeyFileName),
		LegacyPath: legacyPath,
	}
}

func ValidateAccountInput(account, secret string) error {
	if strings.TrimSpace(account) == "" {
		return fmt.Errorf("account name cannot be empty")
	}

	if strings.TrimSpace(secret) == "" {
		return fmt.Errorf("secret cannot be empty")
	}

	return nil
}

func ValidateDigits(digits int) error {
	if digits < 1 || digits > 10 {
		return fmt.Errorf("digits must be between 1 and 10")
	}
	return nil
}

func (s Service) LoadAccounts() ([]Account, error) {
	if err := s.ensureInitialized(); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(s.storePath())
	if err != nil {
		return nil, err
	}

	return s.decodeStoredAccounts(data)
}

func (s Service) SaveAccounts(accounts []Account) error {
	if err := s.ensureParentDirs(); err != nil {
		return err
	}

	key, err := s.loadOrCreateKey()
	if err != nil {
		return err
	}

	payload, err := json.MarshalIndent(accounts, "", "  ")
	if err != nil {
		return err
	}

	encrypted, err := encryptPayload(payload, key)
	if err != nil {
		return err
	}

	file, err := os.OpenFile(s.storePath(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(encrypted)
	return err
}

func (s Service) UpsertAccounts(incoming []Account) (UpsertSummary, error) {
	accounts, err := s.LoadAccounts()
	if err != nil {
		return UpsertSummary{}, fmt.Errorf("load accounts: %w", err)
	}

	accounts, summary := upsertAccounts(accounts, incoming)
	sort.Slice(accounts, func(i, j int) bool {
		return normalizeAccountName(accounts[i].Name) < normalizeAccountName(accounts[j].Name)
	})

	if err := s.SaveAccounts(accounts); err != nil {
		return UpsertSummary{}, fmt.Errorf("save accounts: %w", err)
	}

	return summary, nil
}

func (s Service) DeleteAccount(account string) (int, error) {
	accounts, err := s.LoadAccounts()
	if err != nil {
		return 0, fmt.Errorf("load accounts: %w", err)
	}

	target := strings.ToLower(strings.TrimSpace(account))
	if target == "" {
		return 0, fmt.Errorf("account name cannot be empty")
	}

	if target == "all" {
		removed := len(accounts)
		if err := s.SaveAccounts([]Account{}); err != nil {
			return 0, fmt.Errorf("clear accounts: %w", err)
		}
		return removed, nil
	}

	filtered := make([]Account, 0, len(accounts))
	removed := 0
	for _, current := range accounts {
		if normalizeAccountName(current.Name) == target {
			removed++
			continue
		}
		filtered = append(filtered, current)
	}

	if removed == 0 {
		return 0, fmt.Errorf("no account found matching %q", account)
	}

	if err := s.SaveAccounts(filtered); err != nil {
		return 0, fmt.Errorf("save accounts: %w", err)
	}

	return removed, nil
}

func (s Service) UpdateAccount(currentName string, updated Account) error {
	currentKey := normalizeAccountName(currentName)
	if currentKey == "" {
		return fmt.Errorf("current account name cannot be empty")
	}

	updated = sanitizeAccount(updated)

	accounts, err := s.LoadAccounts()
	if err != nil {
		return fmt.Errorf("load accounts: %w", err)
	}

	matchIdx := -1
	for i, account := range accounts {
		if normalizeAccountName(account.Name) == currentKey {
			matchIdx = i
			break
		}
	}
	if matchIdx == -1 {
		return fmt.Errorf("no account found matching %q", currentName)
	}
	if updated.Secret == "" {
		updated.Secret = accounts[matchIdx].Secret
	}
	if err := ValidateAccountInput(updated.Name, updated.Secret); err != nil {
		return err
	}
	if err := ValidateDigits(updated.Digits); err != nil {
		return err
	}

	newNameKey := normalizeAccountName(updated.Name)
	newSecretKey := normalizeSecret(updated.Secret)
	originalSecretKey := normalizeSecret(accounts[matchIdx].Secret)
	for i, account := range accounts {
		if i == matchIdx {
			continue
		}

		if normalizeAccountName(account.Name) == newNameKey {
			return fmt.Errorf("another account already uses %q", updated.Name)
		}
		if newSecretKey != "" && newSecretKey != originalSecretKey && normalizeSecret(account.Secret) == newSecretKey {
			return fmt.Errorf("another account already uses the same secret")
		}
	}

	accounts[matchIdx] = updated
	sort.Slice(accounts, func(i, j int) bool {
		return normalizeAccountName(accounts[i].Name) < normalizeAccountName(accounts[j].Name)
	})

	if err := s.SaveAccounts(accounts); err != nil {
		return fmt.Errorf("save accounts: %w", err)
	}

	return nil
}

func (s Service) SetAccountArchived(name string, archived bool) error {
	accounts, err := s.LoadAccounts()
	if err != nil {
		return fmt.Errorf("load accounts: %w", err)
	}

	nameKey := normalizeAccountName(name)
	found := false
	for i, a := range accounts {
		if normalizeAccountName(a.Name) == nameKey {
			accounts[i].Archived = archived
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("no account found matching %q", name)
	}

	return s.SaveAccounts(accounts)
}

func (s Service) ImportAccountsFromQR(qrFile string) (ImportResult, error) {
	payload, err := ReadQRFromFile(qrFile)
	if err != nil {
		return ImportResult{}, fmt.Errorf("read QR file: %w", err)
	}

	accounts, err := ParseQRPayload(payload)
	if err != nil {
		return ImportResult{}, fmt.Errorf("parse QR payload: %w", err)
	}

	if len(accounts) == 0 {
		return ImportResult{}, fmt.Errorf("no importable accounts found in QR payload")
	}

	valid := make([]Account, 0, len(accounts))
	skipped := make([]string, 0)
	for _, account := range accounts {
		if err := ValidateAccountInput(account.Name, account.Secret); err != nil {
			skipped = append(skipped, fmt.Sprintf("%s (%v)", account.Name, err))
			continue
		}
		if err := ValidateDigits(account.Digits); err != nil {
			skipped = append(skipped, fmt.Sprintf("%s (%v)", account.Name, err))
			continue
		}
		if account.Interval <= 0 {
			account.Interval = DefaultInterval
		}
		valid = append(valid, account)
	}

	if len(valid) == 0 {
		return ImportResult{}, fmt.Errorf("all accounts in the QR payload were skipped")
	}

	summary, err := s.UpsertAccounts(valid)
	if err != nil {
		return ImportResult{}, err
	}

	return ImportResult{
		Summary: summary,
		Skipped: skipped,
	}, nil
}

func (s Service) MigrateLegacyFrom(path string, removeSource bool) (UpsertSummary, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		path = s.legacyPath()
	}
	if path == "" {
		return UpsertSummary{}, fmt.Errorf("legacy account path is empty")
	}

	legacyAccounts, err := loadPlaintextAccounts(path)
	if err != nil {
		return UpsertSummary{}, fmt.Errorf("read legacy store: %w", err)
	}

	existing, err := s.loadExistingStoreAccounts()
	if err != nil {
		return UpsertSummary{}, err
	}

	merged, summary := upsertAccounts(existing, legacyAccounts)
	sort.Slice(merged, func(i, j int) bool {
		return normalizeAccountName(merged[i].Name) < normalizeAccountName(merged[j].Name)
	})

	if err := s.SaveAccounts(merged); err != nil {
		return UpsertSummary{}, err
	}

	if removeSource {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return UpsertSummary{}, fmt.Errorf("remove migrated legacy store: %w", err)
		}
	}

	return summary, nil
}

func (s Service) ensureInitialized() error {
	if err := s.ensureParentDirs(); err != nil {
		return err
	}

	storePath := s.storePath()
	if _, err := os.Stat(storePath); err == nil {
		legacy := s.legacyPath()
		if legacy == "" || legacy == storePath {
			return nil
		}
		if _, err := os.Stat(legacy); os.IsNotExist(err) {
			return nil
		} else if err != nil {
			return err
		}

		existing, err := s.loadExistingStoreAccounts()
		if err != nil {
			return err
		}
		if len(existing) > 0 {
			return nil
		}

		_, err = s.MigrateLegacyFrom(legacy, true)
		return err
	} else if !os.IsNotExist(err) {
		return err
	}

	if legacy := s.legacyPath(); legacy != "" && legacy != storePath {
		if _, err := os.Stat(legacy); err == nil {
			_, err := s.MigrateLegacyFrom(legacy, true)
			return err
		}
	}

	return s.SaveAccounts([]Account{})
}

func (s Service) ensureParentDirs() error {
	for _, path := range []string{s.storePath(), s.keyPath()} {
		dir := filepath.Dir(path)
		if dir == "." || dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func (s Service) decodeStoredAccounts(data []byte) ([]Account, error) {
	if bytes.HasPrefix(data, []byte(storeMagic)) {
		key, err := s.loadKey()
		if err != nil {
			return nil, err
		}
		plaintext, err := decryptPayload(data, key)
		if err != nil {
			return nil, err
		}
		var accounts []Account
		if err := json.Unmarshal(plaintext, &accounts); err != nil {
			return nil, err
		}
		return accounts, nil
	}

	var accounts []Account
	if err := json.Unmarshal(data, &accounts); err != nil {
		return nil, fmt.Errorf("decode encrypted store: %w", err)
	}

	if err := s.SaveAccounts(accounts); err != nil {
		return nil, err
	}
	return accounts, nil
}

func (s Service) loadExistingStoreAccounts() ([]Account, error) {
	data, err := os.ReadFile(s.storePath())
	if os.IsNotExist(err) {
		return []Account{}, nil
	}
	if err != nil {
		return nil, err
	}
	return s.decodeStoredAccounts(data)
}

func (s Service) loadKey() ([]byte, error) {
	data, err := os.ReadFile(s.keyPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("encryption key not found at %s", s.keyPath())
		}
		return nil, err
	}
	if len(data) != 32 {
		return nil, fmt.Errorf("invalid key length in %s", s.keyPath())
	}
	return data, nil
}

func (s Service) loadOrCreateKey() ([]byte, error) {
	keyPath := s.keyPath()
	if data, err := os.ReadFile(keyPath); err == nil {
		if len(data) != 32 {
			return nil, fmt.Errorf("invalid key length in %s", keyPath)
		}
		return data, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	file, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if _, err := file.Write(key); err != nil {
		return nil, err
	}
	return key, nil
}

func encryptPayload(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	header := []byte(storeMagic)
	ciphertext := gcm.Seal(nil, nonce, plaintext, header)
	out := make([]byte, 0, len(header)+len(nonce)+len(ciphertext))
	out = append(out, header...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

func decryptPayload(data, key []byte) ([]byte, error) {
	header := []byte(storeMagic)
	if !bytes.HasPrefix(data, header) {
		return nil, fmt.Errorf("unknown encrypted store format")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(data) < len(header)+gcm.NonceSize() {
		return nil, fmt.Errorf("encrypted store is truncated")
	}

	nonceStart := len(header)
	nonceEnd := nonceStart + gcm.NonceSize()
	nonce := data[nonceStart:nonceEnd]
	ciphertext := data[nonceEnd:]
	return gcm.Open(nil, nonce, ciphertext, header)
}

func loadPlaintextAccounts(path string) ([]Account, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var accounts []Account
	if err := json.Unmarshal(data, &accounts); err != nil {
		return nil, err
	}
	return accounts, nil
}

func defaultAppDir() string {
	if base, err := os.UserConfigDir(); err == nil && strings.TrimSpace(base) != "" {
		return filepath.Join(base, "TrustPIN")
	}
	return filepath.Join(".", ".trustpin")
}

func currentLegacyPath() string {
	legacyPath := filepath.Join(".", DefaultLegacyAccountFile)
	if cwd, err := os.Getwd(); err == nil {
		legacyPath = filepath.Join(cwd, DefaultLegacyAccountFile)
	}
	return legacyPath
}

func derivedKeyPath(storePath string) string {
	ext := filepath.Ext(storePath)
	if ext == "" {
		return storePath + "." + DefaultKeyFileName
	}
	return strings.TrimSuffix(storePath, ext) + "." + DefaultKeyFileName
}

func (s Service) storePath() string {
	if strings.TrimSpace(s.StorePath) == "" {
		return filepath.Join(defaultAppDir(), DefaultStoreFileName)
	}
	return filepath.Clean(s.StorePath)
}

func (s Service) keyPath() string {
	if strings.TrimSpace(s.KeyPath) == "" {
		return derivedKeyPath(s.storePath())
	}
	return filepath.Clean(s.KeyPath)
}

func (s Service) legacyPath() string {
	return strings.TrimSpace(s.LegacyPath)
}

func upsertAccounts(existing []Account, incoming []Account) ([]Account, UpsertSummary) {
	summary := UpsertSummary{
		Changes: make([]AccountChange, 0, len(incoming)),
	}

	indexByName := buildNameIndex(existing)
	indexBySecret := buildSecretIndex(existing)

	for _, candidate := range incoming {
		candidate = sanitizeAccount(candidate)
		nameKey := normalizeAccountName(candidate.Name)
		secretKey := normalizeSecret(candidate.Secret)

		matchIdx := -1
		if idx, ok := indexByName[nameKey]; ok {
			matchIdx = idx
		}
		if matchIdx == -1 {
			if idx, ok := indexBySecret[secretKey]; ok {
				matchIdx = idx
			}
		}

		if matchIdx >= 0 {
			existing[matchIdx] = candidate
			summary.Replaced++
			summary.Changes = append(summary.Changes, AccountChange{Name: candidate.Name, Action: "replaced"})
		} else {
			existing = append(existing, candidate)
			summary.Added++
			summary.Changes = append(summary.Changes, AccountChange{Name: candidate.Name, Action: "added"})
		}

		indexByName = buildNameIndex(existing)
		indexBySecret = buildSecretIndex(existing)
	}

	return existing, summary
}

func sanitizeAccount(account Account) Account {
	account.Name = strings.TrimSpace(account.Name)
	account.Secret = strings.TrimSpace(account.Secret)
	if account.Interval <= 0 {
		account.Interval = DefaultInterval
	}
	if account.Digits <= 0 {
		account.Digits = DefaultDigits
	}
	account.Algorithm = NormalizeAlgorithm(account.Algorithm)
	account.Type = NormalizeType(account.Type)
	if account.Type == TypeSteam {
		account.Digits = 5
		account.Interval = 30
		account.Algorithm = AlgorithmSHA1
	}
	account.Notes = strings.TrimSpace(account.Notes)
	return account
}

func NormalizeAlgorithm(alg string) string {
	switch strings.ToUpper(strings.TrimSpace(alg)) {
	case AlgorithmSHA256, "SHA-256":
		return AlgorithmSHA256
	case AlgorithmSHA512, "SHA-512":
		return AlgorithmSHA512
	default:
		return AlgorithmSHA1
	}
}

func NormalizeType(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case TypeHOTP:
		return TypeHOTP
	case TypeSteam:
		return TypeSteam
	default:
		return TypeTOTP
	}
}

func buildNameIndex(accounts []Account) map[string]int {
	index := make(map[string]int, len(accounts))
	for i, account := range accounts {
		index[normalizeAccountName(account.Name)] = i
	}
	return index
}

func buildSecretIndex(accounts []Account) map[string]int {
	index := make(map[string]int, len(accounts))
	for i, account := range accounts {
		index[normalizeSecret(account.Secret)] = i
	}
	return index
}

func normalizeAccountName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func normalizeSecret(secret string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
}
