package trustpin

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"strings"
	"time"
)

const steamChars = "23456789BCDFGHJKMNPQRTVWXY"

type AccountSnapshot struct {
	Account         Account  `json:"-"`
	Name            string   `json:"name"`
	DisplayName     string   `json:"displayName"`
	Issuer          string   `json:"issuer"`
	Label           string   `json:"label"`
	OTP             string   `json:"otp"`
	FormattedOTP    string   `json:"formattedOTP"`
	TimeRemaining   int64    `json:"timeRemaining"`
	Interval        int64    `json:"interval"`
	Digits          int      `json:"digits"`
	Algorithm       string   `json:"algorithm"`
	Type            string   `json:"type"`
	Counter         int64    `json:"counter,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	Favorite        bool     `json:"favorite"`
	Notes           string   `json:"notes,omitempty"`
	SortOrder       int      `json:"sortOrder"`
	Archived        bool     `json:"archived"`
	StatusLabel     string   `json:"statusLabel"`
	Tone            string   `json:"tone"`
	ProgressPercent int      `json:"progressPercent"`
	PolicyLabel     string   `json:"policyLabel"`
	SecretPreview   string   `json:"secretPreview"`
	ErrorText       string   `json:"errorText,omitempty"`
}

func hashFunc(algorithm string) func() hash.Hash {
	switch algorithm {
	case AlgorithmSHA256:
		return sha256.New
	case AlgorithmSHA512:
		return sha512.New
	default:
		return sha1.New
	}
}

func generateOTPCode(secret string, counter uint64, digits int, algorithm string) (string, error) {
	secret = normalizeSecret(secret)

	secretBytes, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	if digits <= 0 {
		digits = DefaultDigits
	}

	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)

	h := hmac.New(hashFunc(algorithm), secretBytes)
	h.Write(counterBytes[:])
	hashResult := h.Sum(nil)

	offset := hashResult[len(hashResult)-1] & 0x0F
	truncatedHash := binary.BigEndian.Uint32(hashResult[offset:offset+4]) & 0x7FFFFFFF

	otpCode := truncatedHash % uint32(math.Pow10(digits))
	return fmt.Sprintf("%0*d", digits, otpCode), nil
}

func GenerateTOTP(secret string, interval int64, digits int) (otp string, timeRemaining int64, err error) {
	return GenerateTOTPWithAlgorithm(secret, interval, digits, AlgorithmSHA1)
}

func GenerateTOTPWithAlgorithm(secret string, interval int64, digits int, algorithm string) (otp string, timeRemaining int64, err error) {
	if interval <= 0 {
		interval = DefaultInterval
	}

	counter := uint64(getCurrentTime() / interval)
	otp, err = generateOTPCode(secret, counter, digits, algorithm)
	if err != nil {
		return "", 0, err
	}

	timeRemaining = interval - (getCurrentTime() % interval)
	return otp, timeRemaining, nil
}

func GenerateHOTP(secret string, counter int64, digits int, algorithm string) (string, error) {
	if counter < 0 {
		counter = 0
	}
	return generateOTPCode(secret, uint64(counter), digits, algorithm)
}

func GenerateSteamCode(secret string, interval int64) (string, int64, error) {
	if interval <= 0 {
		interval = DefaultInterval
	}

	secret = normalizeSecret(secret)
	secretBytes, err := decodeSecret(secret)
	if err != nil {
		return "", 0, err
	}

	counter := uint64(getCurrentTime() / interval)
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)

	h := hmac.New(sha1.New, secretBytes)
	h.Write(counterBytes[:])
	hashResult := h.Sum(nil)

	offset := hashResult[len(hashResult)-1] & 0x0F
	fullCode := binary.BigEndian.Uint32(hashResult[offset:offset+4]) & 0x7FFFFFFF

	code := make([]byte, 5)
	for i := range code {
		code[i] = steamChars[fullCode%uint32(len(steamChars))]
		fullCode /= uint32(len(steamChars))
	}

	timeRemaining := interval - (getCurrentTime() % interval)
	return string(code), timeRemaining, nil
}

func BuildAccountSnapshot(account Account) AccountSnapshot {
	account = sanitizeAccount(account)

	issuer, label, hasIssuer := SplitAccountName(account.Name)
	if !hasIssuer {
		issuer = "Standalone"
		label = account.Name
	}

	var otp string
	var remaining int64
	var err error

	switch account.Type {
	case TypeSteam:
		otp, remaining, err = GenerateSteamCode(account.Secret, account.Interval)
	case TypeHOTP:
		otp, err = GenerateHOTP(account.Secret, account.Counter, account.Digits, account.Algorithm)
		remaining = -1 // HOTP doesn't have a countdown
	default:
		otp, remaining, err = GenerateTOTPWithAlgorithm(account.Secret, account.Interval, account.Digits, account.Algorithm)
	}

	progress := computeProgressPercent(remaining, account.Interval)
	tone, status := classifyAccountState(account, remaining, err)

	errorText := ""
	formattedOTP := FormatOTP(otp)
	if account.Type == TypeSteam {
		formattedOTP = otp // Steam codes are already formatted as letters
	}
	if err != nil {
		errorText = "Secret is not valid base32/base64. Re-import or edit this entry."
		formattedOTP = "-- --"
		progress = 0
	}

	policyLabel := fmt.Sprintf("%d digits / %ds", account.Digits, account.Interval)
	if account.Type == TypeHOTP {
		policyLabel = fmt.Sprintf("%d digits / counter %d", account.Digits, account.Counter)
	} else if account.Type == TypeSteam {
		policyLabel = "Steam Guard"
	}
	if account.Algorithm != AlgorithmSHA1 {
		policyLabel += " / " + account.Algorithm
	}

	tags := account.Tags
	if tags == nil {
		tags = []string{}
	}

	return AccountSnapshot{
		Account:         account,
		Name:            account.Name,
		DisplayName:     label,
		Issuer:          issuer,
		Label:           label,
		OTP:             otp,
		FormattedOTP:    formattedOTP,
		TimeRemaining:   remaining,
		Interval:        account.Interval,
		Digits:          account.Digits,
		Algorithm:       account.Algorithm,
		Type:            account.Type,
		Counter:         account.Counter,
		Tags:            tags,
		Favorite:        account.Favorite,
		Notes:           account.Notes,
		SortOrder:       account.SortOrder,
		Archived:        account.Archived,
		StatusLabel:     status,
		Tone:            tone,
		ProgressPercent: progress,
		PolicyLabel:     policyLabel,
		SecretPreview:   PreviewSecret(account.Secret),
		ErrorText:       errorText,
	}
}

func BuildOTPAuthURI(account Account) string {
	account = sanitizeAccount(account)
	issuer, label, hasIssuer := SplitAccountName(account.Name)
	if !hasIssuer {
		label = account.Name
	}

	otpType := "totp"
	if account.Type == TypeHOTP {
		otpType = "hotp"
	}

	path := label
	if hasIssuer {
		path = issuer + ":" + label
	}

	uri := fmt.Sprintf("otpauth://%s/%s?secret=%s", otpType, path, normalizeSecret(account.Secret))
	if hasIssuer {
		uri += "&issuer=" + issuer
	}
	if account.Algorithm != AlgorithmSHA1 {
		uri += "&algorithm=" + account.Algorithm
	}
	uri += fmt.Sprintf("&digits=%d", account.Digits)
	if account.Type == TypeHOTP {
		uri += fmt.Sprintf("&counter=%d", account.Counter)
	} else {
		uri += fmt.Sprintf("&period=%d", account.Interval)
	}
	return uri
}

func SplitAccountName(name string) (issuer, label string, hasIssuer bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", "", false
	}

	if !strings.Contains(name, ":") {
		return "", name, false
	}

	parts := strings.SplitN(name, ":", 2)
	issuer = strings.TrimSpace(parts[0])
	label = strings.TrimSpace(parts[1])
	if issuer == "" || label == "" {
		return "", name, false
	}

	return issuer, label, true
}

func PreviewSecret(secret string) string {
	secret = normalizeSecret(secret)
	if len(secret) <= 8 {
		return secret
	}
	return secret[:4] + "..." + secret[len(secret)-4:]
}

func FormatOTP(otp string) string {
	switch len(otp) {
	case 6:
		return otp[:3] + " " + otp[3:]
	case 8:
		return otp[:4] + " " + otp[4:]
	default:
		if otp == "" {
			return "-- --"
		}

		chunks := make([]string, 0, len(otp)/3+1)
		for len(otp) > 3 {
			chunks = append(chunks, otp[:3])
			otp = otp[3:]
		}
		if otp != "" {
			chunks = append(chunks, otp)
		}
		return strings.Join(chunks, " ")
	}
}

func getCurrentTime() int64 {
	return time.Now().Unix()
}

func decodeSecret(secret string) ([]byte, error) {
	if isBase32(secret) {
		return base32.StdEncoding.DecodeString(secret)
	}
	if isBase64(secret) {
		return base64.StdEncoding.DecodeString(secret)
	}

	return nil, fmt.Errorf("secret is not valid base32 or base64")
}

func isBase32(secret string) bool {
	_, err := base32.StdEncoding.DecodeString(secret)
	return err == nil
}

func isBase64(secret string) bool {
	_, err := base64.StdEncoding.DecodeString(secret)
	return err == nil
}

func classifyAccountState(account Account, remaining int64, err error) (string, string) {
	if err != nil {
		return "danger", "Needs attention"
	}
	if account.Type == TypeHOTP {
		return "accent", "Counter-based"
	}
	if account.Type == TypeSteam {
		if remaining <= 5 {
			return "warning", "Refreshing"
		}
		return "success", "Steam Guard"
	}
	if account.Interval < 20 || account.Digits < 6 {
		return "warning", "High churn"
	}
	if account.Interval != DefaultInterval || account.Digits != DefaultDigits {
		return "accent", "Custom policy"
	}
	if remaining <= 5 {
		return "warning", "Refreshing"
	}
	return "success", "Ready"
}

func computeProgressPercent(remaining, interval int64) int {
	if interval <= 0 {
		interval = DefaultInterval
	}
	if remaining < 0 {
		remaining = 0
	}
	if remaining > interval {
		remaining = interval
	}

	elapsed := float64(interval-remaining) / float64(interval)
	return int(elapsed * 100)
}
