package trustpin

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"
)

type AccountSnapshot struct {
	Account         Account `json:"-"`
	Name            string  `json:"name"`
	DisplayName     string  `json:"displayName"`
	Issuer          string  `json:"issuer"`
	Label           string  `json:"label"`
	OTP             string  `json:"otp"`
	FormattedOTP    string  `json:"formattedOTP"`
	TimeRemaining   int64   `json:"timeRemaining"`
	Interval        int64   `json:"interval"`
	Digits          int     `json:"digits"`
	StatusLabel     string  `json:"statusLabel"`
	Tone            string  `json:"tone"`
	ProgressPercent int     `json:"progressPercent"`
	PolicyLabel     string  `json:"policyLabel"`
	SecretPreview   string  `json:"secretPreview"`
	ErrorText       string  `json:"errorText,omitempty"`
}

func GenerateTOTP(secret string, interval int64, digits int) (otp string, timeRemaining int64, err error) {
	secret = normalizeSecret(secret)

	secretBytes, err := decodeSecret(secret)
	if err != nil {
		return "", 0, err
	}
	if interval <= 0 {
		interval = DefaultInterval
	}
	if digits <= 0 {
		digits = DefaultDigits
	}

	currentTime := getCurrentTime() / interval

	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], uint64(currentTime))

	hash := hmac.New(sha1.New, secretBytes)
	hash.Write(counterBytes[:])
	hashResult := hash.Sum(nil)

	offset := hashResult[len(hashResult)-1] & 0x0F
	truncatedHash := binary.BigEndian.Uint32(hashResult[offset:offset+4]) & 0x7FFFFFFF

	otpCode := truncatedHash % uint32(math.Pow10(digits))
	timeRemaining = interval - (getCurrentTime() % interval)

	return fmt.Sprintf("%0*d", digits, otpCode), timeRemaining, nil
}

func BuildAccountSnapshot(account Account) AccountSnapshot {
	account = sanitizeAccount(account)

	issuer, label, hasIssuer := SplitAccountName(account.Name)
	if !hasIssuer {
		issuer = "Standalone"
		label = account.Name
	}

	otp, remaining, err := GenerateTOTP(account.Secret, account.Interval, account.Digits)
	progress := computeProgressPercent(remaining, account.Interval)
	tone, status := classifyAccountState(account, remaining, err)

	errorText := ""
	formattedOTP := FormatOTP(otp)
	if err != nil {
		errorText = "Secret is not valid base32/base64. Re-import or edit this entry."
		formattedOTP = "-- --"
		progress = 0
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
		StatusLabel:     status,
		Tone:            tone,
		ProgressPercent: progress,
		PolicyLabel:     fmt.Sprintf("%d digits / %ds", account.Digits, account.Interval),
		SecretPreview:   PreviewSecret(account.Secret),
		ErrorText:       errorText,
	}
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
