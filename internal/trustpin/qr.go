package trustpin

import (
	"errors"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/liyue201/goqr"
)

func ReadQRFromFile(fp string) (string, error) {
	f, err := os.Open(fp)
	if err != nil {
		return "", err
	}
	defer f.Close()

	img, _, err := image.Decode(f)
	if err != nil {
		return "", err
	}

	symbols, err := goqr.Recognize(img)
	if err != nil {
		return "", err
	}

	if len(symbols) == 0 {
		return "", errors.New("no QR code found in image")
	}

	return string(symbols[0].Payload), nil
}

func ParseOtpauthURI(uri string) (account string, secret string, interval int, digits int, algorithm string, otpType string, counter int64, err error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", "", 0, 0, "", "", 0, err
	}
	if u.Scheme != "otpauth" {
		return "", "", 0, 0, "", "", 0, errors.New("uri is not otpauth scheme")
	}

	otpType = strings.ToLower(u.Host)
	if otpType != "totp" && otpType != "hotp" {
		return "", "", 0, 0, "", "", 0, errors.New("only totp and hotp types are supported")
	}

	label := strings.TrimPrefix(u.Path, "/")
	q := u.Query()

	secret = q.Get("secret")
	if secret == "" {
		return "", "", 0, 0, "", "", 0, errors.New("secret missing in otpauth uri")
	}

	interval = DefaultInterval
	digits = DefaultDigits
	algorithm = AlgorithmSHA1

	if p := q.Get("period"); p != "" {
		if v, e := strconv.Atoi(p); e == nil && v > 0 {
			interval = v
		}
	}

	if d := q.Get("digits"); d != "" {
		if v, e := strconv.Atoi(d); e == nil && v > 0 {
			digits = v
		}
	}

	if a := q.Get("algorithm"); a != "" {
		algorithm = NormalizeAlgorithm(a)
	}

	if c := q.Get("counter"); c != "" {
		if v, e := strconv.ParseInt(c, 10, 64); e == nil {
			counter = v
		}
	}

	account = label
	if account == "" {
		if issuer := q.Get("issuer"); issuer != "" {
			account = issuer
		}
	}
	if strings.Contains(label, ":") {
		account = label
	}
	account = path.Base(account)

	return account, secret, interval, digits, algorithm, otpType, counter, nil
}

func ParseQRPayload(payload string) ([]Account, error) {
	trimmed := strings.TrimSpace(payload)

	if strings.Contains(trimmed, "otpauth-migration://") {
		if idx := strings.Index(trimmed, "otpauth-migration://"); idx != -1 {
			trimmed = trimmed[idx:]
		}

		u, err := url.Parse(trimmed)
		if err != nil {
			return nil, err
		}

		data := u.Query().Get("data")
		if data == "" {
			return nil, errors.New("migration payload missing data parameter")
		}

		return parseMigrationData(data)
	}

	if !strings.HasPrefix(trimmed, "otpauth://") {
		if idx := strings.Index(trimmed, "otpauth://"); idx != -1 {
			trimmed = trimmed[idx:]
		}
	}
	if !strings.HasPrefix(trimmed, "otpauth://") {
		return nil, errors.New("no otpauth URI found in payload")
	}

	account, secret, interval, digits, algorithm, otpType, counter, err := ParseOtpauthURI(trimmed)
	if err != nil {
		return nil, err
	}

	return []Account{{
		Name:      account,
		Secret:    secret,
		Interval:  int64(interval),
		Digits:    digits,
		Algorithm: algorithm,
		Type:      otpType,
		Counter:   counter,
	}}, nil
}
