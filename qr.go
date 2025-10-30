package main

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

const otpauthScheme = "otpauth://"

func readQRFromFile(fp string) (string, error) {
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

func parseOtpauthURI(uri string) (account string, secret string, interval int, digits int, err error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", "", 0, 0, err
	}
	if u.Scheme != "otpauth" {
		return "", "", 0, 0, errors.New("uri is not otpauth scheme")
	}
	// only support totp for now
	if strings.ToLower(u.Host) != "totp" {
		return "", "", 0, 0, errors.New("only totp type is supported")
	}

	// label is in the path (may start with /)
	label := strings.TrimPrefix(u.Path, "/")

	q := u.Query()
	secret = q.Get("secret")
	if secret == "" {
		return "", "", 0, 0, errors.New("secret missing in otpauth uri")
	}

	interval = defaultInterval
	digits = defaultDigits

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

	return account, secret, interval, digits, nil
}

// parseQRPayload accepts the raw payload decoded from a QR code and returns
// one or more Account entries. It supports both standard otpauth:// URIs and
// Google Authenticator migration URLs (otpauth-migration://offline?data=...).
func parseQRPayload(payload string) ([]Account, error) {
	trimmed := strings.TrimSpace(payload)

	// Detect migration URI
	if strings.Contains(trimmed, "otpauth-migration://") {
		// Ensure we extract the full migration URL if it's embedded
		if idx := strings.Index(trimmed, "otpauth-migration://"); idx != -1 {
			trimmed = trimmed[idx:]
		}

		u, err := url.Parse(trimmed)
		if err != nil {
			return nil, err
		}

		q := u.Query()
		data := q.Get("data")
		if data == "" {
			return nil, errors.New("migration payload missing data parameter")
		}

		accts, err := parseMigrationData(data)
		if err != nil {
			return nil, err
		}

		return accts, nil
	}

	// Otherwise try to find an otpauth:// substring or treat the whole payload as an otpauth URI
	if !strings.HasPrefix(trimmed, "otpauth://") {
		if idx := strings.Index(trimmed, "otpauth://"); idx != -1 {
			trimmed = trimmed[idx:]
		}
	}

	// If still not starting with otpauth, give up
	if !strings.HasPrefix(trimmed, "otpauth://") {
		return nil, errors.New("no otpauth URI found in payload")
	}

	account, secret, interval, digits, err := parseOtpauthURI(trimmed)
	if err != nil {
		return nil, err
	}

	return []Account{{
		Name:     account,
		Secret:   secret,
		Interval: int64(interval),
		Digits:   digits,
	}}, nil
}
