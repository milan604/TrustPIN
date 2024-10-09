package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"strings"
	"time"
)

func generateTOTP(secret string, interval int64, digits int) (otp string, timeInMs int64) {
	secret = strings.Replace(secret, " ", "", -1)
	secret = strings.ToUpper(secret)

	secretBytes, err := decodeSecret(secret)
	if err != nil {
		log.Fatalf("Error decoding secret: %v", err)
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

	timeRemaining := interval - (getCurrentTime() % interval)

	return fmt.Sprintf("%0*d", digits, otpCode), timeRemaining
}

func getCurrentTime() int64 {
	return time.Now().Unix()
}

func decodeSecret(secret string) ([]byte, error) {
	if isBase32(secret) {
		return base32.StdEncoding.DecodeString(secret)
	} else if isBase64(secret) {
		return base64.StdEncoding.DecodeString(secret)
	}

	return nil, nil
}

func isBase32(secret string) bool {
	_, err := base32.StdEncoding.DecodeString(secret)
	return err == nil
}

func isBase64(secret string) bool {
	_, err := base64.StdEncoding.DecodeString(secret)
	return err == nil
}
