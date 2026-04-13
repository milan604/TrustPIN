package trustpin

import (
	qrcode "github.com/skip2/go-qrcode"
)

// GenerateQRCodePNG creates a QR code PNG for the account's otpauth URI.
func GenerateQRCodePNG(account Account, size int) ([]byte, error) {
	uri := BuildOTPAuthURI(account)
	if size <= 0 {
		size = 256
	}
	return qrcode.Encode(uri, qrcode.Medium, size)
}
