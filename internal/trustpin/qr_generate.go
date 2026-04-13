package trustpin

import (
	"bytes"
	"image"
	"image/color"
	"image/draw"
	"image/png"

	qrcode "github.com/skip2/go-qrcode"
)

// brandedQRPadding is the vertical space reserved for header and footer text.
const brandedQRPadding = 36

// GenerateQRCodePNG creates a branded QR code PNG with a "TrustPIN" header
// and "M-LAN" footer text rendered around the QR matrix.
func GenerateQRCodePNG(account Account, size int) ([]byte, error) {
	uri := BuildOTPAuthURI(account)
	if size <= 0 {
		size = 256
	}

	qr, err := qrcode.New(uri, qrcode.Medium)
	if err != nil {
		return nil, err
	}
	qrImg := qr.Image(size)

	// Canvas: QR + header + footer bands
	totalH := size + brandedQRPadding*2
	canvas := image.NewRGBA(image.Rect(0, 0, size, totalH))

	// Fill white background
	white := color.RGBA{255, 255, 255, 255}
	draw.Draw(canvas, canvas.Bounds(), &image.Uniform{white}, image.Point{}, draw.Src)

	// Draw QR code in the center band
	qrRect := image.Rect(0, brandedQRPadding, size, brandedQRPadding+size)
	draw.Draw(canvas, qrRect, qrImg, image.Point{}, draw.Over)

	// Draw "TrustPIN" header and "M-LAN" footer
	accent := color.RGBA{16, 185, 129, 255} // --accent green
	dark := color.RGBA{30, 41, 59, 255}     // dark slate

	drawText(canvas, "TrustPIN", size/2, 6, accent, true)
	drawText(canvas, "M-LAN", size/2, totalH-10, dark, false)

	var buf bytes.Buffer
	if err := png.Encode(&buf, canvas); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// drawText renders a simple pixel-font string centered at (cx, y).
// If bold is true, each pixel is drawn 2px wide for emphasis.
func drawText(img *image.RGBA, text string, cx, y int, col color.RGBA, bold bool) {
	glyphs := pixelFont()
	// Calculate total width
	totalW := 0
	for _, ch := range text {
		if g, ok := glyphs[ch]; ok {
			totalW += len(g[0]) + 1 // +1 for letter spacing
		} else {
			totalW += 4
		}
	}
	if totalW > 0 {
		totalW-- // remove trailing spacing
	}

	scale := 2
	startX := cx - (totalW*scale)/2
	curX := startX

	for _, ch := range text {
		g, ok := glyphs[ch]
		if !ok {
			curX += 4 * scale
			continue
		}
		for row, line := range g {
			for col_idx, px := range line {
				if px == 1 {
					for dy := 0; dy < scale; dy++ {
						for dx := 0; dx < scale; dx++ {
							img.SetRGBA(curX+col_idx*scale+dx, y+row*scale+dy, col)
						}
					}
					if bold {
						for dy := 0; dy < scale; dy++ {
							img.SetRGBA(curX+col_idx*scale+scale, y+row*scale+dy, col)
						}
					}
				}
			}
		}
		curX += (len(g[0]) + 1) * scale
	}
}

// pixelFont returns a minimal 5-row pixel font for uppercase + digits.
func pixelFont() map[rune][][]int {
	return map[rune][][]int{
		'T': {{1, 1, 1}, {0, 1, 0}, {0, 1, 0}, {0, 1, 0}, {0, 1, 0}},
		'r': {{0, 0, 0}, {1, 0, 1}, {1, 1, 0}, {1, 0, 0}, {1, 0, 0}},
		'u': {{0, 0, 0}, {1, 0, 1}, {1, 0, 1}, {1, 0, 1}, {0, 1, 1}},
		's': {{0, 0, 0}, {0, 1, 1}, {1, 0, 0}, {0, 0, 1}, {1, 1, 0}},
		't': {{0, 1, 0}, {1, 1, 1}, {0, 1, 0}, {0, 1, 0}, {0, 0, 1}},
		'P': {{1, 1, 0}, {1, 0, 1}, {1, 1, 0}, {1, 0, 0}, {1, 0, 0}},
		'I': {{1, 1, 1}, {0, 1, 0}, {0, 1, 0}, {0, 1, 0}, {1, 1, 1}},
		'N': {{1, 0, 0, 1}, {1, 1, 0, 1}, {1, 0, 1, 1}, {1, 0, 0, 1}, {1, 0, 0, 1}},
		'M': {{1, 0, 0, 0, 1}, {1, 1, 0, 1, 1}, {1, 0, 1, 0, 1}, {1, 0, 0, 0, 1}, {1, 0, 0, 0, 1}},
		'-': {{0, 0, 0}, {0, 0, 0}, {1, 1, 1}, {0, 0, 0}, {0, 0, 0}},
		'L': {{1, 0, 0}, {1, 0, 0}, {1, 0, 0}, {1, 0, 0}, {1, 1, 1}},
		'A': {{0, 1, 0}, {1, 0, 1}, {1, 1, 1}, {1, 0, 1}, {1, 0, 1}},
	}
}
