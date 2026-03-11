package handlers

import (
	"image"
	"image/color"
	"image/png"
	"net/http"
)

// HandleAppleTouchIcon serves a 180×180 PNG icon for iOS/iPadOS home screen.
// iOS ignores SVG apple-touch-icon links and requires a raster PNG.
func HandleAppleTouchIcon(w http.ResponseWriter, r *http.Request) {
	const size = 180
	img := image.NewRGBA(image.Rect(0, 0, size, size))

	bg     := color.RGBA{0x0d, 0x0d, 0x0f, 0xff} // #0d0d0f dark background
	cyan   := color.RGBA{0x00, 0xea, 0xff, 0xff} // #00eaff
	violet := color.RGBA{0x8a, 0x2c, 0xff, 0xff} // #8a2cff

	// Fill background.
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			img.Set(x, y, bg)
		}
	}

	// Rack frame.
	iconDrawRect(img, 20, 10, 140, 160, 3, cyan)

	// Three server unit rectangles.
	for i, c := range []color.RGBA{cyan, violet, cyan} {
		y := 30 + i*46
		iconDrawRect(img, 32, y, 116, 28, 2, c)
		// LED dot on the left of each unit.
		iconFillCircle(img, 44, y+14, 4, c)
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	png.Encode(w, img) //nolint:errcheck
}

func iconDrawRect(img *image.RGBA, x, y, w, h, thickness int, c color.RGBA) {
	for t := 0; t < thickness; t++ {
		for i := x; i < x+w; i++ {
			img.Set(i, y+t, c)
			img.Set(i, y+h-1-t, c)
		}
		for j := y; j < y+h; j++ {
			img.Set(x+t, j, c)
			img.Set(x+w-1-t, j, c)
		}
	}
}

func iconFillCircle(img *image.RGBA, cx, cy, r int, c color.RGBA) {
	for py := cy - r; py <= cy+r; py++ {
		for px := cx - r; px <= cx+r; px++ {
			dx, dy := px-cx, py-cy
			if dx*dx+dy*dy <= r*r {
				img.Set(px, py, c)
			}
		}
	}
}
