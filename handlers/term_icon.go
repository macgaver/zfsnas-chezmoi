package handlers

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
	"net/http"
	"sync"
)

// ServeZTerminalsIcon returns the apple-touch-icon used when an iPad
// user adds the consolidated terminal page (/terminal-multi) to their
// home screen as a standalone webapp.
//
// iOS Safari requires a *PNG* for apple-touch-icon — SVGs in the link
// tag are silently ignored and iOS falls back to /apple-touch-icon.png
// at the site root (the main ZNAS portal icon). The PNG is rendered
// once at startup with stdlib image drawing (no external dependencies)
// and cached as bytes for every subsequent request.
//
//	GET /icons/z-terminals.png  — apple-touch-icon, 360×360
//	GET /icons/z-terminals.svg  — favicon for the browser tab itself
func ServeZTerminalsIcon(w http.ResponseWriter, r *http.Request) {
	if bytes := zTerminalsPNG(); bytes != nil {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(bytes) //nolint:errcheck
		return
	}
	http.Error(w, "icon not available", http.StatusInternalServerError)
}

// ServeZTerminalsIconSVG returns the vector version used for the
// browser tab favicon (where SVG is supported and crisper than PNG).
func ServeZTerminalsIconSVG(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write([]byte(zTerminalsIconSVG)) //nolint:errcheck
}

// ── PNG generator ────────────────────────────────────────────────────────────

var (
	zTermPNGOnce  sync.Once
	zTermPNGBytes []byte
)

func zTerminalsPNG() []byte {
	zTermPNGOnce.Do(func() {
		zTermPNGBytes = renderZTerminalsPNG(360)
	})
	return zTermPNGBytes
}

// renderZTerminalsPNG draws the Z Terminals icon at outW×outW pixels
// using a 2× supersample for anti-aliasing. Pure stdlib (image,
// image/draw, image/png, math). Mirrors the SVG design at
// zTerminalsIconSVG: dark navy background, rounded corners, neon-cyan
// "Z" plus chevron prompt, magenta block cursor.
func renderZTerminalsPNG(outW int) []byte {
	const ss = 2 // supersample factor for AA
	W := outW * ss

	// 1. Allocate big canvas filled with background gradient.
	big := image.NewRGBA(image.Rect(0, 0, W, W))
	for y := 0; y < W; y++ {
		for x := 0; x < W; x++ {
			big.Set(x, y, bgColorAt(x, y, W))
		}
	}

	// 2. Carve rounded corners by masking alpha to 0 outside the squircle.
	cornerR := int(0.22 * float64(W)) // 56/256 ≈ 0.22 — same as SVG rx=56
	applyRoundedMask(big, W, cornerR)

	// 3. Tron-style perspective grid converging toward (W/2, 0.66W).
	gridCol := color.RGBA{0x1a, 0x4a, 0x72, 0xC0}
	vx, vy := float64(W)/2, 0.66*float64(W)
	for _, sx := range []float64{-0.20, 0.05, 0.25, 0.40, 0.55, 0.72, 0.95, 1.20} {
		drawAALine(big, sx*float64(W), float64(W), vx, vy, 1.0*ss, gridCol)
	}
	// Horizontal grid lines near the bottom.
	for _, y := range []float64{0.82, 0.88, 0.94} {
		drawAALine(big, 0, y*float64(W), float64(W), y*float64(W), 1.0*ss, color.RGBA{0x10, 0x3a, 0x55, 0xC0})
	}

	// 4. Terminal-window outline + traffic lights.
	rectStroke := color.RGBA{0x00, 0xc0, 0xe8, 0x66}
	drawRoundedRectStroke(big,
		int(0.125*float64(W)), int(0.156*float64(W)),
		int(0.875*float64(W)), int(0.844*float64(W)),
		int(0.047*float64(W)), 2*ss, rectStroke)
	// Title-bar separator
	drawAALine(big, 0.125*float64(W), 0.258*float64(W), 0.875*float64(W), 0.258*float64(W),
		1.2*ss, color.RGBA{0x00, 0xc0, 0xe8, 0x55})
	// Traffic-light dots (red, yellow, green) with a tiny blur for glow.
	fillCircle(big, int(0.188*float64(W)), int(0.207*float64(W)), int(0.018*float64(W)),
		color.RGBA{0xff, 0x5f, 0x57, 0xff})
	fillCircle(big, int(0.242*float64(W)), int(0.207*float64(W)), int(0.018*float64(W)),
		color.RGBA{0xff, 0xbd, 0x2e, 0xff})
	fillCircle(big, int(0.297*float64(W)), int(0.207*float64(W)), int(0.018*float64(W)),
		color.RGBA{0x28, 0xca, 0x42, 0xff})

	// 5. The big neon "Z". Drawn as three connected line segments with
	//    a thick stroke, then a 2-pass outer glow via wider faded strokes.
	zStroke := []struct{ x1, y1, x2, y2 float64 }{
		{0.219, 0.359, 0.516, 0.359}, // top bar
		{0.516, 0.359, 0.219, 0.688}, // diagonal
		{0.219, 0.688, 0.516, 0.688}, // bottom bar
	}
	cyanCore := color.RGBA{0xaf, 0xf8, 0xff, 0xff}
	cyanBright := color.RGBA{0x00, 0xe8, 0xff, 0xff}
	cyanDeep := color.RGBA{0x5b, 0x8c, 0xff, 0xff}
	for _, s := range zStroke {
		// Outer glow halo
		drawAALine(big, s.x1*float64(W), s.y1*float64(W), s.x2*float64(W), s.y2*float64(W), 38*ss/2, color.RGBA{0x00, 0xc8, 0xff, 0x20})
		drawAALine(big, s.x1*float64(W), s.y1*float64(W), s.x2*float64(W), s.y2*float64(W), 28*ss/2, color.RGBA{0x00, 0xd8, 0xff, 0x44})
		// Main stroke (gradient simulated by stacking colored layers)
		drawAALine(big, s.x1*float64(W), s.y1*float64(W), s.x2*float64(W), s.y2*float64(W), 20*ss/2, cyanDeep)
		drawAALine(big, s.x1*float64(W), s.y1*float64(W), s.x2*float64(W), s.y2*float64(W), 14*ss/2, cyanBright)
		drawAALine(big, s.x1*float64(W), s.y1*float64(W), s.x2*float64(W), s.y2*float64(W), 6*ss/2, cyanCore)
	}

	// 6. The neon ">" chevron prompt.
	chev := []struct{ x1, y1, x2, y2 float64 }{
		{0.594, 0.398, 0.742, 0.523},
		{0.742, 0.523, 0.594, 0.648},
	}
	for _, s := range chev {
		drawAALine(big, s.x1*float64(W), s.y1*float64(W), s.x2*float64(W), s.y2*float64(W), 32*ss/2, color.RGBA{0x00, 0xc8, 0xff, 0x22})
		drawAALine(big, s.x1*float64(W), s.y1*float64(W), s.x2*float64(W), s.y2*float64(W), 22*ss/2, color.RGBA{0x00, 0xd8, 0xff, 0x44})
		drawAALine(big, s.x1*float64(W), s.y1*float64(W), s.x2*float64(W), s.y2*float64(W), 16*ss/2, cyanBright)
		drawAALine(big, s.x1*float64(W), s.y1*float64(W), s.x2*float64(W), s.y2*float64(W), 8*ss/2, cyanCore)
	}

	// 7. Magenta block cursor next to the chevron.
	magenta := color.RGBA{0xff, 0x7d, 0xf0, 0xff}
	magentaDeep := color.RGBA{0xa3, 0x22, 0xff, 0xff}
	cx, cy := int(0.766*float64(W)), int(0.469*float64(W))
	cw, ch := int(0.055*float64(W)), int(0.109*float64(W))
	// Outer glow
	fillRoundedRect(big, cx-4*ss, cy-4*ss, cx+cw+4*ss, cy+ch+4*ss, 3*ss, color.RGBA{0xff, 0x44, 0xff, 0x30})
	// Body
	fillRoundedRect(big, cx, cy, cx+cw, cy+ch, 2*ss, magentaDeep)
	fillRoundedRect(big, cx+2*ss, cy+2*ss, cx+cw-2*ss, cy+ch-2*ss, 2*ss, magenta)

	// 8. Downsample big → outW with 2×2 box filter for clean AA edges.
	out := image.NewRGBA(image.Rect(0, 0, outW, outW))
	for y := 0; y < outW; y++ {
		for x := 0; x < outW; x++ {
			var r, g, b, a uint32
			for dy := 0; dy < ss; dy++ {
				for dx := 0; dx < ss; dx++ {
					c := big.RGBAAt(x*ss+dx, y*ss+dy)
					r += uint32(c.R)
					g += uint32(c.G)
					b += uint32(c.B)
					a += uint32(c.A)
				}
			}
			n := uint32(ss * ss)
			out.SetRGBA(x, y, color.RGBA{
				R: uint8(r / n), G: uint8(g / n),
				B: uint8(b / n), A: uint8(a / n),
			})
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, out); err != nil {
		return nil
	}
	return buf.Bytes()
}

// bgColorAt returns the radial-gradient background pixel at (x,y) on a
// canvas of side W. Approximates the SVG radialGradient stops:
//
//	r=0   → #0d1633
//	r=55% → #03071a
//	r=100%→ #000208
func bgColorAt(x, y, W int) color.RGBA {
	dx := float64(x-W/2) / float64(W/2)
	dy := float64(y-W/2) / float64(W/2)
	r := math.Min(1, math.Sqrt(dx*dx+dy*dy))
	var rc, gc, bc float64
	if r < 0.55 {
		t := r / 0.55
		rc = lerp(0x0d, 0x03, t)
		gc = lerp(0x16, 0x07, t)
		bc = lerp(0x33, 0x1a, t)
	} else {
		t := (r - 0.55) / 0.45
		rc = lerp(0x03, 0x00, t)
		gc = lerp(0x07, 0x02, t)
		bc = lerp(0x1a, 0x08, t)
	}
	return color.RGBA{uint8(rc), uint8(gc), uint8(bc), 0xff}
}

func lerp(a, b, t float64) float64 { return a + (b-a)*t }

// applyRoundedMask zeroes the alpha of pixels outside a rounded square.
func applyRoundedMask(img *image.RGBA, W, R int) {
	rsq := float64(R) * float64(R)
	for y := 0; y < W; y++ {
		for x := 0; x < W; x++ {
			var cx, cy float64
			switch {
			case x < R && y < R:
				cx, cy = float64(R), float64(R)
			case x >= W-R && y < R:
				cx, cy = float64(W-R), float64(R)
			case x < R && y >= W-R:
				cx, cy = float64(R), float64(W-R)
			case x >= W-R && y >= W-R:
				cx, cy = float64(W-R), float64(W-R)
			default:
				continue
			}
			dx := float64(x) - cx
			dy := float64(y) - cy
			d2 := dx*dx + dy*dy
			if d2 > rsq {
				img.SetRGBA(x, y, color.RGBA{})
			}
		}
	}
}

// drawAALine draws a width-`w` anti-aliased line from (x1,y1) to
// (x2,y2). Implementation: walk every pixel in the bounding box,
// compute its perpendicular distance to the segment, and alpha-blend
// `c` proportional to how much of that pixel sits within the stroke
// (distance ≤ w/2 → full coverage, smooth falloff over 1 px).
func drawAALine(img *image.RGBA, x1, y1, x2, y2, w float64, c color.RGBA) {
	half := w / 2
	// Bounding box of the stroke (with 1 px padding for AA falloff)
	minX := int(math.Min(x1, x2) - half - 1)
	minY := int(math.Min(y1, y2) - half - 1)
	maxX := int(math.Max(x1, x2) + half + 1)
	maxY := int(math.Max(y1, y2) + half + 1)
	if minX < 0 {
		minX = 0
	}
	if minY < 0 {
		minY = 0
	}
	if maxX >= img.Bounds().Max.X {
		maxX = img.Bounds().Max.X - 1
	}
	if maxY >= img.Bounds().Max.Y {
		maxY = img.Bounds().Max.Y - 1
	}
	dx, dy := x2-x1, y2-y1
	lenSq := dx*dx + dy*dy
	if lenSq == 0 {
		return
	}
	for py := minY; py <= maxY; py++ {
		for px := minX; px <= maxX; px++ {
			fx, fy := float64(px)+0.5, float64(py)+0.5
			// Project pixel center onto the segment (clamped to endpoints)
			t := ((fx-x1)*dx + (fy-y1)*dy) / lenSq
			if t < 0 {
				t = 0
			} else if t > 1 {
				t = 1
			}
			cxx := x1 + t*dx
			cyy := y1 + t*dy
			d := math.Sqrt((fx-cxx)*(fx-cxx) + (fy-cyy)*(fy-cyy))
			var cov float64
			switch {
			case d <= half-0.5:
				cov = 1
			case d >= half+0.5:
				continue
			default:
				cov = (half + 0.5 - d) // 0..1
			}
			alphaBlend(img, px, py, c, cov)
		}
	}
}

func alphaBlend(img *image.RGBA, x, y int, c color.RGBA, cov float64) {
	if cov <= 0 {
		return
	}
	srcA := float64(c.A) / 255.0 * cov
	if srcA <= 0 {
		return
	}
	dst := img.RGBAAt(x, y)
	dr := float64(dst.R) / 255.0
	dg := float64(dst.G) / 255.0
	db := float64(dst.B) / 255.0
	da := float64(dst.A) / 255.0
	sr := float64(c.R) / 255.0
	sg := float64(c.G) / 255.0
	sb := float64(c.B) / 255.0
	outA := srcA + da*(1-srcA)
	if outA <= 0 {
		return
	}
	outR := (sr*srcA + dr*da*(1-srcA)) / outA
	outG := (sg*srcA + dg*da*(1-srcA)) / outA
	outB := (sb*srcA + db*da*(1-srcA)) / outA
	img.SetRGBA(x, y, color.RGBA{
		R: uint8(outR * 255),
		G: uint8(outG * 255),
		B: uint8(outB * 255),
		A: uint8(outA * 255),
	})
}

func drawRoundedRectStroke(img *image.RGBA, x0, y0, x1, y1, r, w int, c color.RGBA) {
	fx0, fy0 := float64(x0), float64(y0)
	fx1, fy1 := float64(x1), float64(y1)
	fr := float64(r)
	// Top
	drawAALine(img, fx0+fr, fy0, fx1-fr, fy0, float64(w), c)
	// Bottom
	drawAALine(img, fx0+fr, fy1, fx1-fr, fy1, float64(w), c)
	// Left
	drawAALine(img, fx0, fy0+fr, fx0, fy1-fr, float64(w), c)
	// Right
	drawAALine(img, fx1, fy0+fr, fx1, fy1-fr, float64(w), c)
	// Four corner arcs — approximate with short line segments.
	const steps = 24
	for _, corner := range []struct{ cx, cy, start float64 }{
		{fx0 + fr, fy0 + fr, math.Pi},       // top-left
		{fx1 - fr, fy0 + fr, 1.5 * math.Pi}, // top-right
		{fx1 - fr, fy1 - fr, 0},             // bottom-right
		{fx0 + fr, fy1 - fr, 0.5 * math.Pi}, // bottom-left
	} {
		for i := 0; i < steps; i++ {
			a1 := corner.start + float64(i)/float64(steps)*0.5*math.Pi
			a2 := corner.start + float64(i+1)/float64(steps)*0.5*math.Pi
			drawAALine(img,
				corner.cx+math.Cos(a1)*fr, corner.cy+math.Sin(a1)*fr,
				corner.cx+math.Cos(a2)*fr, corner.cy+math.Sin(a2)*fr,
				float64(w), c)
		}
	}
}

func fillCircle(img *image.RGBA, cx, cy, r int, c color.RGBA) {
	for y := cy - r - 1; y <= cy+r+1; y++ {
		for x := cx - r - 1; x <= cx+r+1; x++ {
			if x < 0 || y < 0 || x >= img.Bounds().Max.X || y >= img.Bounds().Max.Y {
				continue
			}
			d := math.Sqrt(float64((x-cx)*(x-cx) + (y-cy)*(y-cy)))
			fr := float64(r)
			var cov float64
			switch {
			case d <= fr-0.5:
				cov = 1
			case d >= fr+0.5:
				continue
			default:
				cov = fr + 0.5 - d
			}
			alphaBlend(img, x, y, c, cov)
		}
	}
}

func fillRoundedRect(img *image.RGBA, x0, y0, x1, y1, r int, c color.RGBA) {
	for y := y0; y < y1; y++ {
		for x := x0; x < x1; x++ {
			if x < 0 || y < 0 || x >= img.Bounds().Max.X || y >= img.Bounds().Max.Y {
				continue
			}
			// Distance to nearest corner; cov=1 inside, smooth at edges.
			var dx, dy float64
			if x < x0+r {
				dx = float64(x0+r-x) - 0.5
			} else if x >= x1-r {
				dx = float64(x-(x1-r)) + 0.5
			}
			if y < y0+r {
				dy = float64(y0+r-y) - 0.5
			} else if y >= y1-r {
				dy = float64(y-(y1-r)) + 0.5
			}
			if dx > 0 && dy > 0 {
				d := math.Sqrt(dx*dx + dy*dy)
				if d >= float64(r)+0.5 {
					continue
				}
				cov := math.Min(1, float64(r)+0.5-d)
				alphaBlend(img, x, y, c, cov)
				continue
			}
			alphaBlend(img, x, y, c, 1)
		}
	}
}

const zTerminalsIconSVG = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" width="256" height="256">
  <defs>
    <radialGradient id="bg" cx="50%" cy="55%" r="70%">
      <stop offset="0%" stop-color="#0d1633"/>
      <stop offset="55%" stop-color="#03071a"/>
      <stop offset="100%" stop-color="#000208"/>
    </radialGradient>
    <linearGradient id="cyan" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#9ffaff"/>
      <stop offset="50%" stop-color="#00e8ff"/>
      <stop offset="100%" stop-color="#0078ff"/>
    </linearGradient>
    <linearGradient id="magenta" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#ff7df0"/>
      <stop offset="100%" stop-color="#a322ff"/>
    </linearGradient>
    <linearGradient id="zStroke" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%"  stop-color="#aff8ff"/>
      <stop offset="40%" stop-color="#00e8ff"/>
      <stop offset="65%" stop-color="#5b8cff"/>
      <stop offset="100%" stop-color="#a322ff"/>
    </linearGradient>
    <filter id="glow" x="-30%" y="-30%" width="160%" height="160%">
      <feGaussianBlur in="SourceGraphic" stdDeviation="3" result="b1"/>
      <feGaussianBlur in="SourceGraphic" stdDeviation="7" result="b2"/>
      <feMerge>
        <feMergeNode in="b2"/>
        <feMergeNode in="b1"/>
        <feMergeNode in="SourceGraphic"/>
      </feMerge>
    </filter>
    <filter id="softGlow" x="-50%" y="-50%" width="200%" height="200%">
      <feGaussianBlur in="SourceGraphic" stdDeviation="2"/>
      <feMerge>
        <feMergeNode/>
        <feMergeNode in="SourceGraphic"/>
      </feMerge>
    </filter>
    <clipPath id="round">
      <rect width="256" height="256" rx="56"/>
    </clipPath>
  </defs>
  <g clip-path="url(#round)">
    <rect width="256" height="256" fill="url(#bg)"/>
    <g stroke="#103a55" stroke-width="0.7" opacity="0.55">
      <line x1="0" y1="210" x2="256" y2="210"/>
      <line x1="0" y1="225" x2="256" y2="225"/>
      <line x1="0" y1="240" x2="256" y2="240"/>
    </g>
    <g stroke="#1a4a72" stroke-width="0.6" opacity="0.45">
      <line x1="-40" y1="256" x2="128" y2="170"/>
      <line x1="296" y1="256" x2="128" y2="170"/>
      <line x1="10"  y1="256" x2="128" y2="170"/>
      <line x1="246" y1="256" x2="128" y2="170"/>
      <line x1="60"  y1="256" x2="128" y2="170"/>
      <line x1="196" y1="256" x2="128" y2="170"/>
      <line x1="110" y1="256" x2="128" y2="170"/>
      <line x1="146" y1="256" x2="128" y2="170"/>
    </g>
    <rect x="32" y="40" width="192" height="176" rx="12" fill="none"
          stroke="url(#cyan)" stroke-width="1.6" opacity="0.5"/>
    <line x1="32" y1="66" x2="224" y2="66" stroke="url(#cyan)" stroke-width="1" opacity="0.35"/>
    <circle cx="48" cy="53" r="4" fill="#ff5f57" filter="url(#softGlow)"/>
    <circle cx="62" cy="53" r="4" fill="#ffbd2e" filter="url(#softGlow)"/>
    <circle cx="76" cy="53" r="4" fill="#28ca42" filter="url(#softGlow)"/>
    <g filter="url(#glow)">
      <path d="M 56 92 L 132 92 L 56 176 L 132 176"
            stroke="url(#zStroke)" stroke-width="20"
            stroke-linecap="round" stroke-linejoin="round" fill="none"/>
    </g>
    <g filter="url(#glow)">
      <path d="M 152 102 L 190 134 L 152 166"
            stroke="url(#cyan)" stroke-width="16"
            stroke-linecap="round" stroke-linejoin="round" fill="none"/>
    </g>
    <rect x="196" y="120" width="14" height="28" rx="2"
          fill="url(#magenta)" filter="url(#softGlow)"/>
    <rect x="0" y="0" width="256" height="40" fill="url(#cyan)" opacity="0.04"/>
  </g>
</svg>
`
