package main

// Минимальный QR-кодировщик: байтовый режим, уровень коррекции H (30% — чтобы поверх влезал логотип), версии 1–10 (до ~200 байт).

import (
	"errors"
	"fmt"
	"strings"
)

type qrVer struct {
	ec     int      // EC-кодовых слов на блок
	blocks [][2]int // {кол-во блоков, данных в блоке}
	align  []int
}

var qrM = []qrVer{ // уровень H
	{},
	{17, [][2]int{{1, 9}}, nil},
	{28, [][2]int{{1, 16}}, []int{6, 18}},
	{22, [][2]int{{2, 13}}, []int{6, 22}},
	{16, [][2]int{{4, 9}}, []int{6, 26}},
	{22, [][2]int{{2, 11}, {2, 12}}, []int{6, 30}},
	{28, [][2]int{{4, 15}}, []int{6, 34}},
	{26, [][2]int{{4, 13}, {1, 14}}, []int{6, 22, 38}},
	{26, [][2]int{{4, 14}, {2, 15}}, []int{6, 24, 42}},
	{24, [][2]int{{4, 12}, {4, 13}}, []int{6, 26, 46}},
	{28, [][2]int{{6, 15}, {2, 16}}, []int{6, 28, 50}},
}

var gfExp [512]byte
var gfLog [256]int

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfLog[x] = i
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11d
		}
	}
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[gfLog[a]+gfLog[b]]
}

func rsEC(data []byte, n int) []byte {
	gen := []byte{1}
	for i := 0; i < n; i++ {
		ng := make([]byte, len(gen)+1)
		for j, g := range gen {
			ng[j] ^= g
			ng[j+1] ^= gfMul(g, gfExp[i])
		}
		gen = ng
	}
	res := make([]byte, len(data)+n)
	copy(res, data)
	for i := range data {
		c := res[i]
		if c == 0 {
			continue
		}
		for j := 1; j < len(gen); j++ {
			res[i+j] ^= gfMul(gen[j], c)
		}
	}
	return res[len(data):]
}

func dataCap(v int) int {
	n := 0
	for _, b := range qrM[v].blocks {
		n += b[0] * b[1]
	}
	return n
}

type bitBuf struct{ b []bool }

func (bb *bitBuf) put(v, n int) {
	for i := n - 1; i >= 0; i-- {
		bb.b = append(bb.b, v>>i&1 == 1)
	}
}

// qrEncode возвращает матрицу модулей (true = чёрный).
func qrEncode(text string) ([][]bool, error) {
	data := []byte(text)
	ver := 0
	for v := 1; v <= 10; v++ {
		cc := 8
		if v >= 10 {
			cc = 16
		}
		if 4+cc+8*len(data) <= dataCap(v)*8 {
			ver = v
			break
		}
	}
	if ver == 0 {
		return nil, errors.New("too long for QR")
	}
	cc := 8
	if ver >= 10 {
		cc = 16
	}
	capBits := dataCap(ver) * 8
	var bb bitBuf
	bb.put(4, 4)
	bb.put(len(data), cc)
	for _, c := range data {
		bb.put(int(c), 8)
	}
	for i := 0; i < 4 && len(bb.b) < capBits; i++ {
		bb.b = append(bb.b, false)
	}
	for len(bb.b)%8 != 0 {
		bb.b = append(bb.b, false)
	}
	for p := 0; len(bb.b) < capBits; p++ {
		bb.put([]int{0xec, 0x11}[p%2], 8)
	}
	cw := make([]byte, capBits/8)
	for i := range cw {
		for j := 0; j < 8; j++ {
			if bb.b[i*8+j] {
				cw[i] |= 1 << (7 - j)
			}
		}
	}
	// блоки + чередование
	vi := qrM[ver]
	var dBlocks, eBlocks [][]byte
	pos := 0
	for _, g := range vi.blocks {
		for k := 0; k < g[0]; k++ {
			blk := cw[pos : pos+g[1]]
			pos += g[1]
			dBlocks = append(dBlocks, blk)
			eBlocks = append(eBlocks, rsEC(blk, vi.ec))
		}
	}
	var final []byte
	for i := 0; ; i++ {
		any := false
		for _, b := range dBlocks {
			if i < len(b) {
				final = append(final, b[i])
				any = true
			}
		}
		if !any {
			break
		}
	}
	for i := 0; i < vi.ec; i++ {
		for _, b := range eBlocks {
			final = append(final, b[i])
		}
	}

	size := 17 + 4*ver
	m := make([][]bool, size)
	fn := make([][]bool, size) // функциональные модули
	for i := range m {
		m[i] = make([]bool, size)
		fn[i] = make([]bool, size)
	}
	set := func(r, c int, v bool) { m[r][c] = v; fn[r][c] = true }
	finder := func(r0, c0 int) {
		for r := -1; r <= 7; r++ {
			for c := -1; c <= 7; c++ {
				rr, cc := r0+r, c0+c
				if rr < 0 || cc < 0 || rr >= size || cc >= size {
					continue
				}
				in := r >= 0 && r <= 6 && c >= 0 && c <= 6
				v := in && (r == 0 || r == 6 || c == 0 || c == 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4))
				set(rr, cc, v)
			}
		}
	}
	finder(0, 0)
	finder(0, size-7)
	finder(size-7, 0)
	for i := 8; i < size-8; i++ {
		set(6, i, i%2 == 0)
		set(i, 6, i%2 == 0)
	}
	la := len(vi.align) - 1
	for i, r := range vi.align {
		for j, c := range vi.align {
			if (i == 0 && j == 0) || (i == 0 && j == la) || (i == la && j == 0) {
				continue // углы с поисковыми узорами
			}
			for dr := -2; dr <= 2; dr++ {
				for dc := -2; dc <= 2; dc++ {
					v := dr == -2 || dr == 2 || dc == -2 || dc == 2 || (dr == 0 && dc == 0)
					set(r+dr, c+dc, v)
				}
			}
		}
	}
	set(size-8, 8, true) // тёмный модуль
	// резерв под формат
	for i := 0; i < 9; i++ {
		if !fn[8][i] {
			set(8, i, false)
		}
		if !fn[i][8] {
			set(i, 8, false)
		}
	}
	for i := 0; i < 8; i++ {
		set(8, size-1-i, false)
		set(size-1-i, 8, false)
	}
	if ver >= 7 {
		vb := ver << 12
		rem := ver
		for i := 0; i < 12; i++ {
			rem = rem<<1 ^ (rem>>11)*0x1f25
		}
		vb |= rem
		for i := 0; i < 18; i++ {
			bit := vb>>i&1 == 1
			a, b := size-11+i%3, i/3
			set(a, b, bit)
			set(b, a, bit)
		}
	}
	// данные зигзагом
	bitIdx := 0
	total := len(final) * 8
	for right := size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < size; vert++ {
			for j := 0; j < 2; j++ {
				c := right - j
				upward := (right+1)&2 == 0
				r := vert
				if upward {
					r = size - 1 - vert
				}
				if fn[r][c] {
					continue
				}
				if bitIdx < total {
					m[r][c] = final[bitIdx/8]>>(7-bitIdx%8)&1 == 1
				}
				bitIdx++
			}
		}
	}
	// выбор маски
	best, bestPen := -1, 1<<30
	var bestM [][]bool
	for mask := 0; mask < 8; mask++ {
		t := make([][]bool, size)
		for r := range t {
			t[r] = append([]bool(nil), m[r]...)
		}
		for r := 0; r < size; r++ {
			for c := 0; c < size; c++ {
				if !fn[r][c] && maskBit(mask, r, c) {
					t[r][c] = !t[r][c]
				}
			}
		}
		drawFormat(t, mask)
		if p := penalty(t); p < bestPen {
			best, bestPen, bestM = mask, p, t
		}
	}
	_ = best
	return bestM, nil
}

func maskBit(mask, r, c int) bool {
	switch mask {
	case 0:
		return (r+c)%2 == 0
	case 1:
		return r%2 == 0
	case 2:
		return c%3 == 0
	case 3:
		return (r+c)%3 == 0
	case 4:
		return (r/2+c/3)%2 == 0
	case 5:
		return r*c%2+r*c%3 == 0
	case 6:
		return (r*c%2+r*c%3)%2 == 0
	default:
		return ((r+c)%2+r*c%3)%2 == 0
	}
}

func drawFormat(m [][]bool, mask int) {
	size := len(m)
	data := 2<<3 | mask // уровень H = 10
	rem := data
	for i := 0; i < 10; i++ {
		rem = rem<<1 ^ (rem>>9)*0x537
	}
	bits := (data<<10 | rem) ^ 0x5412
	bit := func(i int) bool { return bits>>i&1 == 1 }
	for i := 0; i <= 5; i++ {
		m[i][8] = bit(i)
	}
	m[7][8] = bit(6)
	m[8][8] = bit(7)
	m[8][7] = bit(8)
	for i := 9; i < 15; i++ {
		m[8][14-i] = bit(i)
	}
	for i := 0; i < 8; i++ {
		m[8][size-1-i] = bit(i)
	}
	for i := 8; i < 15; i++ {
		m[size-15+i][8] = bit(i)
	}
	m[size-8][8] = true
}

func penalty(m [][]bool) int {
	n := len(m)
	p := 0
	get := func(r, c int, horiz bool) bool {
		if horiz {
			return m[r][c]
		}
		return m[c][r]
	}
	for _, h := range []bool{true, false} {
		for r := 0; r < n; r++ {
			run := 1
			for c := 1; c < n; c++ {
				if get(r, c, h) == get(r, c-1, h) {
					run++
				} else {
					if run >= 5 {
						p += run - 2
					}
					run = 1
				}
			}
			if run >= 5 {
				p += run - 2
			}
			for c := 0; c+10 < n+1; c++ {
				if c+11 > n {
					break
				}
				pat := ""
				for k := 0; k < 11; k++ {
					if get(r, c+k, h) {
						pat += "1"
					} else {
						pat += "0"
					}
				}
				if pat == "10111010000" || pat == "00001011101" {
					p += 40
				}
			}
		}
	}
	dark := 0
	for r := 0; r < n; r++ {
		for c := 0; c < n; c++ {
			if m[r][c] {
				dark++
			}
			if r+1 < n && c+1 < n && m[r][c] == m[r+1][c] && m[r][c] == m[r][c+1] && m[r][c] == m[r+1][c+1] {
				p += 3
			}
		}
	}
	k := dark * 100 / (n * n)
	d := k - 50
	if d < 0 {
		d = -d
	}
	return p + d/5*10
}

// qrSVG — QR как SVG с полем 4 модуля.
func qrSVG(text string) (string, error) {
	m, err := qrEncode(text)
	if err != nil {
		return "", err
	}
	n := len(m) + 8
	var sb strings.Builder
	fmt.Fprintf(&sb, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges"><rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, n, n, n, n)
	for r := range m {
		for c := range m[r] {
			if m[r][c] {
				fmt.Fprintf(&sb, "M%d %dh1v1h-1z", c+4, r+4)
			}
		}
	}
	sb.WriteString(`"/>`)
	// логотип Droply в центре: ~22% ширины кода, перекрывает < 6% модулей (запас коррекции H — 30%)
	q := float64(len(m))
	sz := q * 0.22
	x := (float64(n) - sz) / 2
	pad := sz * 0.12
	r := sz / 2
	cx, cy := x+r, x+r
	fmt.Fprintf(&sb, `<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" rx="%.2f" fill="#fff"/>`, x-pad, x-pad, sz+2*pad, sz+2*pad, (sz+2*pad)*0.26)
	fmt.Fprintf(&sb, `<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" rx="%.2f" fill="#0a0a0a"/>`, x, x, sz, sz, sz*0.24)
	fmt.Fprintf(&sb, `<circle cx="%.2f" cy="%.2f" r="%.2f" fill="#fff"/>`, cx, cy, sz*0.31)
	k := sz * 0.13
	fmt.Fprintf(&sb, `<path d="M%.2f %.2fL%.2f %.2fL%.2f %.2f" fill="none" stroke="#0a0a0a" stroke-width="%.2f" stroke-linecap="round" stroke-linejoin="round" shape-rendering="geometricPrecision"/>`,
		cx-k, cy+k*0.45, cx, cy-k*0.55, cx+k, cy+k*0.45, sz*0.075)
	sb.WriteString(`</svg>`)
	return sb.String(), nil
}
