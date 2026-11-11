package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
	"net/http"
	"sync"
)

var iconCache sync.Map

// Иконка Droply: чёрный фон, белый круг с чёрной стрелкой-галочкой вверх.
// Рисуется кодом с 4×4 сглаживанием.
func makeIcon(n int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, n, n))
	bg := [3]float64{10, 10, 10}
	white := [3]float64{255, 255, 255}
	// расстояние от точки до отрезка
	seg := func(x, y, ax, ay, bx, by float64) float64 {
		dx, dy := bx-ax, by-ay
		t := ((x-ax)*dx + (y-ay)*dy) / (dx*dx + dy*dy)
		t = math.Max(0, math.Min(1, t))
		return math.Hypot(x-ax-t*dx, y-ay-t*dy)
	}
	color3 := func(x, y float64) [3]float64 {
		if math.Hypot(x-0.5, y-0.5) > 0.245 {
			return bg
		}
		// чёрная галочка-стрелка вверх внутри белого круга
		if seg(x, y, 0.391, 0.547, 0.5, 0.4375) <= 0.0275 || seg(x, y, 0.5, 0.4375, 0.609, 0.547) <= 0.0275 {
			return bg
		}
		return white
	}
	const ss = 4
	for py := 0; py < n; py++ {
		for px := 0; px < n; px++ {
			var acc [3]float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					x := (float64(px) + (float64(sx)+0.5)/ss) / float64(n)
					y := (float64(py) + (float64(sy)+0.5)/ss) / float64(n)
					c := color3(x, y)
					for i := range acc {
						acc[i] += c[i]
					}
				}
			}
			k := float64(ss * ss)
			img.Set(px, py, color.RGBA{uint8(acc[0] / k), uint8(acc[1] / k), uint8(acc[2] / k), 255})
		}
	}
	var b bytes.Buffer
	png.Encode(&b, img)
	return b.Bytes()
}

func iconHandler(size string) http.HandlerFunc {
	n := map[string]int{"180": 180, "192": 192, "512": 512}[size]
	return func(w http.ResponseWriter, r *http.Request) {
		v, ok := iconCache.Load(n)
		if !ok {
			v = makeIcon(n)
			iconCache.Store(n, v)
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Write(v.([]byte))
	}
}
