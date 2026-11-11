package main

// Локальная база городов и провайдеров (DB-IP Lite, формат MaxMind DB, лицензия CC BY 4.0).
// Файлы скачиваются раз в месяц в /data/meta/geo; читаются через ReadAt без загрузки в память,
// поэтому база весом ~130 МБ почти не занимает ОЗУ.

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type mmdb struct {
	f          *os.File
	size       int64
	nodeCount  uint32
	recordSize int
	ipVersion  int
	dataStart  int64
	v4start    uint32
}

var mmdbMarker = []byte("\xAB\xCD\xEFMaxMind.com")

func openMMDB(path string) (*mmdb, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	tail := int64(128 << 10)
	if tail > st.Size() {
		tail = st.Size()
	}
	buf := make([]byte, tail)
	if _, err := f.ReadAt(buf, st.Size()-tail); err != nil {
		f.Close()
		return nil, err
	}
	i := bytes.LastIndex(buf, mmdbMarker)
	if i < 0 {
		f.Close()
		return nil, errors.New("mmdb: no metadata")
	}
	db := &mmdb{f: f, size: st.Size()}
	metaOff := st.Size() - tail + int64(i+len(mmdbMarker))
	d := &mmdbDec{db: db, base: metaOff}
	meta, _, err := d.decode(metaOff)
	if err != nil {
		f.Close()
		return nil, err
	}
	m, ok := meta.(map[string]any)
	if !ok {
		f.Close()
		return nil, errors.New("mmdb: bad metadata")
	}
	db.nodeCount = uint32(asUint(m["node_count"]))
	db.recordSize = int(asUint(m["record_size"]))
	db.ipVersion = int(asUint(m["ip_version"]))
	if db.recordSize != 24 && db.recordSize != 28 && db.recordSize != 32 {
		f.Close()
		return nil, fmt.Errorf("mmdb: record size %d", db.recordSize)
	}
	db.dataStart = int64(db.recordSize*2/8)*int64(db.nodeCount) + 16
	if db.ipVersion == 6 { // IPv4 лежит под ::/96
		n := uint32(0)
		for i := 0; i < 96 && n < db.nodeCount; i++ {
			if n, err = db.record(n, 0); err != nil {
				f.Close()
				return nil, err
			}
		}
		db.v4start = n
	}
	return db, nil
}

func asUint(v any) uint64 {
	switch x := v.(type) {
	case uint64:
		return x
	}
	return 0
}

func (db *mmdb) record(node uint32, bit int) (uint32, error) {
	n := db.recordSize * 2 / 8
	b := make([]byte, n)
	if _, err := db.f.ReadAt(b, int64(node)*int64(n)); err != nil {
		return 0, err
	}
	switch db.recordSize {
	case 24:
		if bit == 0 {
			return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]), nil
		}
		return uint32(b[3])<<16 | uint32(b[4])<<8 | uint32(b[5]), nil
	case 28:
		if bit == 0 {
			return uint32(b[3]&0xF0)<<20 | uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]), nil
		}
		return uint32(b[3]&0x0F)<<24 | uint32(b[4])<<16 | uint32(b[5])<<8 | uint32(b[6]), nil
	default:
		if bit == 0 {
			return binary.BigEndian.Uint32(b[0:4]), nil
		}
		return binary.BigEndian.Uint32(b[4:8]), nil
	}
}

// lookup — запись для адреса (nil, если нет).
func (db *mmdb) lookup(a netip.Addr) (map[string]any, error) {
	var bits []byte
	node := uint32(0)
	if a.Is4() || a.Is4In6() {
		a4 := a.Unmap().As4()
		bits = a4[:]
		if db.ipVersion == 6 {
			node = db.v4start
		}
	} else {
		if db.ipVersion != 6 {
			return nil, nil
		}
		a16 := a.As16()
		bits = a16[:]
	}
	for i := 0; i < len(bits)*8 && node < db.nodeCount; i++ {
		bit := int(bits[i/8]>>(7-uint(i%8))) & 1
		var err error
		if node, err = db.record(node, bit); err != nil {
			return nil, err
		}
	}
	if node == db.nodeCount || node < db.nodeCount {
		return nil, nil
	}
	off := db.dataStart + int64(node-db.nodeCount) - 16
	d := &mmdbDec{db: db, base: db.dataStart}
	v, _, err := d.decode(off)
	if err != nil {
		return nil, err
	}
	m, _ := v.(map[string]any)
	return m, nil
}

type mmdbDec struct {
	db    *mmdb
	base  int64 // начало секции данных (указатели — от него)
	depth int
}

func (d *mmdbDec) read(off int64, n int) ([]byte, error) {
	if n < 0 || n > 16<<20 || off < 0 || off+int64(n) > d.db.size {
		return nil, errors.New("mmdb: out of range")
	}
	b := make([]byte, n)
	_, err := d.db.f.ReadAt(b, off)
	return b, err
}

// decode — значение по абсолютному смещению; возвращает значение и смещение следующего.
func (d *mmdbDec) decode(off int64) (any, int64, error) {
	d.depth++
	defer func() { d.depth-- }()
	if d.depth > 64 {
		return nil, 0, errors.New("mmdb: too deep")
	}
	h, err := d.read(off, 1)
	if err != nil {
		return nil, 0, err
	}
	ctrl := h[0]
	off++
	typ := int(ctrl >> 5)
	if typ == 1 { // указатель
		ss := int(ctrl>>3) & 3
		b, err := d.read(off, ss+1)
		if err != nil {
			return nil, 0, err
		}
		vvv := uint64(ctrl & 7)
		var p uint64
		switch ss {
		case 0:
			p = vvv<<8 | uint64(b[0])
		case 1:
			p = (vvv<<16 | uint64(b[0])<<8 | uint64(b[1])) + 2048
		case 2:
			p = (vvv<<24 | uint64(b[0])<<16 | uint64(b[1])<<8 | uint64(b[2])) + 526336
		default:
			p = uint64(binary.BigEndian.Uint32(b))
		}
		v, _, err := d.decode(d.base + int64(p))
		return v, off + int64(ss+1), err
	}
	if typ == 0 {
		b, err := d.read(off, 1)
		if err != nil {
			return nil, 0, err
		}
		typ = 7 + int(b[0])
		off++
	}
	size := int(ctrl & 0x1f)
	if size >= 29 {
		n := size - 28
		b, err := d.read(off, n)
		if err != nil {
			return nil, 0, err
		}
		off += int64(n)
		switch n {
		case 1:
			size = 29 + int(b[0])
		case 2:
			size = 285 + int(b[0])<<8 + int(b[1])
		default:
			size = 65821 + int(b[0])<<16 + int(b[1])<<8 + int(b[2])
		}
	}
	switch typ {
	case 2, 4: // строка, байты
		b, err := d.read(off, size)
		return string(b), off + int64(size), err
	case 3: // double
		b, err := d.read(off, 8)
		if err != nil {
			return nil, 0, err
		}
		return math.Float64frombits(binary.BigEndian.Uint64(b)), off + 8, nil
	case 15: // float
		b, err := d.read(off, 4)
		if err != nil {
			return nil, 0, err
		}
		return float64(math.Float32frombits(binary.BigEndian.Uint32(b))), off + 4, nil
	case 5, 6, 8, 9, 10: // целые (до 16 байт; больше 8 — обрезаем)
		b, err := d.read(off, size)
		if err != nil {
			return nil, 0, err
		}
		var v uint64
		for _, c := range b {
			v = v<<8 | uint64(c)
		}
		return v, off + int64(size), nil
	case 14: // bool
		return size != 0, off, nil
	case 7: // map
		m := make(map[string]any, size)
		for i := 0; i < size; i++ {
			k, next, err := d.decode(off)
			if err != nil {
				return nil, 0, err
			}
			v, next2, err := d.decode(next)
			if err != nil {
				return nil, 0, err
			}
			ks, _ := k.(string)
			m[ks] = v
			off = next2
		}
		return m, off, nil
	case 11: // array
		a := make([]any, 0, size)
		for i := 0; i < size; i++ {
			v, next, err := d.decode(off)
			if err != nil {
				return nil, 0, err
			}
			a = append(a, v)
			off = next
		}
		return a, off, nil
	}
	return nil, 0, fmt.Errorf("mmdb: type %d", typ)
}

// ---------- обёртка: город/страна/провайдер ----------

var geoDB struct {
	sync.RWMutex
	city, asn *mmdb
}

func pickName(m map[string]any) string {
	n, _ := m["names"].(map[string]any)
	for _, l := range []string{"ru", "en"} {
		if s, _ := n[l].(string); s != "" {
			return s
		}
	}
	return ""
}

var countryRu = map[string]string{"RU": "Россия", "BY": "Беларусь", "KZ": "Казахстан", "UA": "Украина", "DE": "Германия", "NL": "Нидерланды",
	"LV": "Латвия", "BG": "Болгария", "FI": "Финляндия", "US": "США", "GB": "Великобритания", "FR": "Франция", "TR": "Турция",
	"GE": "Грузия", "AM": "Армения", "UZ": "Узбекистан", "KG": "Киргизия", "AZ": "Азербайджан", "PL": "Польша", "EE": "Эстония",
	"LT": "Литва", "SE": "Швеция", "CN": "Китай", "AE": "ОАЭ", "IL": "Израиль", "CZ": "Чехия", "RS": "Сербия"}

// в Lite-базе города только на английском — крупные переводим
var cityRu = map[string]string{"Moscow": "Москва", "St Petersburg": "Санкт-Петербург", "Saint Petersburg": "Санкт-Петербург",
	"Novosibirsk": "Новосибирск", "Yekaterinburg": "Екатеринбург", "Kazan": "Казань", "Nizhniy Novgorod": "Нижний Новгород",
	"Nizhny Novgorod": "Нижний Новгород", "Chelyabinsk": "Челябинск", "Samara": "Самара", "Omsk": "Омск", "Rostov-on-Don": "Ростов-на-Дону",
	"Ufa": "Уфа", "Krasnoyarsk": "Красноярск", "Voronezh": "Воронеж", "Perm": "Пермь", "Volgograd": "Волгоград", "Krasnodar": "Краснодар",
	"Saratov": "Саратов", "Tyumen": "Тюмень", "Tolyatti": "Тольятти", "Izhevsk": "Ижевск", "Barnaul": "Барнаул", "Irkutsk": "Иркутск",
	"Khabarovsk": "Хабаровск", "Vladivostok": "Владивосток", "Yaroslavl": "Ярославль", "Makhachkala": "Махачкала", "Tomsk": "Томск",
	"Orenburg": "Оренбург", "Kemerovo": "Кемерово", "Novokuznetsk": "Новокузнецк", "Ryazan": "Рязань", "Astrakhan": "Астрахань",
	"Penza": "Пенза", "Lipetsk": "Липецк", "Kirov": "Киров", "Tula": "Тула", "Kaliningrad": "Калининград", "Stavropol": "Ставрополь",
	"Sochi": "Сочи", "Cherkessk": "Черкесск", "Nalchik": "Нальчик", "Vladikavkaz": "Владикавказ", "Pyatigorsk": "Пятигорск",
	"Kislovodsk": "Кисловодск", "Grozny": "Грозный", "Mineralnye Vody": "Минеральные Воды", "Nevinnomyssk": "Невинномысск",
	"Essentuki": "Ессентуки", "Karachayevsk": "Карачаевск", "Ust-Dzheguta": "Усть-Джегута", "Tver": "Тверь", "Kursk": "Курск",
	"Belgorod": "Белгород", "Bryansk": "Брянск", "Ivanovo": "Иваново", "Vladimir": "Владимир", "Smolensk": "Смоленск",
	"Kaluga": "Калуга", "Murmansk": "Мурманск", "Arkhangelsk": "Архангельск", "Surgut": "Сургут", "Yakutsk": "Якутск",
	"Ulyanovsk": "Ульяновск", "Cheboksary": "Чебоксары", "Petrozavodsk": "Петрозаводск", "Simferopol": "Симферополь",
	"Sevastopol": "Севастополь", "Minsk": "Минск", "Almaty": "Алматы", "Astana": "Астана", "Tbilisi": "Тбилиси", "Yerevan": "Ереван",
	"Frankfurt am Main": "Франкфурт", "Amsterdam": "Амстердам", "Riga": "Рига", "Sofia": "София", "Helsinki": "Хельсинки",
	"Istanbul": "Стамбул", "Mountain View": "Маунтин-Вью"}

func asnNum(v any) uint64 {
	n, _ := v.(uint64)
	return n
}

// mobileOp — имя мобильного оператора по AS ("" — не мобильный). Билайн и МТС держат и домашний интернет
// в других AS — их отбираем по номеру мобильной AS.
func mobileOp(org string, asn uint64) string {
	o := strings.ToLower(org)
	switch {
	case strings.Contains(o, "megafon"):
		return "МегаФон"
	case strings.Contains(o, "t2 mobile") || strings.Contains(o, "tele2") || strings.Contains(o, "t2 russia"):
		return "Т2"
	case strings.Contains(o, "yota") || strings.Contains(o, "scartel"):
		return "Yota"
	case asn == 16345 || asn == 3216 && strings.Contains(o, "mobile"):
		return "Билайн"
	case asn == 8359:
		return "МТС"
	case strings.Contains(o, "tinkoff mobile") || strings.Contains(o, "t-mobile russia"):
		return "Т-Мобайл"
	}
	return ""
}

// localPlace — «Санкт-Петербург, Россия · T2 Mobile» из локальной базы; ok=false — базы нет.
func localPlace(a netip.Addr) (string, bool) {
	geoDB.RLock()
	city, asn := geoDB.city, geoDB.asn
	geoDB.RUnlock()
	if city == nil {
		return "", false
	}
	// мобильные операторы раздают IP из общих региональных пулов — город по ним не определить, пишем только оператора
	if asn != nil {
		if m, err := asn.lookup(a); err == nil && m != nil {
			org, _ := m["autonomous_system_organization"].(string)
			if op := mobileOp(org, asnNum(m["autonomous_system_number"])); op != "" {
				country := "Россия"
				if cm, err := city.lookup(a); err == nil && cm != nil {
					co, _ := cm["country"].(map[string]any)
					iso, _ := co["iso_code"].(string)
					if n := countryRu[iso]; n != "" {
						country = n
					} else if n := pickName(co); n != "" {
						country = n
					}
				}
				return "мобильная сеть · " + op + ", " + country, true
			}
		}
	}
	var parts []string
	if m, err := city.lookup(a); err == nil && m != nil {
		cm, _ := m["city"].(map[string]any)
		if c := pickName(cm); c != "" {
			if i := strings.Index(c, " ("); i > 0 { // «Moscow (Tsentralnyy administrativnyy okrug)»
				c = c[:i]
			}
			if ru := cityRu[c]; ru != "" {
				c = ru
			}
			parts = append(parts, c)
		}
		co, _ := m["country"].(map[string]any)
		iso, _ := co["iso_code"].(string)
		if n := countryRu[iso]; n != "" {
			parts = append(parts, n)
		} else if n := pickName(co); n != "" {
			parts = append(parts, n)
		}
	}
	text := ""
	for i, p := range parts {
		if i > 0 {
			if p == parts[i-1] {
				continue
			}
			text += ", "
		}
		text += p
	}
	if asn != nil {
		if m, err := asn.lookup(a); err == nil && m != nil {
			if org, _ := m["autonomous_system_organization"].(string); org != "" {
				if text != "" {
					text += " · "
				}
				text += org
			}
		}
	}
	return text, true
}

// geoUpdater — при старте и раз в сутки: если базы нет или ей больше 35 дней — скачать свежую.
func (s *srv) geoUpdater() {
	dir := filepath.Join(s.cfg.DataDir, "meta", "geo")
	os.MkdirAll(dir, 0750)
	files := map[string]string{"city": "dbip-city-lite", "asn": "dbip-asn-lite"}
	for {
		for kind, prefix := range files {
			p := filepath.Join(dir, prefix+".mmdb")
			if st, err := os.Stat(p); err != nil || time.Since(st.ModTime()) > 35*24*time.Hour {
				if err := downloadGeo(prefix, p); err != nil {
					log.Printf("geo: %s: %v", prefix, err)
				} else {
					log.Printf("geo: %s обновлена", prefix)
				}
			}
			if db, err := openMMDB(p); err == nil {
				geoDB.Lock()
				old := geoDB.city
				if kind == "asn" {
					old = geoDB.asn
					geoDB.asn = db
				} else {
					geoDB.city = db
				}
				geoDB.Unlock()
				if old != nil {
					go func() { time.Sleep(time.Minute); old.f.Close() }() // дать дочитать текущим запросам
				}
			}
		}
		time.Sleep(24 * time.Hour)
	}
}

func downloadGeo(prefix, dst string) error {
	cl := &http.Client{Timeout: 10 * time.Minute}
	now := time.Now().UTC()
	var lastErr error
	for _, t := range []time.Time{now, now.AddDate(0, -1, 0)} { // база месяца выходит в первых числах
		url := fmt.Sprintf("https://download.db-ip.com/free/%s-%s.mmdb.gz", prefix, t.Format("2006-01"))
		resp, err := cl.Get(url)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			lastErr = fmt.Errorf("%s: %s", url, resp.Status)
			continue
		}
		zr, err := gzip.NewReader(resp.Body)
		if err != nil {
			resp.Body.Close()
			lastErr = err
			continue
		}
		tmp := dst + ".tmp"
		f, err := os.Create(tmp)
		if err != nil {
			resp.Body.Close()
			return err
		}
		_, err = io.Copy(f, io.LimitReader(zr, 1<<30))
		f.Close()
		resp.Body.Close()
		if err != nil {
			os.Remove(tmp)
			lastErr = err
			continue
		}
		if db, err := openMMDB(tmp); err != nil { // проверка, что файл читается
			os.Remove(tmp)
			lastErr = err
			continue
		} else {
			db.f.Close()
		}
		return os.Rename(tmp, dst)
	}
	return lastErr
}
