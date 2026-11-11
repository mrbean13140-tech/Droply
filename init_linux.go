package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	uidServe = 1000
	uidCF    = 1001
	cfPath   = "/opt/cloudflared"
	// версия закреплена и проверяется по SHA-256 (защита от подмены при скачивании)
	cfURL    = "https://github.com/cloudflare/cloudflared/releases/download/2026.10.7/cloudflared-linux-amd64"
	cfSHA256 = "1f99fb518b83dec2ba8d870a7cc991d82a77e6196295a3d2754ba17ab9f91872"
)

func logf(f string, a ...any) {
	fmt.Fprintf(logRing, time.Now().Format("15:04:05 ")+f+"\n", a...)
}

func runInit() {
	logf("landrop init")
	os.Setenv("PATH", "/bin")
	syscall.Mount("tmpfs", "/tmp", "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "size=16m,mode=1777")
	syscall.Mount("tmpfs", "/run", "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "size=4m")

	cfg, err := loadConfig()
	if err != nil {
		logf("config error: %v", err)
		sleepForever()
	}
	if err := setupNet(cfg); err != nil {
		logf("net error: %v", err)
	}
	var rc strings.Builder
	for _, d := range cfg.DNS {
		rc.WriteString("nameserver " + d + "\n")
	}
	os.WriteFile("/etc/resolv.conf", []byte(rc.String()), 0644)

	os.Chown(cfg.DataDir, 0, 0)
	os.Chmod(cfg.DataDir, 0755)
	for _, d := range []string{"files", "part", "meta"} {
		os.MkdirAll(cfg.DataDir+"/"+d, 0750)
		os.Chown(cfg.DataDir+"/"+d, uidServe, uidServe)
	}

	// Секреты (токен туннеля, пароль) лежат на томе данных, доступны только root.
	secDir := cfg.DataDir + "/.cfg"
	os.MkdirAll(secDir, 0700)
	os.Chown(secDir, 0, 0)
	os.Chmod(secDir, 0700)
	secPath := secDir + "/secret.json"
	readJSON(secPath, cfg)
	st := &state{cfg: cfg, secPath: secPath}
	st.writeServeConfig()

	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGPWR)

	self, _ := os.Executable()
	st.serve = &svc{name: "serve", path: self, args: []string{"serve"}, uid: uidServe,
		envFn: func() []string { return []string{"LANDROP_CONFIG=/run/serve.json"} }}
	st.cf = &svc{name: "cloudflared", path: cfPath, uid: uidCF, prep: ensureCloudflared,
		args:    []string{"tunnel", "--no-autoupdate", "--protocol", "http2", "--metrics", "127.0.0.1:0", "run"},
		enabled: func() bool { return st.token() != "" && st.cfg.TLSDomain == "" }, // при прямом HTTPS туннель не нужен
		envFn:   func() []string { return []string{"TUNNEL_TOKEN=" + st.token(), "HOME=/tmp"} }}
	go st.serve.loop()
	go st.cf.loop()
	go runSettings(st) // страница настройки :8081 (после первой настройки — по паролю)

	s := <-sig
	logf("signal %v, stopping", s)
	st.serve.stop()
	st.cf.stop()
	time.Sleep(2 * time.Second)
	syscall.Sync()
	os.Exit(0)
}

type state struct {
	mu        sync.Mutex
	cfg       *Config
	secPath   string
	serve, cf *svc
}

func (st *state) token() string {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.cfg.TunnelToken
}

// serve получает конфиг без токена туннеля
func (st *state) writeServeConfig() {
	st.mu.Lock()
	sc := *st.cfg
	st.mu.Unlock()
	sc.TunnelToken = ""
	sc.Password = ""
	b, _ := json.Marshal(sc)
	os.Remove("/run/serve.json")
	os.WriteFile("/run/serve.json", b, 0400)
	os.Chown("/run/serve.json", uidServe, uidServe)
}

type svc struct {
	name, path string
	args       []string
	envFn      func() []string
	enabled    func() bool
	uid        int
	prep       func() error
	mu         sync.Mutex
	cmd        *exec.Cmd
	stopping   bool
	restarting bool
}

func (s *svc) loop() {
	for !s.stopping {
		if s.enabled != nil && !s.enabled() {
			time.Sleep(5 * time.Second)
			continue
		}
		if s.prep != nil {
			if err := s.prep(); err != nil {
				logf("%s prep: %v", s.name, err)
				time.Sleep(30 * time.Second)
				continue
			}
		}
		c := exec.Command(s.path, s.args...)
		c.Env = append([]string{"PATH=/bin"}, s.envFn()...)
		c.Stdout, c.Stderr = logRing, logRing
		c.Dir = "/tmp"
		c.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(s.uid), Gid: uint32(s.uid)}, Setsid: true}
		s.mu.Lock()
		s.cmd = c
		s.restarting = false
		s.mu.Unlock()
		start := time.Now()
		logf("start %s", s.name)
		err := c.Run()
		logf("%s exited: %v", s.name, err)
		s.mu.Lock()
		quick := s.restarting
		s.mu.Unlock()
		if !quick && time.Since(start) < 10*time.Second {
			time.Sleep(10 * time.Second)
		}
	}
}

func (s *svc) stop() {
	s.mu.Lock()
	s.stopping = true
	s.mu.Unlock()
	s.kill()
}

func (s *svc) restart() {
	s.mu.Lock()
	s.restarting = true
	s.mu.Unlock()
	s.kill()
}

func (s *svc) kill() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != nil && s.cmd.Process != nil && s.cmd.ProcessState == nil {
		s.cmd.Process.Signal(syscall.SIGTERM)
	}
}

// cloudflared скачивается при первом старте и обновляется раз в 30 дней.
func fileSHA256(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil))
}

func ensureCloudflared() error {
	if fileSHA256(cfPath) == cfSHA256 {
		return nil
	}
	logf("downloading cloudflared")
	cl := &http.Client{Timeout: 5 * time.Minute}
	resp, err := cl.Get(cfURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	tmp := cfPath + ".new"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, resp.Body)
	f.Close()
	if sum := fileSHA256(tmp); err != nil || sum != cfSHA256 {
		os.Remove(tmp)
		return fmt.Errorf("cloudflared: контрольная сумма не совпала (%s), не запускаю", sum)
	}
	return os.Rename(tmp, cfPath)
}

func sleepForever() {
	for {
		time.Sleep(time.Hour)
	}
}

// ---- сеть через ioctl (в контейнере нет ip/ifconfig) ----

type ifreqAddr struct {
	Name [16]byte
	Addr syscall.RawSockaddrInet4
	_    [8]byte
}
type ifreqFlags struct {
	Name  [16]byte
	Flags uint16
	_     [22]byte
}
type rtentry struct {
	Pad1    uint64
	Dst     syscall.RawSockaddrInet4
	Gateway syscall.RawSockaddrInet4
	Genmask syscall.RawSockaddrInet4
	Flags   uint16
	Pad2    int16
	Pad3    uint64
	Pad4    uintptr
	Metric  int16
	Dev     uintptr
	Mtu     uint64
	Window  uint64
	Irtt    uint16
}

func ioctl(fd int, req uintptr, p unsafe.Pointer) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(p)); e != 0 {
		return e
	}
	return nil
}

func sa4(ip net.IP) syscall.RawSockaddrInet4 {
	s := syscall.RawSockaddrInet4{Family: syscall.AF_INET}
	copy(s.Addr[:], ip.To4())
	return s
}

func ifUp(fd int, name string) error {
	var r ifreqFlags
	copy(r.Name[:], name)
	if err := ioctl(fd, syscall.SIOCGIFFLAGS, unsafe.Pointer(&r)); err != nil {
		return err
	}
	r.Flags |= syscall.IFF_UP | syscall.IFF_RUNNING
	return ioctl(fd, syscall.SIOCSIFFLAGS, unsafe.Pointer(&r))
}

func setupNet(c *Config) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	ifUp(fd, "lo")
	if c.IP == "" {
		return nil
	}
	ip, nw, err := net.ParseCIDR(c.IP)
	if err != nil {
		return err
	}
	var r ifreqAddr
	copy(r.Name[:], c.Iface)
	r.Addr = sa4(ip)
	if err := ioctl(fd, syscall.SIOCSIFADDR, unsafe.Pointer(&r)); err != nil {
		return fmt.Errorf("addr: %w", err)
	}
	r.Addr = sa4(net.IP(nw.Mask))
	if err := ioctl(fd, syscall.SIOCSIFNETMASK, unsafe.Pointer(&r)); err != nil {
		return fmt.Errorf("mask: %w", err)
	}
	if err := ifUp(fd, c.Iface); err != nil {
		return fmt.Errorf("up: %w", err)
	}
	if c.GW != "" {
		var rt rtentry
		rt.Dst = sa4(net.IPv4zero)
		rt.Genmask = sa4(net.IPv4zero)
		rt.Gateway = sa4(net.ParseIP(c.GW))
		rt.Flags = 0x1 | 0x2 // RTF_UP|RTF_GATEWAY
		if err := ioctl(fd, syscall.SIOCADDRT, unsafe.Pointer(&rt)); err != nil {
			return fmt.Errorf("route: %w", err)
		}
	}
	logf("net %s via %s on %s", c.IP, c.GW, c.Iface)
	return nil
}
