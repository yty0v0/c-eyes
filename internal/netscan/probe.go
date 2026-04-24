package netscan

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type probeObservation struct {
	IP string

	Alive bool

	Hostname  string
	MAC       string
	MACVendor string

	ScanModes     []string
	Sources       []string
	OpenTCPPorts  []int
	OpenUDPPorts  []int
	PortScanModes []string
	Warnings      []string
}

type modeSelection struct {
	Executable  []ScanMode
	Skipped     []string
	Permissions []string
	Warnings    []string
}

type rateLimiter struct {
	tuner  *adaptiveTuner
	jitter time.Duration
}

func newRateLimiter(tuner *adaptiveTuner, jitter time.Duration) *rateLimiter {
	return &rateLimiter{
		tuner:  tuner,
		jitter: jitter,
	}
}

func (r *rateLimiter) wait(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	pps := r.tuner.effectivePPS()
	if pps <= 0 {
		pps = 1
	}
	interval := time.Second / time.Duration(pps)
	delay := interval
	if r.jitter > 0 {
		extra := time.Duration(rand.Int63n(int64(r.jitter) + 1))
		delay += extra
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func selectModes(modes []ScanMode, hasIPv6 bool) modeSelection {
	out := modeSelection{
		Executable:  make([]ScanMode, 0, len(modes)),
		Skipped:     []string{},
		Permissions: []string{},
		Warnings:    []string{},
	}

	for _, mode := range modes {
		capability, ok := modeCapabilities[mode]
		if !ok {
			out.Skipped = append(out.Skipped, fmt.Sprintf("%s: unsupported mode", mode))
			continue
		}
		if !capability.SupportsIPv4 && !capability.SupportsIPv6 {
			out.Skipped = append(out.Skipped, fmt.Sprintf("%s: unsupported in current build", mode))
			continue
		}

		if capability.PermissionRequired {
			if err := checkPermissionForMode(mode, hasIPv6); err != nil {
				out.Permissions = append(out.Permissions, err.Error())
				continue
			}
		}

		if mode == ModeTCPSYN {
			out.Warnings = append(out.Warnings, "TS mode uses TCP connect fallback when raw SYN is unavailable in this build.")
		}

		out.Executable = append(out.Executable, mode)
	}
	return out
}

func checkPermissionForMode(mode ScanMode, hasIPv6 bool) error {
	switch mode {
	case ModeICMPEcho, ModeICMPAddressMask, ModeICMPTimestamp:
		if err := canOpenICMPSocket(false); err != nil {
			return fmt.Errorf("mode %s requires elevated privileges for raw ICMP: %v", mode, err)
		}
		if hasIPv6 && mode == ModeICMPEcho {
			if err := canOpenICMPSocket(true); err != nil {
				return fmt.Errorf("mode %s requires elevated privileges for raw ICMPv6: %v", mode, err)
			}
		}
		return nil
	default:
		return nil
	}
}

func canOpenICMPSocket(ipv6Enabled bool) error {
	network := "ip4:icmp"
	addr := "0.0.0.0"
	if ipv6Enabled {
		network = "ip6:ipv6-icmp"
		addr = "::"
	}
	conn, err := icmp.ListenPacket(network, addr)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func probeHost(
	ctx context.Context,
	target string,
	params normalizedParams,
	modes []ScanMode,
	limiter *rateLimiter,
) probeObservation {
	obs := probeObservation{
		IP:            target,
		ScanModes:     []string{},
		Sources:       []string{},
		OpenTCPPorts:  []int{},
		OpenUDPPorts:  []int{},
		PortScanModes: []string{},
		Warnings:      []string{},
	}

	for _, mode := range modes {
		if err := limiter.wait(ctx); err != nil {
			obs.Warnings = append(obs.Warnings, fmt.Sprintf("probe interrupted for %s: %v", target, err))
			return obs
		}

		modeResult := executeMode(ctx, target, mode, params)
		if modeResult.Warn != "" {
			obs.Warnings = append(obs.Warnings, modeResult.Warn)
		}
		if modeResult.Err != nil {
			obs.Warnings = append(obs.Warnings, modeResult.Err.Error())
			continue
		}
		if !modeResult.Alive {
			continue
		}
		obs.Alive = true
		obs.ScanModes = appendIfMissing(obs.ScanModes, string(mode))
		obs.Sources = appendIfMissing(obs.Sources, modeSource(mode, modeResult))
		obs.OpenTCPPorts = append(obs.OpenTCPPorts, modeResult.OpenTCPPorts...)
		obs.OpenUDPPorts = append(obs.OpenUDPPorts, modeResult.OpenUDPPorts...)
		if mode == ModeTCPConnect || mode == ModeTCPSYN || mode == ModeUDP {
			obs.PortScanModes = appendIfMissing(obs.PortScanModes, string(mode))
		}
		if obs.Hostname == "" && strings.TrimSpace(modeResult.Hostname) != "" {
			obs.Hostname = strings.TrimSpace(modeResult.Hostname)
		}
	}

	obs.OpenTCPPorts = uniqueInts(obs.OpenTCPPorts)
	obs.OpenUDPPorts = uniqueInts(obs.OpenUDPPorts)
	return obs
}

type modeResult struct {
	Alive        bool
	Hostname     string
	OpenTCPPorts []int
	OpenUDPPorts []int
	Source       string
	Warn         string
	Err          error
}

func executeMode(ctx context.Context, target string, mode ScanMode, params normalizedParams) modeResult {
	switch mode {
	case ModeARP:
		return probeARPFallback(ctx, target, params.Timeout)
	case ModeICMPEcho:
		alive, err := probeICMP(target, mode, params.Timeout)
		return modeResult{Alive: alive, Err: err}
	case ModeICMPAddressMask:
		alive, err := probeICMP(target, mode, params.Timeout)
		return modeResult{Alive: alive, Err: err}
	case ModeICMPTimestamp:
		alive, err := probeICMP(target, mode, params.Timeout)
		return modeResult{Alive: alive, Err: err}
	case ModeTCPConnect:
		open := probeTCPPorts(ctx, target, params.TCPPorts, params.Timeout)
		return modeResult{Alive: len(open) > 0, OpenTCPPorts: open}
	case ModeTCPSYN:
		open := probeTCPPorts(ctx, target, params.TCPPorts, params.Timeout)
		return modeResult{
			Alive:        len(open) > 0,
			OpenTCPPorts: open,
			Source:       modeCapabilities[ModeTCPConnect].Source,
		}
	case ModeUDP:
		open := probeUDPPorts(ctx, target, params.UDPPorts, params.Timeout)
		return modeResult{Alive: len(open) > 0, OpenUDPPorts: open}
	case ModeNetBIOS:
		alive, hostname := probeNetBIOS(target, params.Timeout)
		return modeResult{Alive: alive, Hostname: hostname}
	case ModeOXID:
		alive := probeTCPPort(ctx, target, 135, params.Timeout)
		open := []int{}
		if alive {
			open = append(open, 135)
		}
		return modeResult{Alive: alive, OpenTCPPorts: open}
	default:
		return modeResult{Err: fmt.Errorf("unsupported mode: %s", mode)}
	}
}

func probeARPFallback(ctx context.Context, target string, timeout time.Duration) modeResult {
	parsed := net.ParseIP(target)
	if parsed == nil || parsed.To4() == nil {
		return modeResult{Warn: fmt.Sprintf("A mode skipped for non-IPv4 target: %s", target)}
	}
	if !isPrivateIPv4(parsed.To4()) {
		return modeResult{Warn: fmt.Sprintf("A mode is optimized for local/private IPv4 targets: %s", target)}
	}

	ports := []int{80, 443, 445, 22}
	open := probeTCPPorts(ctx, target, ports, timeout)
	warn := "A mode uses local-subnet ARP-compatible fallback probing in this build."
	if len(open) > 0 {
		return modeResult{
			Alive: true,
			Warn:  warn,
		}
	}
	return modeResult{
		Alive: false,
		Warn:  warn,
	}
}

func probeICMP(target string, mode ScanMode, timeout time.Duration) (bool, error) {
	ip := net.ParseIP(target)
	if ip == nil {
		return false, nil
	}

	var (
		network string
		laddr   string
		mtype   icmp.Type
	)
	if ip.To4() != nil {
		network = "ip4:icmp"
		laddr = "0.0.0.0"
		switch mode {
		case ModeICMPEcho:
			mtype = ipv4.ICMPTypeEcho
		case ModeICMPAddressMask:
			mtype = ipv4.ICMPType(17)
		case ModeICMPTimestamp:
			mtype = ipv4.ICMPTypeTimestamp
		default:
			mtype = ipv4.ICMPTypeEcho
		}
	} else {
		if mode != ModeICMPEcho {
			return false, nil
		}
		network = "ip6:ipv6-icmp"
		laddr = "::"
		mtype = ipv6.ICMPTypeEchoRequest
	}

	conn, err := icmp.ListenPacket(network, laddr)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	body := &icmp.Echo{
		ID:   os.Getpid() & 0xffff,
		Seq:  int(time.Now().UnixNano() & 0xffff),
		Data: []byte("c-eyes"),
	}
	msg := icmp.Message{
		Type: mtype,
		Code: 0,
		Body: body,
	}
	payload, err := msg.Marshal(nil)
	if err != nil {
		return false, err
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return false, err
	}
	if _, err := conn.WriteTo(payload, &net.IPAddr{IP: ip}); err != nil {
		if errors.Is(err, os.ErrPermission) {
			return false, fmt.Errorf("permission denied while probing ICMP mode %s", mode)
		}
		return false, err
	}

	buf := make([]byte, 1500)
	n, peer, err := conn.ReadFrom(buf)
	if err != nil {
		if isTimeout(err) {
			return false, nil
		}
		return false, err
	}

	peerIP := ""
	if ipAddr, ok := peer.(*net.IPAddr); ok && ipAddr != nil && ipAddr.IP != nil {
		peerIP = ipAddr.IP.String()
	}
	if peerIP != "" && !sameIP(peerIP, target) {
		return false, nil
	}
	parsed, err := icmp.ParseMessage(protocolNumber(ip), buf[:n])
	if err != nil {
		return false, nil
	}

	switch parsed.Type {
	case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
		return true, nil
	case ipv4.ICMPTypeTimestampReply:
		return mode == ModeICMPTimestamp, nil
	case ipv4.ICMPType(18):
		return mode == ModeICMPAddressMask, nil
	default:
		return true, nil
	}
}

func probeTCPPorts(ctx context.Context, target string, ports []int, timeout time.Duration) []int {
	open := make([]int, 0, len(ports))
	for _, port := range ports {
		if probeTCPPort(ctx, target, port, timeout) {
			open = append(open, port)
		}
	}
	return open
}

func probeTCPPort(ctx context.Context, target string, port int, timeout time.Duration) bool {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func probeUDPPorts(ctx context.Context, target string, ports []int, timeout time.Duration) []int {
	open := make([]int, 0, len(ports))
	for _, port := range ports {
		if probeUDPPort(ctx, target, port, timeout) {
			open = append(open, port)
		}
	}
	return open
}

func probeUDPPort(ctx context.Context, target string, port int, timeout time.Duration) bool {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(target, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte{0}); err != nil {
		return false
	}

	buf := make([]byte, 32)
	_, err = conn.Read(buf)
	if err == nil {
		return true
	}
	if isTimeout(err) {
		// UDP timeout is treated as open|filtered to avoid dropping reachable hosts.
		return true
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "refused") || strings.Contains(lower, "unreachable") {
		return false
	}
	return false
}

func probeNetBIOS(target string, timeout time.Duration) (bool, string) {
	ip := net.ParseIP(target)
	if ip == nil || ip.To4() == nil {
		return false, ""
	}
	conn, err := net.DialTimeout("udp", net.JoinHostPort(target, "137"), timeout)
	if err != nil {
		return false, ""
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	query := netBIOSNodeStatusQuery()
	if _, err := conn.Write(query); err != nil {
		return false, ""
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return false, ""
	}
	if n <= 0 {
		return false, ""
	}
	return true, parseNetBIOSHostname(buf[:n])
}

func netBIOSNodeStatusQuery() []byte {
	txid := uint16(rand.Intn(65535))
	out := make([]byte, 50)
	binary.BigEndian.PutUint16(out[0:2], txid)
	// Flags: recursion desired.
	out[2] = 0x01
	out[3] = 0x10
	// Questions=1
	out[4] = 0x00
	out[5] = 0x01
	// Encoded NetBIOS name length=32, "*"
	out[12] = 0x20
	name := "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	copy(out[13:], []byte(name))
	out[45] = 0x00
	// TYPE NBSTAT, CLASS IN
	out[46] = 0x00
	out[47] = 0x21
	out[48] = 0x00
	out[49] = 0x01
	return out
}

func parseNetBIOSHostname(payload []byte) string {
	if len(payload) < 57 {
		return ""
	}
	count := int(payload[56])
	offset := 57
	for i := 0; i < count; i++ {
		if offset+18 > len(payload) {
			return ""
		}
		name := strings.TrimSpace(string(payload[offset : offset+15]))
		flags := binary.BigEndian.Uint16(payload[offset+16 : offset+18])
		offset += 18
		if flags&0x8000 == 0 && name != "" && name != "*" {
			return name
		}
	}
	return ""
}

func resolveHostname(ip string, timeout time.Duration) string {
	type lookupResult struct {
		names []string
	}
	resultCh := make(chan lookupResult, 1)
	go func() {
		names, _ := net.LookupAddr(ip)
		resultCh <- lookupResult{names: names}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-timer.C:
		return ""
	case result := <-resultCh:
		if len(result.names) == 0 {
			return ""
		}
		name := strings.TrimSpace(strings.TrimSuffix(result.names[0], "."))
		return name
	}
}

func inferProfile(obs probeObservation) (osFamily, deviceType string, confidence int) {
	osFamily = "unknown"
	deviceType = "unknown"
	confidence = 20

	openTCP := map[int]struct{}{}
	for _, port := range obs.OpenTCPPorts {
		openTCP[port] = struct{}{}
	}
	openUDP := map[int]struct{}{}
	for _, port := range obs.OpenUDPPorts {
		openUDP[port] = struct{}{}
	}

	if _, ok135 := openTCP[135]; ok135 {
		if _, ok445 := openTCP[445]; ok445 {
			osFamily = "windows"
			deviceType = "pc"
			confidence = 88
			return
		}
	}
	if _, ok22 := openTCP[22]; ok22 {
		osFamily = "linux"
		deviceType = "server"
		confidence = 82
	}
	if _, ok3389 := openTCP[3389]; ok3389 {
		osFamily = "windows"
		if deviceType == "unknown" {
			deviceType = "pc"
		}
		confidence = maxInt(confidence, 80)
	}
	if _, ok80 := openTCP[80]; ok80 {
		if _, ok443 := openTCP[443]; ok443 {
			if deviceType == "unknown" {
				deviceType = "iot"
			}
			confidence = maxInt(confidence, 68)
		}
	}
	if _, ok161 := openUDP[161]; ok161 {
		deviceType = "network_device"
		confidence = maxInt(confidence, 72)
	}
	if _, ok53 := openUDP[53]; ok53 && deviceType == "unknown" {
		deviceType = "server"
		confidence = maxInt(confidence, 65)
	}
	if deviceType == "unknown" && obs.Alive {
		deviceType = "pc"
		confidence = maxInt(confidence, 40)
	}
	return
}

func modeSource(mode ScanMode, result modeResult) string {
	override := strings.TrimSpace(result.Source)
	if override != "" {
		return override
	}
	if capability, ok := modeCapabilities[mode]; ok {
		return capability.Source
	}
	return ""
}

func appendIfMissing(items []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return items
	}
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item), value) {
			return items
		}
	}
	return append(items, value)
}

func uniqueInts(values []int) []int {
	if len(values) == 0 {
		return []int{}
	}
	seen := make(map[int]struct{}, len(values))
	out := make([]int, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}

func sameIP(a, b string) bool {
	na, okA := normalizeIP(a)
	nb, okB := normalizeIP(b)
	return okA && okB && na == nb
}

func protocolNumber(ip net.IP) int {
	if ip.To4() != nil {
		return 1
	}
	return 58
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	type timeout interface {
		Timeout() bool
	}
	var te timeout
	if errors.As(err, &te) {
		return te.Timeout()
	}
	return strings.Contains(strings.ToLower(err.Error()), "timeout")
}

func platformName() string {
	switch runtime.GOOS {
	case "windows", "linux":
		return runtime.GOOS
	default:
		return runtime.GOOS
	}
}
