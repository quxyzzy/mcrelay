package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var version = "dev"

const (
	defaultCacheMS     = 1500
	defaultRequesterMS = 5000
	defaultBufSize     = 65535
	soReusePort        = 15 // SO_REUSEPORT; not exported by Go's syscall package on Linux
	ipPktInfo          = 8  // IP_PKTINFO (linux)
	ipv6PktInfo        = 50 // IPV6_PKTINFO (linux cmsg type)
	ipMulticastAll     = 49 // IP_MULTICAST_ALL (linux)
)

type relayConfig struct {
	service string
	family  int // 4 or 6
	group   string
	port    int
}

type listenerKey struct {
	iface   string
	service string
	family  int
}

type listener struct {
	ifaceName string
	ifindex   int
	cfg       relayConfig
	conn      *net.UDPConn
	groupAddr net.UDPAddr // pre-parsed destination for sends
}

type relay struct {
	listeners   []*listener
	listenerMap map[listenerKey]*listener
	cacheTTL    time.Duration
	reqTTL      time.Duration
	quiet       bool
	done        chan struct{}
	wg          sync.WaitGroup

	cacheMu sync.Mutex
	cache   map[uint64]time.Time

	reqMu     sync.Mutex
	requester map[string]time.Time // key: "service|family|iface|ip|port"

	filter *serviceFilter
}

type ipMreqn struct {
	Multiaddr [4]byte
	Address   [4]byte
	Ifindex   int32
}

type ipv6Mreq struct {
	Multiaddr [16]byte
	Ifindex   uint32
}

func main() {
	interfacesFlag := flag.String("interfaces", "", "Comma-separated interfaces (example: br10,br20,br40)")
	servicesFlag := flag.String("services", "mdns,ssdp", "Comma-separated services: mdns,ssdp,chromecast,googlecast")
	familiesFlag := flag.String("families", "4,6", "IP families: 4,6")
	cacheMS := flag.Int("cache-ms", defaultCacheMS, "Duplicate suppression window in ms")
	requesterMS := flag.Int("requester-ms", defaultRequesterMS, "Unicast requester tracking window in ms")
	bufsize := flag.Int("bufsize", defaultBufSize, "Receive buffer size")
	quiet := flag.Bool("quiet", false, "Reduce per-packet logging")
	showVersion := flag.Bool("version", false, "Print version and exit")
	blockServicesFlag := flag.String("block-services", strings.Join(defaultBlockedServices, ","), "Comma-separated mDNS service types to block from relay (empty to disable)")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	interfaces := parseCSV(*interfacesFlag)
	if len(interfaces) < 2 {
		exitf("need at least 2 interfaces")
	}

	services := parseCSV(*servicesFlag)
	if len(services) == 0 {
		exitf("services cannot be empty")
	}

	families, err := parseFamilies(*familiesFlag)
	if err != nil {
		exitf("invalid families: %v", err)
	}

	relayCfgs, err := buildConfigs(services, families)
	if err != nil {
		exitf("%v", err)
	}

	r := &relay{
		listenerMap: make(map[listenerKey]*listener),
		cacheTTL:    time.Duration(max(*cacheMS, 1)) * time.Millisecond,
		reqTTL:      time.Duration(max(*requesterMS, 1)) * time.Millisecond,
		quiet:       *quiet,
		cache:       make(map[uint64]time.Time),
		done:        make(chan struct{}),
		requester:   make(map[string]time.Time),
	}

	r.filter = newServiceFilter(parseCSV(*blockServicesFlag))

	for _, ifName := range interfaces {
		ifi, err := net.InterfaceByName(ifName)
		if err != nil {
			exitf("interface %q not found: %v", ifName, err)
		}

		for _, cfg := range relayCfgs {
			lst, err := newListener(ifi, cfg)
			if err != nil {
				exitf("listener create failed iface=%s svc=%s ipv%d: %v", ifName, cfg.service, cfg.family, err)
			}
			r.listeners = append(r.listeners, lst)
			r.listenerMap[listenerKey{iface: ifName, service: cfg.service, family: cfg.family}] = lst
		}
	}

	slog.Info("mcrelay started",
		"interfaces", strings.Join(interfaces, ","),
		"services", strings.Join(services, ","),
		"families", *familiesFlag,
		"cache_ms", *cacheMS,
		"requester_ms", *requesterMS,
		"block_services", *blockServicesFlag,
	)

	r.wg.Add(1)
	go r.cacheCleanup()

	for _, lst := range r.listeners {
		r.wg.Add(1)
		go r.readLoop(lst, max(*bufsize, 1024))
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	<-sigs

	slog.Info("mcrelay shutting down")
	close(r.done)
	for _, lst := range r.listeners {
		lst.conn.Close()
	}
	r.wg.Wait()
}

func parseCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseFamilies(s string) ([]int, error) {
	parts := parseCSV(s)
	if len(parts) == 0 {
		return nil, fmt.Errorf("families cannot be empty")
	}
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		switch p {
		case "4":
			out = append(out, 4)
		case "6":
			out = append(out, 6)
		default:
			return nil, fmt.Errorf("unsupported family %q", p)
		}
	}
	return out, nil
}

func buildConfigs(services []string, families []int) ([]relayConfig, error) {
	cfgs := []relayConfig{}
	for _, svc := range services {
		switch svc {
		case "mdns":
			for _, fam := range families {
				if fam == 4 {
					cfgs = append(cfgs, relayConfig{service: svc, family: 4, group: "224.0.0.251", port: 5353})
				} else {
					cfgs = append(cfgs, relayConfig{service: svc, family: 6, group: "ff02::fb", port: 5353})
				}
			}
		case "ssdp":
			for _, fam := range families {
				if fam == 4 {
					cfgs = append(cfgs, relayConfig{service: svc, family: 4, group: "239.255.255.250", port: 1900})
				} else {
					cfgs = append(cfgs, relayConfig{service: svc, family: 6, group: "ff02::c", port: 1900})
				}
			}
		case "chromecast", "googlecast":
			for _, fam := range families {
				if fam == 4 {
					cfgs = append(cfgs, relayConfig{service: "mdns", family: 4, group: "224.0.0.251", port: 5353})
					cfgs = append(cfgs, relayConfig{service: "ssdp", family: 4, group: "239.255.255.250", port: 1900})
				} else {
					cfgs = append(cfgs, relayConfig{service: "mdns", family: 6, group: "ff02::fb", port: 5353})
					cfgs = append(cfgs, relayConfig{service: "ssdp", family: 6, group: "ff02::c", port: 1900})
				}
			}
		default:
			return nil, fmt.Errorf("unsupported service %q (valid: mdns,ssdp,chromecast,googlecast)", svc)
		}
	}
	return dedupeConfigs(cfgs), nil
}

func dedupeConfigs(cfgs []relayConfig) []relayConfig {
	seen := make(map[string]struct{}, len(cfgs))
	out := make([]relayConfig, 0, len(cfgs))
	for _, c := range cfgs {
		k := fmt.Sprintf("%s|%d|%s|%d", c.service, c.family, c.group, c.port)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, c)
	}
	return out
}

func newListener(ifi *net.Interface, cfg relayConfig) (*listener, error) {
	fd, err := syscall.Socket(familyToSys(cfg.family), syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return nil, err
	}

	closeOnErr := true
	defer func() {
		if closeOnErr {
			_ = syscall.Close(fd)
		}
	}()

	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return nil, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, soReusePort, 1); err != nil {
		slog.Warn("SO_REUSEPORT not available", "iface", ifi.Name, "error", err)
	}

	if err := syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifi.Name); err != nil {
		return nil, err
	}

	if cfg.family == 4 {
		if err := bindV4(fd, cfg.port); err != nil {
			return nil, err
		}
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, ipPktInfo, 1); err != nil {
			return nil, fmt.Errorf("IP_PKTINFO: %w", err)
		}
		if err := joinV4(fd, ifi.Index, cfg.group); err != nil {
			return nil, err
		}
		_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, 1)
		_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, 0)
		// Only receive multicast for groups we've joined, not all groups on this port.
		_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, ipMulticastAll, 0)
		if err := setMulticastIfV4(fd, ifi.Index); err != nil {
			return nil, fmt.Errorf("IP_MULTICAST_IF: %w", err)
		}
	} else {
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1); err != nil {
			return nil, err
		}
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_RECVPKTINFO, 1); err != nil {
			return nil, fmt.Errorf("IPV6_RECVPKTINFO: %w", err)
		}
		if err := bindV6(fd, cfg.port); err != nil {
			return nil, err
		}
		if err := joinV6(fd, ifi.Index, cfg.group); err != nil {
			return nil, err
		}
		_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_HOPS, 1)
		_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_LOOP, 0)
		_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_IF, ifi.Index)
	}

	file := os.NewFile(uintptr(fd), fmt.Sprintf("mcrelay-%s-%s-ipv%d", ifi.Name, cfg.service, cfg.family))
	pc, err := net.FilePacketConn(file)
	_ = file.Close()
	if err != nil {
		return nil, err
	}

	uc, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, fmt.Errorf("unexpected packet conn type %T", pc)
	}

	lst := &listener{
		ifaceName: ifi.Name,
		ifindex:   ifi.Index,
		cfg:       cfg,
		conn:      uc,
	}
	if cfg.family == 4 {
		lst.groupAddr = net.UDPAddr{IP: net.ParseIP(cfg.group).To4(), Port: cfg.port}
	} else {
		lst.groupAddr = net.UDPAddr{IP: net.ParseIP(cfg.group).To16(), Port: cfg.port, Zone: ifi.Name}
	}

	closeOnErr = false
	return lst, nil
}

func familyToSys(f int) int {
	if f == 4 {
		return syscall.AF_INET
	}
	return syscall.AF_INET6
}

func bindV4(fd int, port int) error {
	var addr syscall.SockaddrInet4
	addr.Port = port
	return syscall.Bind(fd, &addr)
}

func bindV6(fd int, port int) error {
	var addr syscall.SockaddrInet6
	addr.Port = port
	return syscall.Bind(fd, &addr)
}

func joinV4(fd int, ifindex int, group string) error {
	ip := net.ParseIP(group).To4()
	if ip == nil {
		return fmt.Errorf("invalid v4 group %q", group)
	}
	var m ipMreqn
	copy(m.Multiaddr[:], ip)
	m.Ifindex = int32(ifindex)
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.IPPROTO_IP),
		uintptr(syscall.IP_ADD_MEMBERSHIP),
		uintptr(unsafe.Pointer(&m)),
		uintptr(binary.Size(m)),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func setMulticastIfV4(fd int, ifindex int) error {
	m := ipMreqn{Ifindex: int32(ifindex)}
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.IPPROTO_IP),
		uintptr(syscall.IP_MULTICAST_IF),
		uintptr(unsafe.Pointer(&m)),
		uintptr(binary.Size(m)),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func joinV6(fd int, ifindex int, group string) error {
	ip := net.ParseIP(group).To16()
	if ip == nil {
		return fmt.Errorf("invalid v6 group %q", group)
	}
	var m ipv6Mreq
	copy(m.Multiaddr[:], ip)
	m.Ifindex = uint32(ifindex)
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.IPPROTO_IPV6),
		uintptr(syscall.IPV6_JOIN_GROUP),
		uintptr(unsafe.Pointer(&m)),
		uintptr(binary.Size(m)),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func (r *relay) readLoop(src *listener, bufsize int) {
	defer r.wg.Done()
	buf := make([]byte, bufsize)
	oob := make([]byte, 256)
	outerLoop:
	for {
		n, oobn, _, addr, err := src.conn.ReadMsgUDP(buf, oob)
		if err != nil {
			select {
			case <-r.done:
				return
			default:
			}
			slog.Error("recv error", "iface", src.ifaceName, "svc", src.cfg.service, "family", src.cfg.family, "error", err)
			time.Sleep(250 * time.Millisecond)
			continue
		}

		payload := make([]byte, n)
		copy(payload, buf[:n])

		dstIP := parseDstIP(src.cfg.family, oob[:oobn])
		if dstIP == nil {
			continue
		}

		isMcast := dstIP.IsMulticast()
		if !isMcast {
			switch src.cfg.service {
			case "ssdp":
				r.forwardUnicastToRequesters(src, "ssdp", payload)
			case "mdns":
				if msg, err := parseMDNS(payload); err == nil {
					if isMDNSResponse(msg) {
						svcTypes := mdnsServiceTypes(msg)
						blocked := false
						for _, st := range svcTypes {
							if r.filter.isBlocked(st) {
								blocked = true
								break
							}
						}
						if !blocked {
							r.forwardUnicastToRequesters(src, "mdns", payload)
						}
					}
				} else if isDNSResponse(payload) {
					r.forwardUnicastToRequesters(src, "mdns", payload)
				}
			}
			continue
		}

		if !dstIP.Equal(net.ParseIP(src.cfg.group)) {
			continue
		}

		if src.cfg.service == "ssdp" && isMSearch(payload) && addr != nil {
			r.trackRequester("ssdp", src.cfg.family, src.ifaceName, *addr)
		}
		if src.cfg.service == "mdns" {
			if msg, err := parseMDNS(payload); err == nil {
				// Service-type filtering
				svcTypes := mdnsServiceTypes(msg)
				for _, st := range svcTypes {
					if r.filter.isBlocked(st) {
						if !r.quiet {
							slog.Info("blocked", "svc_types", svcTypes, "iface", src.ifaceName)
						}
						continue outerLoop
					}
				}
				// Goodbye packets bypass dedup suppression
				if isGoodbye(msg) {
					if !r.quiet {
						srcIP := "<nil>"
						if addr != nil && addr.IP != nil {
							srcIP = addr.IP.String()
						}
						slog.Info("goodbye", "svc", src.cfg.service, "family", src.cfg.family, "iface", src.ifaceName, "src", srcIP, "len", n)
					}
					// Forward without dedup check
					for _, dst := range r.listeners {
						if dst.ifaceName == src.ifaceName || dst.cfg != src.cfg {
							continue
						}
						if err := sendMulticast(dst, payload); err != nil {
							slog.Error("send error", "src", src.ifaceName, "dst", dst.ifaceName, "svc", dst.cfg.service, "family", dst.cfg.family, "error", err)
						}
					}
					continue
				}
				// Track mDNS queriers; note QU bit
				if isMDNSQuery(msg) && addr != nil {
					qu := hasQUBit(msg)
					r.trackRequester("mdns", src.cfg.family, src.ifaceName, *addr)
					if !r.quiet && qu {
						slog.Info("qu-query", "iface", src.ifaceName, "src", addr.IP.String())
					}
				}
			} else {
				// Parse failed — fall back to original behaviour
				if isDNSQuery(payload) && addr != nil {
					r.trackRequester("mdns", src.cfg.family, src.ifaceName, *addr)
				}
			}
		}

		if r.isDuplicate(src.cfg, payload) {
			continue
		}

		forwards := 0
		for _, dst := range r.listeners {
			if dst.ifaceName == src.ifaceName {
				continue
			}
			if dst.cfg != src.cfg {
				continue
			}
			if err := sendMulticast(dst, payload); err != nil {
				slog.Error("send error", "src", src.ifaceName, "dst", dst.ifaceName, "svc", dst.cfg.service, "family", dst.cfg.family, "error", err)
				continue
			}
			forwards++
		}

		if !r.quiet {
			srcIP := "<nil>"
			if addr != nil && addr.IP != nil {
				srcIP = addr.IP.String()
			}
			slog.Info("relay", "svc", src.cfg.service, "family", src.cfg.family, "iface", src.ifaceName, "src", srcIP, "len", n, "forwarded", forwards)
		}
	}
}

func sendMulticast(dst *listener, payload []byte) error {
	_, err := dst.conn.WriteToUDP(payload, &dst.groupAddr)
	return err
}

func parseDstIP(family int, oob []byte) net.IP {
	cmsgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil
	}
	for _, cmsg := range cmsgs {
		if family == 4 && cmsg.Header.Level == syscall.IPPROTO_IP && cmsg.Header.Type == ipPktInfo {
			// struct in_pktinfo { int ifindex; struct in_addr spec_dst; struct in_addr addr; }
			if len(cmsg.Data) >= 12 {
				return net.IPv4(cmsg.Data[8], cmsg.Data[9], cmsg.Data[10], cmsg.Data[11]).To4()
			}
		}
		if family == 6 && cmsg.Header.Level == syscall.IPPROTO_IPV6 && cmsg.Header.Type == ipv6PktInfo {
			// struct in6_pktinfo { struct in6_addr addr; unsigned int ifindex; }
			if len(cmsg.Data) >= 16 {
				ip := make(net.IP, 16)
				copy(ip, cmsg.Data[:16])
				return ip
			}
		}
	}
	return nil
}

func isMSearch(payload []byte) bool {
	p := bytes.TrimLeft(payload, "\r\n\t ")
	return len(p) >= 19 && bytes.EqualFold(p[:19], []byte("M-SEARCH * HTTP/1.1"))
}

func isDNSQuery(payload []byte) bool {
	if len(payload) < 12 {
		return false
	}
	flags := binary.BigEndian.Uint16(payload[2:4])
	return (flags & 0x8000) == 0
}

func isDNSResponse(payload []byte) bool {
	if len(payload) < 12 {
		return false
	}
	flags := binary.BigEndian.Uint16(payload[2:4])
	return (flags & 0x8000) != 0
}

func requesterKey(service string, family int, iface string, addr net.UDPAddr) string {
	return fmt.Sprintf("%s|%d|%s|%s|%d", service, family, iface, addr.IP.String(), addr.Port)
}

func (r *relay) trackRequester(service string, family int, iface string, addr net.UDPAddr) {
	if addr.IP == nil || addr.Port <= 0 || addr.IP.IsMulticast() {
		return
	}
	exp := time.Now().Add(r.reqTTL)
	key := requesterKey(service, family, iface, addr)
	r.reqMu.Lock()
	r.requester[key] = exp
	r.reqMu.Unlock()
}

func parseRequesterKey(key string) (service string, family int, iface string, addr net.UDPAddr, ok bool) {
	parts := strings.Split(key, "|")
	if len(parts) != 5 {
		return "", 0, "", net.UDPAddr{}, false
	}
	service = parts[0]
	switch parts[1] {
	case "4":
		family = 4
	case "6":
		family = 6
	default:
		return "", 0, "", net.UDPAddr{}, false
	}
	iface = parts[2]
	ip := net.ParseIP(parts[3])
	if ip == nil {
		return "", 0, "", net.UDPAddr{}, false
	}
	var port int
	_, err := fmt.Sscanf(parts[4], "%d", &port)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, "", net.UDPAddr{}, false
	}
	addr = net.UDPAddr{IP: ip, Port: port}
	return service, family, iface, addr, true
}

func (r *relay) findListener(iface, service string, family int) *listener {
	return r.listenerMap[listenerKey{iface: iface, service: service, family: family}]
}

func (r *relay) forwardUnicastToRequesters(src *listener, service string, payload []byte) {
	now := time.Now()

	var targets []struct {
		iface string
		addr  net.UDPAddr
	}

	r.reqMu.Lock()
	for key, exp := range r.requester {
		if now.After(exp) {
			delete(r.requester, key)
			continue
		}
		svc, family, iface, addr, ok := parseRequesterKey(key)
		if !ok {
			delete(r.requester, key)
			continue
		}
		if svc != service || family != src.cfg.family || iface == src.ifaceName {
			continue
		}
		if family == 6 && addr.IP.IsLinkLocalUnicast() {
			addr.Zone = iface
		}
		targets = append(targets, struct {
			iface string
			addr  net.UDPAddr
		}{iface: iface, addr: addr})
	}
	r.reqMu.Unlock()

	for _, t := range targets {
		dst := r.findListener(t.iface, service, src.cfg.family)
		if dst == nil {
			continue
		}
		if _, err := dst.conn.WriteToUDP(payload, &t.addr); err != nil {
			slog.Error("send unicast error", "src", src.ifaceName, "dst", t.iface, "svc", service, "family", src.cfg.family, "error", err)
		}
	}
}

func (r *relay) isDuplicate(cfg relayConfig, payload []byte) bool {
	var hdr [4]byte
	hdr[0] = byte(cfg.family)
	if cfg.service == "mdns" {
		hdr[1] = 1
	} else {
		hdr[1] = 2
	}
	binary.BigEndian.PutUint16(hdr[2:4], uint16(cfg.port))

	h := fnv.New64a()
	h.Write(hdr[:])
	h.Write(payload)
	sum := h.Sum64()

	now := time.Now()
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()

	if exp, ok := r.cache[sum]; ok && now.Before(exp) {
		return true
	}
	r.cache[sum] = now.Add(r.cacheTTL)
	return false
}

func (r *relay) cacheCleanup() {
	defer r.wg.Done()
	ticker := time.NewTicker(r.cacheTTL)
	defer ticker.Stop()
	for {
		select {
		case <-r.done:
			return
		case now := <-ticker.C:
			r.cacheMu.Lock()
			for k, exp := range r.cache {
				if now.After(exp) {
					delete(r.cache, k)
				}
			}
			r.cacheMu.Unlock()

			r.reqMu.Lock()
			for k, exp := range r.requester {
				if now.After(exp) {
					delete(r.requester, k)
				}
			}
			r.reqMu.Unlock()
		}
	}
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
