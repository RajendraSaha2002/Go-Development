package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Cross-platform compatibility constants for raw socket creation.
// On Linux, AF_PACKET = 17 and ETH_P_ALL = 0x0003.
const (
	afPacket = 17
	ethPAll  = 0x0003
)

// ============================================================================
// 1. HAND-WRITTEN PROTOCOL PARSERS (ETHERNET, IPV4, TCP, UDP, DNS)
// ============================================================================

type EthernetFrame struct {
	DstMAC    net.HardwareAddr
	SrcMAC    net.HardwareAddr
	EtherType uint16
	Payload   []byte
}

func ParseEthernet(data []byte) (*EthernetFrame, error) {
	if len(data) < 14 {
		return nil, fmt.Errorf("ethernet frame too short: %d bytes", len(data))
	}
	return &EthernetFrame{
		DstMAC:    net.HardwareAddr(data[0:6]),
		SrcMAC:    net.HardwareAddr(data[6:12]),
		EtherType: binary.BigEndian.Uint16(data[12:14]),
		Payload:   data[14:],
	}, nil
}

type IPv4Header struct {
	Version  uint8
	IHL      uint8
	TOS      uint8
	TotalLen uint16
	ID       uint16
	Flags    uint8
	TTL      uint8
	Protocol uint8
	Checksum uint16
	SrcIP    net.IP
	DstIP    net.IP
	Payload  []byte
}

func ParseIPv4(data []byte) (*IPv4Header, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("ipv4 packet too short: %d bytes", len(data))
	}
	version := data[0] >> 4
	if version != 4 {
		return nil, fmt.Errorf("unsupported IP version: %d", version)
	}
	ihl := (data[0] & 0x0F) * 4
	if len(data) < int(ihl) {
		return nil, fmt.Errorf("invalid ipv4 IHL: %d", ihl)
	}
	totalLen := binary.BigEndian.Uint16(data[2:4])
	if int(totalLen) > len(data) {
		totalLen = uint16(len(data))
	}

	return &IPv4Header{
		Version:  version,
		IHL:      ihl,
		TOS:      data[1],
		TotalLen: totalLen,
		ID:       binary.BigEndian.Uint16(data[4:6]),
		Flags:    data[6] >> 5,
		TTL:      data[8],
		Protocol: data[9],
		Checksum: binary.BigEndian.Uint16(data[10:12]),
		SrcIP:    net.IP(data[12:16]),
		DstIP:    net.IP(data[16:20]),
		Payload:  data[ihl:totalLen],
	}, nil
}

type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8
	Flags      uint8
	Window     uint16
	Checksum   uint16
	Urgent     uint16
	Payload    []byte
}

const (
	TCPFlagFIN = 0x01
	TCPFlagSYN = 0x02
	TCPFlagRST = 0x04
	TCPFlagPSH = 0x08
	TCPFlagACK = 0x10
	TCPFlagURG = 0x20
)

func ParseTCP(data []byte) (*TCPHeader, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("tcp segment too short: %d bytes", len(data))
	}
	offset := (data[12] >> 4) * 4
	if len(data) < int(offset) {
		return nil, fmt.Errorf("invalid tcp data offset: %d", offset)
	}

	return &TCPHeader{
		SrcPort:    binary.BigEndian.Uint16(data[0:2]),
		DstPort:    binary.BigEndian.Uint16(data[2:4]),
		SeqNum:     binary.BigEndian.Uint32(data[4:8]),
		AckNum:     binary.BigEndian.Uint32(data[8:12]),
		DataOffset: offset,
		Flags:      data[13],
		Window:     binary.BigEndian.Uint16(data[14:16]),
		Checksum:   binary.BigEndian.Uint16(data[16:18]),
		Urgent:     binary.BigEndian.Uint16(data[18:20]),
		Payload:    data[offset:],
	}, nil
}

type UDPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
	Payload  []byte
}

func ParseUDP(data []byte) (*UDPHeader, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("udp datagram too short: %d bytes", len(data))
	}
	length := binary.BigEndian.Uint16(data[4:6])
	if int(length) > len(data) {
		length = uint16(len(data))
	}
	return &UDPHeader{
		SrcPort:  binary.BigEndian.Uint16(data[0:2]),
		DstPort:  binary.BigEndian.Uint16(data[2:4]),
		Length:   length,
		Checksum: binary.BigEndian.Uint16(data[6:8]),
		Payload:  data[8:length],
	}, nil
}

type DNSQuery struct {
	Name  string
	QType uint16
}

type DNSHeader struct {
	ID        uint16
	Flags     uint16
	QDCount   uint16
	ANCount   uint16
	Questions []DNSQuery
}

func ParseDNS(data []byte) (*DNSHeader, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("dns message too short: %d bytes", len(data))
	}
	dns := &DNSHeader{
		ID:      binary.BigEndian.Uint16(data[0:2]),
		Flags:   binary.BigEndian.Uint16(data[2:4]),
		QDCount: binary.BigEndian.Uint16(data[4:6]),
		ANCount: binary.BigEndian.Uint16(data[6:8]),
	}

	offset := 12
	for i := 0; i < int(dns.QDCount) && offset < len(data); i++ {
		var nameParts []string
		for offset < len(data) {
			length := int(data[offset])
			offset++
			if length == 0 {
				break
			}
			if offset+length > len(data) {
				return dns, nil
			}
			nameParts = append(nameParts, string(data[offset:offset+length]))
			offset += length
		}
		if offset+4 <= len(data) {
			qtype := binary.BigEndian.Uint16(data[offset : offset+2])
			offset += 4 // Skip QType & QClass
			dns.Questions = append(dns.Questions, DNSQuery{
				Name:  strings.Join(nameParts, "."),
				QType: qtype,
			})
		}
	}
	return dns, nil
}

// ============================================================================
// 2. SHANNON ENTROPY ANOMALY DETECTOR
// ============================================================================

// Calculates empirical Shannon entropy: H(X) = -SUM(p(x) * log2(p(x)))
// Scores range from 0.0 (uniform) to 8.0 (completely random / encrypted)
func CalculateShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}
	var frequencies [256]int
	for _, b := range data {
		frequencies[b]++
	}

	entropy := 0.0
	total := float64(len(data))
	for _, count := range frequencies {
		if count == 0 {
			continue
		}
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// ============================================================================
// 3. FLOW TRACKER, PORT-SCAN DETECTOR & IDS ALERTS
// ============================================================================

type FlowKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Proto   string
}

type FlowStats struct {
	Key        FlowKey
	FirstSeen  time.Time
	LastSeen   time.Time
	Packets    uint64
	Bytes      uint64
	AvgEntropy float64
	LastFlags  uint8
}

type Alert struct {
	Timestamp   time.Time
	Severity    string // "INFO", "WARN", "CRIT"
	Type        string
	SourceIP    string
	Destination string
	Description string
}

type PortScanTracker struct {
	mu           sync.Mutex
	scannedPorts map[string]map[uint16]time.Time // srcIP -> dstPort -> lastSeen
}

func NewPortScanTracker() *PortScanTracker {
	return &PortScanTracker{
		scannedPorts: make(map[string]map[uint16]time.Time),
	}
}

func (pst *PortScanTracker) Record(srcIP string, dstPort uint16) int {
	pst.mu.Lock()
	defer pst.mu.Unlock()

	now := time.Now()
	ports, exists := pst.scannedPorts[srcIP]
	if !exists {
		ports = make(map[uint16]time.Time)
		pst.scannedPorts[srcIP] = ports
	}

	// Purge probes older than 5 seconds (sliding window)
	for p, t := range ports {
		if now.Sub(t) > 5*time.Second {
			delete(ports, p)
		}
	}
	ports[dstPort] = now
	return len(ports)
}

type AnalysisEngine struct {
	mu           sync.RWMutex
	flows        map[FlowKey]*FlowStats
	portScanner  *PortScanTracker
	alerts       []Alert
	totalPackets uint64
	totalBytes   uint64
	protoTCP     uint64
	protoUDP     uint64
	protoDNS     uint64
	protoOther   uint64
}

func NewAnalysisEngine() *AnalysisEngine {
	return &AnalysisEngine{
		flows:       make(map[FlowKey]*FlowStats),
		portScanner: NewPortScanTracker(),
		alerts:      make([]Alert, 0),
	}
}

func (ae *AnalysisEngine) AddAlert(severity, alertType, src, dst, desc string) {
	ae.mu.Lock()
	defer ae.mu.Unlock()
	alert := Alert{
		Timestamp:   time.Now(),
		Severity:    severity,
		Type:        alertType,
		SourceIP:    src,
		Destination: dst,
		Description: desc,
	}
	ae.alerts = append(ae.alerts, alert)
	if len(ae.alerts) > 8 {
		ae.alerts = ae.alerts[1:]
	}
}

func (ae *AnalysisEngine) ProcessPacket(raw []byte) {
	eth, err := ParseEthernet(raw)
	if err != nil || eth.EtherType != 0x0800 {
		return
	}

	ip, err := ParseIPv4(eth.Payload)
	if err != nil {
		return
	}

	ae.mu.Lock()
	ae.totalPackets++
	ae.totalBytes += uint64(len(raw))
	ae.mu.Unlock()

	srcIPStr := ip.SrcIP.String()
	dstIPStr := ip.DstIP.String()

	switch ip.Protocol {
	case 6: // TCP
		ae.mu.Lock()
		ae.protoTCP++
		ae.mu.Unlock()

		tcp, err := ParseTCP(ip.Payload)
		if err != nil {
			return
		}

		key := FlowKey{
			SrcIP: srcIPStr, DstIP: dstIPStr,
			SrcPort: tcp.SrcPort, DstPort: tcp.DstPort,
			Proto: "TCP",
		}
		entropy := CalculateShannonEntropy(tcp.Payload)
		ae.updateFlow(key, uint64(len(raw)), entropy, tcp.Flags)

		// 1. Port Scan Detection (SYN without ACK)
		if (tcp.Flags&TCPFlagSYN != 0) && (tcp.Flags&TCPFlagACK == 0) {
			probeCount := ae.portScanner.Record(srcIPStr, tcp.DstPort)
			if probeCount >= 8 {
				ae.AddAlert("CRIT", "PORT_SCAN_DETECTED", srcIPStr,
					fmt.Sprintf("%s:%d", dstIPStr, tcp.DstPort),
					fmt.Sprintf("Horizontal/Vertical probe: %d ports probed within 5s", probeCount))
			}
		}

		// 2. High-Entropy Payload Anomaly (C2 Beacon, Encrypted Shellcode)
		if len(tcp.Payload) > 48 && entropy > 7.35 {
			ae.AddAlert("WARN", "HIGH_ENTROPY_TCP", srcIPStr,
				fmt.Sprintf("%s:%d", dstIPStr, tcp.DstPort),
				fmt.Sprintf("High entropy payload (H=%.2f/8.00, size=%dB). Possible encrypted exfiltration",
					entropy, len(tcp.Payload)))
		}

	case 17: // UDP
		ae.mu.Lock()
		ae.protoUDP++
		ae.mu.Unlock()

		udp, err := ParseUDP(ip.Payload)
		if err != nil {
			return
		}

		key := FlowKey{
			SrcIP: srcIPStr, DstIP: dstIPStr,
			SrcPort: udp.SrcPort, DstPort: udp.DstPort,
			Proto: "UDP",
		}
		entropy := CalculateShannonEntropy(udp.Payload)
		ae.updateFlow(key, uint64(len(raw)), entropy, 0)

		// 3. DNS Inspection (Port 53)
		if udp.DstPort == 53 || udp.SrcPort == 53 {
			ae.mu.Lock()
			ae.protoDNS++
			ae.mu.Unlock()

			dns, err := ParseDNS(udp.Payload)
			if err == nil {
				for _, q := range dns.Questions {
					// Suspiciously long or high-entropy subdomain (DNS Tunneling)
					qEntropy := CalculateShannonEntropy([]byte(q.Name))
					if len(q.Name) > 42 || qEntropy > 4.4 {
						ae.AddAlert("WARN", "DNS_TUNNEL_ANOMALY", srcIPStr, q.Name,
							fmt.Sprintf("Suspicious query length (%d) or entropy (H=%.2f)", len(q.Name), qEntropy))
					}
				}
			}
		}
	default:
		ae.mu.Lock()
		ae.protoOther++
		ae.mu.Unlock()
	}
}

func (ae *AnalysisEngine) updateFlow(key FlowKey, bytes uint64, entropy float64, flags uint8) {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	flow, exists := ae.flows[key]
	now := time.Now()
	if !exists {
		ae.flows[key] = &FlowStats{
			Key:        key,
			FirstSeen:  now,
			LastSeen:   now,
			Packets:    1,
			Bytes:      bytes,
			AvgEntropy: entropy,
			LastFlags:  flags,
		}
		return
	}
	flow.LastSeen = now
	flow.Packets++
	flow.Bytes += bytes
	flow.AvgEntropy = (flow.AvgEntropy * 0.8) + (entropy * 0.2)
	flow.LastFlags = flags
}

// ============================================================================
// 4. LIVE TERMINAL DASHBOARD (ANSI CODES)
// ============================================================================

func RenderDashboard(ae *AnalysisEngine, isSynthetic bool, captureRate float64) {
	ae.mu.RLock()
	defer ae.mu.RUnlock()

	// Clear Screen and Move Cursor to Home (0,0)
	fmt.Print("\033[2J\033[H")

	// ANSI Colors
	cyan := "\033[1;36m"
	white := "\033[1;37m"
	gray := "\033[0;90m"
	green := "\033[1;32m"
	yellow := "\033[1;33m"
	red := "\033[1;31m"
	reset := "\033[0m"

	modeStr := green + "RAW_SOCKET (AF_PACKET/ETH_P_ALL)" + reset
	if isSynthetic {
		modeStr = yellow + "SIMULATION_FALLBACK (WINDOWS/MAC/NON-ROOT)" + reset
	}

	fmt.Printf("%s====================================================================================================%s\n", cyan, reset)
	fmt.Printf("%s GO-IDS: REAL-TIME PACKET ANALYZER & THREAT DETECTION DASHBOARD %s[%s]%s\n", cyan, white, modeStr, cyan)
	fmt.Printf("%s====================================================================================================%s\n", cyan, reset)

	// Summary Stats
	fmt.Printf(" %sTotal Packets:%s %-10d | %sTotal Traffic:%s %-9.2f MB | %sCapture Rate:%s %-6.1f pkt/s\n",
		white, reset, ae.totalPackets,
		white, reset, float64(ae.totalBytes)/(1024*1024),
		white, reset, captureRate)
	fmt.Printf(" %sProtocols:%s TCP: %s%d%s | UDP: %s%d%s | DNS: %s%d%s | Other: %s%d%s\n",
		white, reset,
		green, ae.protoTCP, reset,
		green, ae.protoUDP, reset,
		green, ae.protoDNS, reset,
		gray, ae.protoOther, reset)

	// Live Threat Alerts Panel
	fmt.Printf("\n%s[%s INTRUSION DETECTION ALERTS & ANOMALIES %s]%s\n", gray, red, gray, reset)
	fmt.Printf("%s%-8s | %-20s | %-16s | %-24s | %s%s\n",
		gray, "SEV", "THREAT TYPE", "SOURCE IP", "TARGET/DOMAIN", "DETAILS", reset)
	fmt.Println(strings.Repeat("-", 100))

	if len(ae.alerts) == 0 {
		fmt.Printf(" %sNo critical network security alerts triggered. Traffic nominal.%s\n", gray, reset)
	} else {
		for i := len(ae.alerts) - 1; i >= 0; i-- {
			a := ae.alerts[i]
			sevColor := yellow
			if a.Severity == "CRIT" {
				sevColor = red
			}
			fmt.Printf("%s%-8s%s | %-20s | %-16s | %-24s | %s\n",
				sevColor, a.Severity, reset,
				a.Type,
				a.SourceIP,
				a.Destination,
				a.Description)
		}
	}

	// Active Flow Tracker Panel
	fmt.Printf("\n%s[%s ACTIVE 5-TUPLE NETWORK FLOWS (TOP RECENT) %s]%s\n", gray, cyan, gray, reset)
	fmt.Printf("%s%-5s | %-21s | %-21s | %-8s | %-9s | %s%s\n",
		gray, "PROTO", "SOURCE IP:PORT", "DESTINATION IP:PORT", "PACKETS", "BYTES", "ENTROPY (0-8)", reset)
	fmt.Println(strings.Repeat("-", 100))

	type sortedFlow struct {
		k FlowKey
		f *FlowStats
	}
	var flowList []sortedFlow
	for k, v := range ae.flows {
		flowList = append(flowList, sortedFlow{k, v})
	}
	sort.Slice(flowList, func(i, j int) bool {
		return flowList[i].f.LastSeen.After(flowList[j].f.LastSeen)
	})

	maxRows := 6
	if len(flowList) < maxRows {
		maxRows = len(flowList)
	}
	for i := 0; i < maxRows; i++ {
		fl := flowList[i].f
		src := fmt.Sprintf("%s:%d", fl.Key.SrcIP, fl.Key.SrcPort)
		dst := fmt.Sprintf("%s:%d", fl.Key.DstIP, fl.Key.DstPort)

		entropyColor := green
		if fl.AvgEntropy > 7.0 {
			entropyColor = red
		} else if fl.AvgEntropy > 5.0 {
			entropyColor = yellow
		}

		fmt.Printf("%-5s | %-21s | %-21s | %-8d | %-9d | %s%5.2f / 8.00%s\n",
			fl.Key.Proto,
			src,
			dst,
			fl.Packets,
			fl.Bytes,
			entropyColor, fl.AvgEntropy, reset)
	}
	fmt.Printf("%s====================================================================================================%s\n", cyan, reset)
	fmt.Printf(" %sPress [Ctrl+C] to stop capture and restore console.%s\n", gray, reset)
}

// ============================================================================
// 5. PACKET INJECTOR FOR FALLBACK / TEST HARNESS
// ============================================================================

func craftSyntheticPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, flags uint8, payload []byte, isDNS bool) []byte {
	buf := new(bytes.Buffer)

	// 1. Ethernet Header (14 bytes)
	buf.Write([]byte{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E})   // Dst MAC
	buf.Write([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})   // Src MAC
	_ = binary.Write(buf, binary.BigEndian, uint16(0x0800)) // EtherType IPv4

	// 2. IPv4 Header (20 bytes)
	proto := uint8(6) // TCP
	if isDNS || flags == 0 {
		proto = 17 // UDP
	}
	ipLen := uint16(20 + 20 + len(payload))
	if proto == 17 {
		ipLen = uint16(20 + 8 + len(payload))
	}

	buf.WriteByte(0x45) // Ver 4, IHL 5
	buf.WriteByte(0x00) // TOS
	_ = binary.Write(buf, binary.BigEndian, ipLen)
	_ = binary.Write(buf, binary.BigEndian, uint16(1234))
	_ = binary.Write(buf, binary.BigEndian, uint16(0)) // Flags & Offset
	buf.WriteByte(64)                                  // TTL
	buf.WriteByte(proto)
	_ = binary.Write(buf, binary.BigEndian, uint16(0)) // Checksum
	buf.Write(srcIP.To4())
	buf.Write(dstIP.To4())

	// 3. Transport Layer
	if proto == 6 {
		// TCP (20 bytes)
		_ = binary.Write(buf, binary.BigEndian, srcPort)
		_ = binary.Write(buf, binary.BigEndian, dstPort)
		_ = binary.Write(buf, binary.BigEndian, uint32(1000))
		_ = binary.Write(buf, binary.BigEndian, uint32(0))
		buf.WriteByte(0x50) // Data offset 5 (20 bytes)
		buf.WriteByte(flags)
		_ = binary.Write(buf, binary.BigEndian, uint16(65535)) // Window
		_ = binary.Write(buf, binary.BigEndian, uint16(0))     // Checksum
		_ = binary.Write(buf, binary.BigEndian, uint16(0))     // Urgent
		buf.Write(payload)
	} else {
		// UDP (8 bytes)
		_ = binary.Write(buf, binary.BigEndian, srcPort)
		_ = binary.Write(buf, binary.BigEndian, dstPort)
		_ = binary.Write(buf, binary.BigEndian, uint16(8+len(payload)))
		_ = binary.Write(buf, binary.BigEndian, uint16(0))
		buf.Write(payload)
	}

	return buf.Bytes()
}

func startSyntheticTraffic(pktChan chan<- []byte, stopChan <-chan struct{}) {
	ticker := time.NewTicker(40 * time.Millisecond)
	defer ticker.Stop()

	scanPorts := []uint16{21, 22, 23, 25, 80, 443, 445, 1433, 3306, 3389, 8080}
	scanIdx := 0

	for {
		select {
		case <-stopChan:
			return
		case <-ticker.C:
			// Normal Web Traffic
			pktChan <- craftSyntheticPacket(
				net.IPv4(192, 168, 1, 45), net.IPv4(93, 184, 216, 34),
				54321, 443, TCPFlagACK, []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"), false,
			)

			// Threat 1: SYN Port Scan from External Attacker
			targetPort := scanPorts[scanIdx%len(scanPorts)]
			scanIdx++
			pktChan <- craftSyntheticPacket(
				net.IPv4(45, 33, 32, 156), net.IPv4(192, 168, 1, 10),
				uint16(40000+scanIdx), targetPort, TCPFlagSYN, nil, false,
			)

			// Threat 2: High-Entropy Encrypted C2 Beacon Exfiltration
			highEntropyData := make([]byte, 128)
			_, _ = rand.Read(highEntropyData)
			pktChan <- craftSyntheticPacket(
				net.IPv4(192, 168, 1, 89), net.IPv4(185, 220, 101, 5),
				49152, 9001, TCPFlagPSH|TCPFlagACK, highEntropyData, false,
			)

			// Threat 3: DNS Tunneling Anomaly
			var dnsPayload bytes.Buffer
			_ = binary.Write(&dnsPayload, binary.BigEndian, uint16(0xAAAA)) // ID
			_ = binary.Write(&dnsPayload, binary.BigEndian, uint16(0x0100)) // Standard Query
			_ = binary.Write(&dnsPayload, binary.BigEndian, uint16(1))      // 1 Question
			_ = binary.Write(&dnsPayload, binary.BigEndian, uint16(0))      // 0 Answer
			sub := "exfiltrated-secret-data-payload-chunk-999"
			dnsPayload.WriteByte(byte(len(sub)))
			dnsPayload.WriteString(sub)
			dnsPayload.WriteByte(byte(len("attacker-c2")))
			dnsPayload.WriteString("attacker-c2")
			dnsPayload.WriteByte(byte(len("net")))
			dnsPayload.WriteString("net")
			dnsPayload.WriteByte(0)
			_ = binary.Write(&dnsPayload, binary.BigEndian, uint16(1)) // Type A
			_ = binary.Write(&dnsPayload, binary.BigEndian, uint16(1)) // Class IN

			pktChan <- craftSyntheticPacket(
				net.IPv4(192, 168, 1, 89), net.IPv4(8, 8, 8, 8),
				61234, 53, 0, dnsPayload.Bytes(), true,
			)
		}
	}
}

// ============================================================================
// 6. MAIN ENGINE, RAW SOCKET CAPTURE & EVENT LOOP
// ============================================================================

func htons(v uint16) int {
	return int((v << 8) | (v >> 8))
}

func main() {
	// Hide terminal cursor on start
	fmt.Print("\033[?25l")

	// Ensure terminal cursor is restored on exit (Ctrl+C)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	defer fmt.Print("\033[?25h\n")

	engine := NewAnalysisEngine()
	packetChan := make(chan []byte, 1000)
	stopChan := make(chan struct{})

	// 1. Attempt Raw Socket Capture
	// afPacket (17) is used directly so this compiles on both Windows and Linux without error.
	rawFD, err := syscall.Socket(afPacket, syscall.SOCK_RAW, htons(ethPAll))
	isSynthetic := false

	if err != nil {
		// On Windows or without Linux root permissions, fall back to the synthetic packet generator
		isSynthetic = true
		go startSyntheticTraffic(packetChan, stopChan)
	} else {
		defer syscall.Close(rawFD)
		// Linux Raw Socket Capture Worker
		go func() {
			buf := make([]byte, 65535)
			for {
				select {
				case <-stopChan:
					return
				default:
					n, _, err := syscall.Recvfrom(rawFD, buf, 0)
					if err != nil {
						continue
					}
					pktCopy := make([]byte, n)
					copy(pktCopy, buf[:n])
					packetChan <- pktCopy
				}
			}
		}()
	}

	// 2. Packet Processing Worker Loop
	go func() {
		for pkt := range packetChan {
			engine.ProcessPacket(pkt)
		}
	}()

	// 3. UI Dashboard Rendering Loop (4 FPS)
	renderTicker := time.NewTicker(250 * time.Millisecond)
	defer renderTicker.Stop()

	var lastPackets uint64
	lastTime := time.Now()
	captureRate := 0.0

	for {
		select {
		case <-sigChan:
			close(stopChan)
			fmt.Print("\033[2J\033[H\033[?25h")
			fmt.Println("Analysis Engine halted. Terminal state restored.")
			return

		case now := <-renderTicker.C:
			engine.mu.RLock()
			currentPackets := engine.totalPackets
			engine.mu.RUnlock()

			elapsed := now.Sub(lastTime).Seconds()
			if elapsed >= 0.25 {
				captureRate = float64(currentPackets-lastPackets) / elapsed
				lastPackets = currentPackets
				lastTime = now
			}
			RenderDashboard(engine, isSynthetic, captureRate)
		}
	}
}
