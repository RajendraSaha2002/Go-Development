package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"math"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ============================================================================
// 1. CONSTANTS, VECTOR MATH & PROTOCOL FRAMING
// ============================================================================

const (
	ServerTickRate         = 60 // 60 Hz (16.66ms per tick)
	TickDuration           = time.Second / ServerTickRate
	WorldWidth     float32 = 800.0
	WorldHeight    float32 = 600.0
	PlayerRadius   float32 = 16.0
	PlayerSpeed    float32 = 240.0 // Units per second
	BulletMaxDist  float32 = 600.0
	HistorySize            = 128 // ~2.1 seconds of rewind history at 60 Hz

	// Packet Types
	PacketConnect        uint8 = 0x01
	PacketConnectAck     uint8 = 0x02
	PacketClientInput    uint8 = 0x03
	PacketServerSnapshot uint8 = 0x04
	PacketHitEvent       uint8 = 0x05
	PacketDisconnect     uint8 = 0x06
)

type Vec2 struct {
	X float32
	Y float32
}

func (v Vec2) Add(o Vec2) Vec2    { return Vec2{v.X + o.X, v.Y + o.Y} }
func (v Vec2) Sub(o Vec2) Vec2    { return Vec2{v.X - o.X, v.Y - o.Y} }
func (v Vec2) Mul(s float32) Vec2 { return Vec2{v.X * s, v.Y * s} }
func (v Vec2) Len() float32       { return float32(math.Hypot(float64(v.X), float64(v.Y))) }
func (v Vec2) Normalize() Vec2 {
	l := v.Len()
	if l < 0.0001 {
		return Vec2{0, 0}
	}
	return Vec2{v.X / l, v.Y / l}
}

// Ray-Circle intersection for hitscan weapons
func RayIntersectsCircle(origin, dir Vec2, center Vec2, radius float32, maxDist float32) (bool, float32) {
	d := dir.Normalize()
	m := origin.Sub(center)
	b := m.X*d.X + m.Y*d.Y
	c := (m.X*m.X + m.Y*m.Y) - (radius * radius)

	if c > 0.0 && b > 0.0 {
		return false, 0
	}
	discr := b*b - c
	if discr < 0.0 {
		return false, 0
	}
	t := -b - float32(math.Sqrt(float64(discr)))
	if t < 0.0 {
		t = 0.0
	}
	if t <= maxDist {
		return true, t
	}
	return false, 0
}

// Sequence wrap-around safe comparison (RFC 1982)
func SequenceGreaterThan(s1, s2 uint16) bool {
	return ((s1 > s2) && (s1-s2 <= 32768)) || ((s1 < s2) && (s2-s1 > 32768))
}

// ============================================================================
// 2. RELIABILITY LAYER OVER UDP (ACK BITFIELD & RTT)
// ============================================================================

type ReliabilityLayer struct {
	localSeq    uint16
	remoteSeq   uint16
	ackBitfield uint32
	rttMs       float32
	mu          sync.Mutex
}

func NewReliabilityLayer() *ReliabilityLayer {
	return &ReliabilityLayer{}
}

func (r *ReliabilityLayer) NextSequence() uint16 {
	r.mu.Lock()
	defer r.mu.Unlock()
	seq := r.localSeq
	r.localSeq++
	return seq
}

func (r *ReliabilityLayer) ProcessIncomingHeader(seq, ack uint16, ackBits uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if SequenceGreaterThan(seq, r.remoteSeq) {
		shift := seq - r.remoteSeq
		if shift <= 32 {
			r.ackBitfield = (r.ackBitfield << shift) | (1 << (shift - 1))
		} else {
			r.ackBitfield = 0
		}
		r.remoteSeq = seq
	} else {
		diff := r.remoteSeq - seq
		if diff <= 32 && diff > 0 {
			r.ackBitfield |= 1 << (diff - 1)
		}
	}
}

func (r *ReliabilityLayer) WriteHeader(buf *bytes.Buffer, packetType uint8) {
	r.mu.Lock()
	seq := r.localSeq
	r.localSeq++
	ack := r.remoteSeq
	ackBits := r.ackBitfield
	r.mu.Unlock()

	_ = binary.Write(buf, binary.LittleEndian, seq)
	_ = binary.Write(buf, binary.LittleEndian, ack)
	_ = binary.Write(buf, binary.LittleEndian, ackBits)
	buf.WriteByte(packetType)
}

// ============================================================================
// 3. GAME STATE STRUCTURES & SERIALIZATION
// ============================================================================

type PlayerState struct {
	ID       uint32
	Pos      Vec2
	Rot      float32
	Health   int16
	Score    int16
	LastSeen time.Time
}

type UserCmd struct {
	InputTick  uint32
	TargetTick uint32 // Client's viewed tick for server-side lag compensation
	MoveDir    Vec2
	AimAngle   float32
	Buttons    uint8 // Bit 0: Fire
}

type WorldSnapshot struct {
	Tick    uint32
	Players []PlayerState
}

// Binary serialization routines
func SerializeUserCmd(buf *bytes.Buffer, cmd UserCmd) {
	_ = binary.Write(buf, binary.LittleEndian, cmd.InputTick)
	_ = binary.Write(buf, binary.LittleEndian, cmd.TargetTick)
	_ = binary.Write(buf, binary.LittleEndian, cmd.MoveDir.X)
	_ = binary.Write(buf, binary.LittleEndian, cmd.MoveDir.Y)
	_ = binary.Write(buf, binary.LittleEndian, cmd.AimAngle)
	buf.WriteByte(cmd.Buttons)
}

func DeserializeUserCmd(r *bytes.Reader) (UserCmd, error) {
	var cmd UserCmd
	if err := binary.Read(r, binary.LittleEndian, &cmd.InputTick); err != nil {
		return cmd, err
	}
	_ = binary.Read(r, binary.LittleEndian, &cmd.TargetTick)
	_ = binary.Read(r, binary.LittleEndian, &cmd.MoveDir.X)
	_ = binary.Read(r, binary.LittleEndian, &cmd.MoveDir.Y)
	_ = binary.Read(r, binary.LittleEndian, &cmd.AimAngle)
	cmd.Buttons, _ = r.ReadByte()
	return cmd, nil
}

func SerializeSnapshot(buf *bytes.Buffer, tick uint32, lastAckTick uint32, players []PlayerState) {
	_ = binary.Write(buf, binary.LittleEndian, tick)
	_ = binary.Write(buf, binary.LittleEndian, lastAckTick)
	_ = binary.Write(buf, binary.LittleEndian, uint16(len(players)))
	for _, p := range players {
		_ = binary.Write(buf, binary.LittleEndian, p.ID)
		_ = binary.Write(buf, binary.LittleEndian, p.Pos.X)
		_ = binary.Write(buf, binary.LittleEndian, p.Pos.Y)
		_ = binary.Write(buf, binary.LittleEndian, p.Rot)
		_ = binary.Write(buf, binary.LittleEndian, p.Health)
		_ = binary.Write(buf, binary.LittleEndian, p.Score)
	}
}

func DeserializeSnapshot(r *bytes.Reader) (uint32, uint32, []PlayerState, error) {
	var tick, lastAckTick uint32
	var count uint16
	if err := binary.Read(r, binary.LittleEndian, &tick); err != nil {
		return 0, 0, nil, err
	}
	_ = binary.Read(r, binary.LittleEndian, &lastAckTick)
	_ = binary.Read(r, binary.LittleEndian, &count)

	players := make([]PlayerState, count)
	for i := 0; i < int(count); i++ {
		_ = binary.Read(r, binary.LittleEndian, &players[i].ID)
		_ = binary.Read(r, binary.LittleEndian, &players[i].Pos.X)
		_ = binary.Read(r, binary.LittleEndian, &players[i].Pos.Y)
		_ = binary.Read(r, binary.LittleEndian, &players[i].Rot)
		_ = binary.Read(r, binary.LittleEndian, &players[i].Health)
		_ = binary.Read(r, binary.LittleEndian, &players[i].Score)
	}
	return tick, lastAckTick, players, nil
}

// ============================================================================
// 4. AUTHORITATIVE SERVER WITH LAG COMPENSATION (REWIND)
// ============================================================================

type RemoteClient struct {
	ID                 uint32
	Addr               *net.UDPAddr
	Reliability        *ReliabilityLayer
	LastProcessedInput uint32
	PendingCmds        []UserCmd
	State              PlayerState
}

type Server struct {
	conn            *net.UDPConn
	clients         map[uint32]*RemoteClient
	addrToID        map[string]uint32
	history         [HistorySize]WorldSnapshot
	currentTick     uint32
	nextPlayerID    uint32
	mu              sync.RWMutex
	stopChan        chan struct{}
	totalRewindHits uint64
	totalShotsFired uint64
}

func NewServer(bindAddr string) (*Server, error) {
	addr, err := net.ResolveUDPAddr("udp", bindAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	return &Server{
		conn:         conn,
		clients:      make(map[uint32]*RemoteClient),
		addrToID:     make(map[string]uint32),
		currentTick:  1,
		nextPlayerID: 100,
		stopChan:     make(chan struct{}),
	}, nil
}

func (s *Server) Start() {
	go s.listenWorker()
	go s.tickWorker()
}

func (s *Server) Stop() {
	close(s.stopChan)
	if s.conn != nil {
		_ = s.conn.Close()
	}
}

func (s *Server) listenWorker() {
	buf := make([]byte, 2048)
	for {
		select {
		case <-s.stopChan:
			return
		default:
			n, raddr, err := s.conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			s.handlePacket(buf[:n], raddr)
		}
	}
}

func (s *Server) handlePacket(data []byte, raddr *net.UDPAddr) {
	if len(data) < 11 { // Header size: 2 (Seq) + 2 (Ack) + 4 (AckBits) + 1 (Type)
		return
	}
	r := bytes.NewReader(data)
	var seq, ack uint16
	var ackBits uint32
	_ = binary.Read(r, binary.LittleEndian, &seq)
	_ = binary.Read(r, binary.LittleEndian, &ack)
	_ = binary.Read(r, binary.LittleEndian, &ackBits)
	pType, _ := r.ReadByte()

	addrKey := raddr.String()

	s.mu.Lock()
	defer s.mu.Unlock()

	client, exists := s.clients[s.addrToID[addrKey]]

	switch pType {
	case PacketConnect:
		if !exists {
			pid := s.nextPlayerID
			s.nextPlayerID++
			client = &RemoteClient{
				ID:          pid,
				Addr:        raddr,
				Reliability: NewReliabilityLayer(),
				State: PlayerState{
					ID:       pid,
					Pos:      Vec2{X: 100.0 + float32(rand.Intn(600)), Y: 100.0 + float32(rand.Intn(400))},
					Health:   100,
					LastSeen: time.Now(),
				},
			}
			s.clients[pid] = client
			s.addrToID[addrKey] = pid
		}

		// Reply ConnectAck
		var resp bytes.Buffer
		client.Reliability.WriteHeader(&resp, PacketConnectAck)
		_ = binary.Write(&resp, binary.LittleEndian, client.ID)
		_ = binary.Write(&resp, binary.LittleEndian, s.currentTick)
		_, _ = s.conn.WriteToUDP(resp.Bytes(), raddr)

	case PacketClientInput:
		if !exists {
			return
		}
		client.Reliability.ProcessIncomingHeader(seq, ack, ackBits)
		client.State.LastSeen = time.Now()

		var cmdCount uint8
		_ = binary.Read(r, binary.LittleEndian, &cmdCount)
		for i := 0; i < int(cmdCount); i++ {
			cmd, err := DeserializeUserCmd(r)
			if err == nil && cmd.InputTick > client.LastProcessedInput {
				client.PendingCmds = append(client.PendingCmds, cmd)
			}
		}
	}
}

func (s *Server) tickWorker() {
	ticker := time.NewTicker(TickDuration)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			s.updateTick()
		}
	}
}

func (s *Server) updateTick() {
	s.mu.Lock()
	defer s.mu.Unlock()

	dt := float32(TickDuration.Seconds())
	now := time.Now()

	// 1. Process inputs & move players authoritatively
	for _, client := range s.clients {
		if now.Sub(client.State.LastSeen) > 3*time.Second {
			// Disconnect timed-out clients
			delete(s.addrToID, client.Addr.String())
			delete(s.clients, client.ID)
			continue
		}

		// Sort commands by tick
		sort.Slice(client.PendingCmds, func(i, j int) bool {
			return client.PendingCmds[i].InputTick < client.PendingCmds[j].InputTick
		})

		for _, cmd := range client.PendingCmds {
			// Update movement
			dir := cmd.MoveDir.Normalize()
			client.State.Pos.X += dir.X * PlayerSpeed * dt
			client.State.Pos.Y += dir.Y * PlayerSpeed * dt
			client.State.Rot = cmd.AimAngle

			// Arena boundary clamp
			if client.State.Pos.X < PlayerRadius {
				client.State.Pos.X = PlayerRadius
			}
			if client.State.Pos.X > WorldWidth-PlayerRadius {
				client.State.Pos.X = WorldWidth - PlayerRadius
			}
			if client.State.Pos.Y < PlayerRadius {
				client.State.Pos.Y = PlayerRadius
			}
			if client.State.Pos.Y > WorldHeight-PlayerRadius {
				client.State.Pos.Y = WorldHeight - PlayerRadius
			}

			// Process shooting with Lag Compensation (Server Rewind)
			if (cmd.Buttons & 1) != 0 {
				atomic.AddUint64(&s.totalShotsFired, 1)
				s.executeLagCompensatedShot(client, cmd)
			}

			client.LastProcessedInput = cmd.InputTick
		}
		client.PendingCmds = nil
	}

	// 2. Record historical snapshot in circular buffer
	snapIndex := s.currentTick % HistorySize
	currentSnap := WorldSnapshot{
		Tick:    s.currentTick,
		Players: make([]PlayerState, 0, len(s.clients)),
	}
	for _, client := range s.clients {
		currentSnap.Players = append(currentSnap.Players, client.State)
	}
	s.history[snapIndex] = currentSnap

	// 3. Broadcast snapshot to all clients
	for _, client := range s.clients {
		var buf bytes.Buffer
		client.Reliability.WriteHeader(&buf, PacketServerSnapshot)
		SerializeSnapshot(&buf, s.currentTick, client.LastProcessedInput, currentSnap.Players)
		_, _ = s.conn.WriteToUDP(buf.Bytes(), client.Addr)
	}

	s.currentTick++
}

// Server-side Lag Compensation (Rewinds victim positions to Client's TargetTick)
func (s *Server) executeLagCompensatedShot(shooter *RemoteClient, cmd UserCmd) {
	targetTick := cmd.TargetTick
	maxLagTicks := uint32(HistorySize - 1)

	// Validate target tick within history horizon
	if s.currentTick-targetTick > maxLagTicks || targetTick > s.currentTick {
		targetTick = s.currentTick
	}

	// Extract historical snapshot
	histSnap := s.history[targetTick%HistorySize]
	if histSnap.Tick != targetTick {
		// Fallback to current position if unaligned
		histSnap.Players = make([]PlayerState, 0, len(s.clients))
		for _, c := range s.clients {
			histSnap.Players = append(histSnap.Players, c.State)
		}
	}

	// Raycast from shooter position
	rayOrigin := shooter.State.Pos
	rayDir := Vec2{
		X: float32(math.Cos(float64(cmd.AimAngle))),
		Y: float32(math.Sin(float64(cmd.AimAngle))),
	}

	for _, victimSnap := range histSnap.Players {
		if victimSnap.ID == shooter.ID || victimSnap.Health <= 0 {
			continue
		}

		hit, dist := RayIntersectsCircle(rayOrigin, rayDir, victimSnap.Pos, PlayerRadius, BulletMaxDist)
		if hit {
			atomic.AddUint64(&s.totalRewindHits, 1)

			// Apply damage to authoritative state
			if victim, ok := s.clients[victimSnap.ID]; ok {
				victim.State.Health -= 25
				if victim.State.Health <= 0 {
					shooter.State.Score++
					victim.State.Health = 100
					victim.State.Pos = Vec2{
						X: 100.0 + float32(rand.Intn(600)),
						Y: 100.0 + float32(rand.Intn(400)),
					}
				}

				// Broadcast reliable hit event
				for _, c := range s.clients {
					var hitBuf bytes.Buffer
					c.Reliability.WriteHeader(&hitBuf, PacketHitEvent)
					_ = binary.Write(&hitBuf, binary.LittleEndian, shooter.ID)
					_ = binary.Write(&hitBuf, binary.LittleEndian, victim.ID)
					_ = binary.Write(&hitBuf, binary.LittleEndian, dist)
					_, _ = s.conn.WriteToUDP(hitBuf.Bytes(), c.Addr)
				}
			}
			break
		}
	}
}

// ============================================================================
// 5. CLIENT-SIDE PREDICTION, RECONCILIATION & INTERPOLATION
// ============================================================================

type GameClient struct {
	conn               *net.UDPConn
	serverAddr         *net.UDPAddr
	playerID           uint32
	reliability        *ReliabilityLayer
	predictedPos       Vec2
	predictedRot       float32
	inputHistory       []UserCmd
	lastAckInputTick   uint32
	inputTickCounter   uint32
	snapshotBuffer     []WorldSnapshot
	remotePlayers      map[uint32]Vec2 // Interpolated render positions
	mu                 sync.RWMutex
	stopChan           chan struct{}
	predictionErrors   uint64
	simulatedLatencyMs int
	simulatedDropRate  float32
}

func NewGameClient(serverAddress string, simulatedLatencyMs int, dropRate float32) (*GameClient, error) {
	sAddr, err := net.ResolveUDPAddr("udp", serverAddress)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	return &GameClient{
		conn:               conn,
		serverAddr:         sAddr,
		reliability:        NewReliabilityLayer(),
		inputHistory:       make([]UserCmd, 0, 256),
		snapshotBuffer:     make([]WorldSnapshot, 0, 64),
		remotePlayers:      make(map[uint32]Vec2),
		stopChan:           make(chan struct{}),
		simulatedLatencyMs: simulatedLatencyMs,
		simulatedDropRate:  dropRate,
	}, nil
}

func (c *GameClient) Start() {
	go c.listenWorker()
	// Handshake
	var buf bytes.Buffer
	c.reliability.WriteHeader(&buf, PacketConnect)
	_, _ = c.conn.WriteToUDP(buf.Bytes(), c.serverAddr)
}

func (c *GameClient) Stop() {
	close(c.stopChan)
	if c.conn != nil {
		_ = c.conn.Close()
	}
}

func (c *GameClient) listenWorker() {
	buf := make([]byte, 2048)
	for {
		select {
		case <-c.stopChan:
			return
		default:
			n, _, err := c.conn.ReadFromUDP(buf)
			if err != nil {
				return
			}

			// Simulated Packet Drop
			if c.simulatedDropRate > 0 && rand.Float32() < c.simulatedDropRate {
				continue
			}

			dataCopy := make([]byte, n)
			copy(dataCopy, buf[:n])

			// Simulated Network Jitter/Latency
			if c.simulatedLatencyMs > 0 {
				go func(d []byte) {
					time.Sleep(time.Duration(c.simulatedLatencyMs) * time.Millisecond)
					c.processPacket(d)
				}(dataCopy)
			} else {
				c.processPacket(dataCopy)
			}
		}
	}
}

func (c *GameClient) processPacket(data []byte) {
	if len(data) < 11 {
		return
	}
	r := bytes.NewReader(data)
	var seq, ack uint16
	var ackBits uint32
	_ = binary.Read(r, binary.LittleEndian, &seq)
	_ = binary.Read(r, binary.LittleEndian, &ack)
	_ = binary.Read(r, binary.LittleEndian, &ackBits)
	pType, _ := r.ReadByte()

	c.reliability.ProcessIncomingHeader(seq, ack, ackBits)

	c.mu.Lock()
	defer c.mu.Unlock()

	switch pType {
	case PacketConnectAck:
		_ = binary.Read(r, binary.LittleEndian, &c.playerID)

	case PacketServerSnapshot:
		sTick, lastAckTick, players, err := DeserializeSnapshot(r)
		if err != nil {
			return
		}

		// Buffer snapshot for entity interpolation
		c.snapshotBuffer = append(c.snapshotBuffer, WorldSnapshot{Tick: sTick, Players: players})
		if len(c.snapshotBuffer) > 32 {
			c.snapshotBuffer = c.snapshotBuffer[1:]
		}

		// Perform Client-Side Prediction Reconciliation
		c.lastAckInputTick = lastAckTick
		for _, p := range players {
			if p.ID == c.playerID {
				// Authoritative server position received
				authoritativePos := p.Pos

				// Discard inputs acknowledged by server
				idx := 0
				for idx < len(c.inputHistory) && c.inputHistory[idx].InputTick <= lastAckTick {
					idx++
				}
				c.inputHistory = c.inputHistory[idx:]

				// Replay remaining unacknowledged inputs on top of authoritative base
				replayedPos := authoritativePos
				dt := float32(TickDuration.Seconds())
				for _, unacked := range c.inputHistory {
					dir := unacked.MoveDir.Normalize()
					replayedPos.X += dir.X * PlayerSpeed * dt
					replayedPos.Y += dir.Y * PlayerSpeed * dt
				}

				// Check error distance against prediction
				errDist := c.predictedPos.Sub(replayedPos).Len()
				if errDist > 2.0 { // Disagreement threshold
					c.predictedPos = replayedPos
					atomic.AddUint64(&c.predictionErrors, 1)
				}
				break
			}
		}
	}
}

// Client Tick: Predicts local movement, sends user commands, and interpolates peers
func (c *GameClient) Tick(moveDir Vec2, aimAngle float32, fire bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.inputTickCounter++
	dt := float32(TickDuration.Seconds())

	// 1. Client-Side Prediction (Move locally immediately)
	dir := moveDir.Normalize()
	c.predictedPos.X += dir.X * PlayerSpeed * dt
	c.predictedPos.Y += dir.Y * PlayerSpeed * dt
	c.predictedRot = aimAngle

	// Calculate target tick for lag compensation (Interp delay is ~100ms or 6 ticks)
	targetTick := uint32(0)
	if len(c.snapshotBuffer) > 0 {
		targetTick = c.snapshotBuffer[len(c.snapshotBuffer)-1].Tick
		if targetTick >= 6 {
			targetTick -= 6
		}
	}

	var btn uint8
	if fire {
		btn |= 1
	}

	cmd := UserCmd{
		InputTick:  c.inputTickCounter,
		TargetTick: targetTick,
		MoveDir:    dir,
		AimAngle:   aimAngle,
		Buttons:    btn,
	}
	c.inputHistory = append(c.inputHistory, cmd)

	// 2. Transmit inputs over UDP
	var buf bytes.Buffer
	c.reliability.WriteHeader(&buf, PacketClientInput)
	buf.WriteByte(1) // Sending 1 input command
	SerializeUserCmd(&buf, cmd)
	_, _ = c.conn.WriteToUDP(buf.Bytes(), c.serverAddr)

	// 3. Snapshot Interpolation for Remote Players (100ms render delay)
	c.interpolateRemotePlayers()
}

func (c *GameClient) interpolateRemotePlayers() {
	if len(c.snapshotBuffer) < 2 {
		return
	}
	// LERP between snapshot[N-2] and snapshot[N-1]
	s1 := c.snapshotBuffer[len(c.snapshotBuffer)-2]
	s2 := c.snapshotBuffer[len(c.snapshotBuffer)-1]
	alpha := float32(0.5) // Midpoint interpolation

	for _, p2 := range s2.Players {
		if p2.ID == c.playerID {
			continue
		}
		// Match corresponding player in s1
		for _, p1 := range s1.Players {
			if p1.ID == p2.ID {
				interpPos := Vec2{
					X: p1.Pos.X + (p2.Pos.X-p1.Pos.X)*alpha,
					Y: p1.Pos.Y + (p2.Pos.Y-p1.Pos.Y)*alpha,
				}
				c.remotePlayers[p2.ID] = interpPos
				break
			}
		}
	}
}

// ============================================================================
// 6. LOAD-TESTING BOT CLIENTS & LIVE TERMINAL DASHBOARD
// ============================================================================

func main() {
	port := flag.Int("port", 40000, "Server UDP port")
	botCount := flag.Int("bots", 8, "Number of autonomous simulated bot clients")
	latencyMs := flag.Int("latency", 60, "Simulated network latency in milliseconds per bot")
	dropRate := flag.Float64("drop", 0.03, "Simulated packet drop rate (0.03 = 3%)")
	flag.Parse()

	serverAddr := fmt.Sprintf("127.0.0.1:%d", *port)
	server, err := NewServer(serverAddr)
	if err != nil {
		fmt.Printf("Error starting server: %v\n", err)
		return
	}
	server.Start()
	defer server.Stop()

	fmt.Printf("[SERVER] Authoritative Game Engine running on UDP %s (Tick: 60Hz)\n", serverAddr)
	fmt.Printf("[SIMULATION] Spawning %d Load-Testing Bots (Simulated Latency: %dms, Drop Rate: %.1f%%)\n",
		*botCount, *latencyMs, *dropRate*100)

	// Spawn headless bot clients
	bots := make([]*GameClient, *botCount)
	for i := 0; i < *botCount; i++ {
		bot, err := NewGameClient(serverAddr, *latencyMs, float32(*dropRate))
		if err != nil {
			fmt.Printf("Failed to spawn bot %d: %v\n", i, err)
			continue
		}
		bot.Start()
		bots[i] = bot
		defer bot.Stop()
	}

	// Bot behavior ticker (60 Hz client tick loop)
	botTicker := time.NewTicker(TickDuration)
	defer botTicker.Stop()

	go func() {
		for range botTicker.C {
			for i, bot := range bots {
				// Autonomous wander and aim
				angle := float32(i)*0.8 + float32(time.Now().UnixNano()%1000)/1000.0*math.Pi*2
				move := Vec2{
					X: float32(math.Cos(float64(angle))),
					Y: float32(math.Sin(float64(angle))),
				}
				aimAngle := angle + math.Pi/4
				// Shoot every ~15 ticks
				fire := (time.Now().UnixNano()%15 == 0)
				bot.Tick(move, aimAngle, fire)
			}
		}
	}()

	// Terminal Dashboard Loop (4 FPS)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	renderTicker := time.NewTicker(250 * time.Millisecond)
	defer renderTicker.Stop()

	fmt.Print("\033[2J\033[H\033[?25l") // Clear screen, hide cursor
	defer fmt.Print("\033[?25h\n")      // Show cursor on exit

	for {
		select {
		case <-sigChan:
			fmt.Print("\033[2J\033[H\033[?25h")
			fmt.Println("Server halted cleanly.")
			return

		case <-renderTicker.C:
			server.mu.RLock()
			currentTick := server.currentTick
			clientCount := len(server.clients)
			totalShots := atomic.LoadUint64(&server.totalShotsFired)
			totalHits := atomic.LoadUint64(&server.totalRewindHits)

			type scoreEntry struct {
				id    uint32
				score int16
				hp    int16
				pos   Vec2
			}
			scores := make([]scoreEntry, 0, clientCount)
			for _, c := range server.clients {
				scores = append(scores, scoreEntry{
					id:    c.ID,
					score: c.State.Score,
					hp:    c.State.Health,
					pos:   c.State.Pos,
				})
			}
			server.mu.RUnlock()

			// Aggregate bot-side stats
			var totalPredErrors uint64
			for _, b := range bots {
				totalPredErrors += atomic.LoadUint64(&b.predictionErrors)
			}

			// Render ANSI Terminal Frame
			fmt.Print("\033[H")
			fmt.Println("\033[1;36m========================================================================================\033[0m")
			fmt.Println("\033[1;37m REAL-TIME MULTIPLAYER GAME SERVER: PREDICTION, INTERPOLATION & LAG COMPENSATION\033[0m")
			fmt.Println("\033[1;36m========================================================================================\033[0m")
			fmt.Printf(" Server Tick: \033[1;32m%d\033[0m | Active Players: \033[1;33m%d\033[0m | Network Tickrate: \033[1;32m60 Hz\033[0m\n",
				currentTick, clientCount)
			fmt.Printf(" Total Shots: \033[1;37m%d\033[0m | Rewind Hits Verified: \033[1;32m%d\033[0m | Hit Ratio: \033[1;33m%.1f%%\033[0m\n",
				totalShots, totalHits, float64(totalHits)/math.Max(1.0, float64(totalShots))*100.0)
			fmt.Printf(" Total Client Prediction Reconciliations: \033[1;31m%d\033[0m (Error Dist > 2.0px)\n",
				totalPredErrors)
			fmt.Println("----------------------------------------------------------------------------------------")
			fmt.Println("\033[1;34m [LIVE AUTHORITATIVE WORLD ARENA STATE]\033[0m")
			fmt.Printf(" %-12s | %-16s | %-8s | %-8s\n", "PLAYER ID", "POSITION (X, Y)", "HEALTH", "FRAGS")
			fmt.Println("----------------------------------------------------------------------------------------")

			for _, s := range scores {
				fmt.Printf(" Player #%-5d | (%6.1f, %6.1f)   | HP: %-4d | Score: %-4d\n",
					s.id, s.pos.X, s.pos.Y, s.hp, s.score)
			}

			fmt.Println("----------------------------------------------------------------------------------------")
			fmt.Println(" Press [Ctrl+C] to terminate server and simulation.")
		}
	}
}
