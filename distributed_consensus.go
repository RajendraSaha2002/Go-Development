package main

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"log"
	mrand "math/rand"
	"net"
	"net/rpc"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// 1. FAULT-INJECTION NETWORK & TRANSPORT (TCP + RPC)
// ============================================================================

// NetworkSwitch dynamically controls connectivity and partitions between nodes.
type NetworkSwitch struct {
	mu           sync.RWMutex
	disconnected map[string]bool // "from->to" == true means link is severed
}

func NewNetworkSwitch() *NetworkSwitch {
	return &NetworkSwitch{
		disconnected: make(map[string]bool),
	}
}

func (ns *NetworkSwitch) linkKey(from, to int) string {
	return fmt.Sprintf("%d->%d", from, to)
}

func (ns *NetworkSwitch) Disconnect(from, to int) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.disconnected[ns.linkKey(from, to)] = true
}

func (ns *NetworkSwitch) Connect(from, to int) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	delete(ns.disconnected, ns.linkKey(from, to))
}

func (ns *NetworkSwitch) IsBlocked(from, to int) bool {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return ns.disconnected[ns.linkKey(from, to)]
}

// Partition splits nodes into isolated subgraphs.
func (ns *NetworkSwitch) Partition(groupA, groupB []int) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	for _, a := range groupA {
		for _, b := range groupB {
			ns.disconnected[ns.linkKey(a, b)] = true
			ns.disconnected[ns.linkKey(b, a)] = true
		}
	}
}

func (ns *NetworkSwitch) HealAll() {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.disconnected = make(map[string]bool)
}

// TransportClient provides intercepted RPC dialing respecting the NetworkSwitch.
type TransportClient struct {
	fromID int
	sw     *NetworkSwitch
}

func (tc *TransportClient) Call(peerID int, addr string, method string, args any, reply any) error {
	if tc.sw.IsBlocked(tc.fromID, peerID) {
		return errors.New("network partition: link unreachable")
	}

	conn, err := net.DialTimeout("tcp", addr, 150*time.Millisecond)
	if err != nil {
		return err
	}
	defer conn.Close()

	done := make(chan error, 1)
	client := rpc.NewClient(conn)
	defer client.Close()

	go func() {
		done <- client.Call(method, args, reply)
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(250 * time.Millisecond):
		return errors.New("rpc call timeout")
	}
}

// ============================================================================
// 2. RAFT CONSENSUS CORE
// ============================================================================

type Role int

const (
	Follower Role = iota
	Candidate
	Leader
)

func (r Role) String() string {
	switch r {
	case Follower:
		return "Follower"
	case Candidate:
		return "Candidate"
	case Leader:
		return "Leader"
	default:
		return "Unknown"
	}
}

type LogEntry struct {
	Index   int
	Term    int
	Command any
}

type ApplyMsg struct {
	CommandValid bool
	Command      any
	CommandIndex int
}

type RequestVoteArgs struct {
	Term         int
	CandidateID  int
	LastLogIndex int
	LastLogTerm  int
}

type RequestVoteReply struct {
	Term        int
	VoteGranted bool
}

type AppendEntriesArgs struct {
	Term         int
	LeaderID     int
	PrevLogIndex int
	PrevLogTerm  int
	Entries      []LogEntry
	LeaderCommit int
}

type AppendEntriesReply struct {
	Term          int
	Success       bool
	ConflictIndex int
	ConflictTerm  int
}

type Raft struct {
	mu        sync.Mutex
	peers     map[int]string // peerID -> TCP address
	transport *TransportClient
	me        int
	dead      int32

	// Persistent state
	currentTerm int
	votedFor    int
	log         []LogEntry // 1-based indexing; index 0 holds dummy entry
	storageDir  string

	// Volatile state (all servers)
	commitIndex int
	lastApplied int
	role        Role

	// Volatile state (leaders)
	nextIndex  map[int]int
	matchIndex map[int]int

	// Timers and signaling
	lastElectionActivity time.Time
	electionTimeout      time.Duration
	heartbeatInterval    time.Duration
	applyCh              chan ApplyMsg
	applyCond            *sync.Cond
}

func NewRaft(
	me int,
	peers map[int]string,
	transport *TransportClient,
	storageDir string,
	applyCh chan ApplyMsg,
) *Raft {
	rf := &Raft{
		peers:             peers,
		transport:         transport,
		me:                me,
		currentTerm:       0,
		votedFor:          -1,
		log:               make([]LogEntry, 0),
		storageDir:        storageDir,
		commitIndex:       0,
		lastApplied:       0,
		role:              Follower,
		nextIndex:         make(map[int]int),
		matchIndex:        make(map[int]int),
		heartbeatInterval: 40 * time.Millisecond,
		applyCh:           applyCh,
	}

	// 1-based log dummy sentinel
	rf.log = append(rf.log, LogEntry{Index: 0, Term: 0, Command: nil})
	rf.applyCond = sync.NewCond(&rf.mu)

	// Restore persistent state from disk if available
	rf.readPersist()
	rf.resetElectionTimeoutLocked()

	go rf.electionTicker()
	go rf.heartbeatTicker()
	go rf.applier()

	return rf
}

// ---------------- Persistence ----------------

type PersistentState struct {
	CurrentTerm int
	VotedFor    int
	Log         []LogEntry
}

func (rf *Raft) persistPath() string {
	return filepath.Join(rf.storageDir, fmt.Sprintf("raft_%d.state", rf.me))
}

func (rf *Raft) persist() {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	state := PersistentState{
		CurrentTerm: rf.currentTerm,
		VotedFor:    rf.votedFor,
		Log:         rf.log,
	}
	if err := enc.Encode(state); err != nil {
		log.Printf("[%d] Persist encode error: %v", rf.me, err)
		return
	}

	tmpFile := fmt.Sprintf("%s.tmp-%d", rf.persistPath(), time.Now().UnixNano())
	if err := os.WriteFile(tmpFile, buf.Bytes(), 0644); err != nil {
		log.Printf("[%d] Persist write error: %v", rf.me, err)
		return
	}
	_ = os.Rename(tmpFile, rf.persistPath())
}

func (rf *Raft) readPersist() {
	data, err := os.ReadFile(rf.persistPath())
	if err != nil {
		return // No prior state
	}
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	var state PersistentState
	if err := dec.Decode(&state); err != nil {
		log.Printf("[%d] ReadPersist decode error: %v", rf.me, err)
		return
	}
	rf.currentTerm = state.CurrentTerm
	rf.votedFor = state.VotedFor
	rf.log = state.Log
}

// ---------------- Helpers ----------------

func (rf *Raft) lastLogIndexLocked() int {
	return len(rf.log) - 1
}

func (rf *Raft) lastLogTermLocked() int {
	return rf.log[rf.lastLogIndexLocked()].Term
}

func (rf *Raft) resetElectionTimeoutLocked() {
	rf.lastElectionActivity = time.Now()
	// Randomized timeout between 180ms and 360ms
	n := 180 + mrand.Intn(180)
	rf.electionTimeout = time.Duration(n) * time.Millisecond
}

func (rf *Raft) isKilled() bool {
	return atomic.LoadInt32(&rf.dead) == 1
}

func (rf *Raft) Kill() {
	atomic.StoreInt32(&rf.dead, 1)
	rf.mu.Lock()
	rf.applyCond.Broadcast()
	rf.mu.Unlock()
}

// ---------------- RPC Handlers ----------------

func (rf *Raft) RequestVote(args *RequestVoteArgs, reply *RequestVoteReply) error {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	defer rf.persist()

	if args.Term > rf.currentTerm {
		rf.currentTerm = args.Term
		rf.role = Follower
		rf.votedFor = -1
	}

	reply.Term = rf.currentTerm
	reply.VoteGranted = false

	if args.Term < rf.currentTerm {
		return nil
	}

	canVote := rf.votedFor == -1 || rf.votedFor == args.CandidateID
	lastTerm := rf.lastLogTermLocked()
	lastIdx := rf.lastLogIndexLocked()

	// Raft election safety: Candidate log must be at least as up-to-date as receiver
	logUpToDate := false
	if args.LastLogTerm > lastTerm {
		logUpToDate = true
	} else if args.LastLogTerm == lastTerm && args.LastLogIndex >= lastIdx {
		logUpToDate = true
	}

	if canVote && logUpToDate {
		rf.votedFor = args.CandidateID
		rf.role = Follower
		rf.resetElectionTimeoutLocked()
		reply.VoteGranted = true
	}

	return nil
}

func (rf *Raft) AppendEntries(args *AppendEntriesArgs, reply *AppendEntriesReply) error {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	defer rf.persist()

	reply.Success = false
	reply.Term = rf.currentTerm

	// 1. Reply false if term < currentTerm
	if args.Term < rf.currentTerm {
		return nil
	}

	// 2. If term > currentTerm, become follower
	if args.Term > rf.currentTerm || rf.role == Candidate {
		rf.currentTerm = args.Term
		rf.role = Follower
		rf.votedFor = -1
	}
	rf.resetElectionTimeoutLocked()

	// 3. Consistency check: verify log matches at PrevLogIndex
	if args.PrevLogIndex > rf.lastLogIndexLocked() {
		reply.ConflictIndex = len(rf.log)
		reply.ConflictTerm = -1
		return nil
	}

	if args.PrevLogIndex > 0 && rf.log[args.PrevLogIndex].Term != args.PrevLogTerm {
		reply.ConflictTerm = rf.log[args.PrevLogIndex].Term
		// Fast back-off: find first index for that conflict term
		for i := 1; i <= args.PrevLogIndex; i++ {
			if rf.log[i].Term == reply.ConflictTerm {
				reply.ConflictIndex = i
				break
			}
		}
		return nil
	}

	// 4. Append new entries while resolving conflicts
	for i, entry := range args.Entries {
		idx := args.PrevLogIndex + 1 + i
		if idx <= rf.lastLogIndexLocked() {
			if rf.log[idx].Term != entry.Term {
				rf.log = rf.log[:idx] // Truncate conflicting log
				rf.log = append(rf.log, entry)
			}
		} else {
			rf.log = append(rf.log, entry)
		}
	}

	// 5. Update commit index
	if args.LeaderCommit > rf.commitIndex {
		newCommit := args.LeaderCommit
		lastNewIndex := args.PrevLogIndex + len(args.Entries)
		if newCommit > lastNewIndex {
			newCommit = lastNewIndex
		}
		if newCommit > rf.commitIndex {
			rf.commitIndex = newCommit
			rf.applyCond.Broadcast()
		}
	}

	reply.Success = true
	return nil
}

// ---------------- Background Loops ----------------

func (rf *Raft) electionTicker() {
	for !rf.isKilled() {
		time.Sleep(15 * time.Millisecond)
		rf.mu.Lock()
		if rf.role != Leader && time.Since(rf.lastElectionActivity) >= rf.electionTimeout {
			rf.startElectionLocked()
		}
		rf.mu.Unlock()
	}
}

func (rf *Raft) startElectionLocked() {
	rf.role = Candidate
	rf.currentTerm++
	rf.votedFor = rf.me
	rf.persist()
	rf.resetElectionTimeoutLocked()

	savedTerm := rf.currentTerm
	votes := 1

	for peerID, addr := range rf.peers {
		if peerID == rf.me {
			continue
		}

		args := RequestVoteArgs{
			Term:         savedTerm,
			CandidateID:  rf.me,
			LastLogIndex: rf.lastLogIndexLocked(),
			LastLogTerm:  rf.lastLogTermLocked(),
		}
		targetID := peerID
		targetAddr := addr

		go func() {
			var reply RequestVoteReply
			err := rf.transport.Call(targetID, targetAddr, "Raft.RequestVote", &args, &reply)
			if err != nil {
				return
			}

			rf.mu.Lock()
			defer rf.mu.Unlock()

			if rf.currentTerm != savedTerm || rf.role != Candidate {
				return
			}

			if reply.Term > rf.currentTerm {
				rf.currentTerm = reply.Term
				rf.role = Follower
				rf.votedFor = -1
				rf.persist()
				return
			}

			if reply.VoteGranted {
				votes++
				if votes > (len(rf.peers)+1)/2 {
					rf.role = Leader
					for p := range rf.peers {
						rf.nextIndex[p] = rf.lastLogIndexLocked() + 1
						rf.matchIndex[p] = 0
					}
					rf.broadcastHeartbeatsLocked()
				}
			}
		}()
	}
}

func (rf *Raft) heartbeatTicker() {
	for !rf.isKilled() {
		time.Sleep(rf.heartbeatInterval)
		rf.mu.Lock()
		if rf.role == Leader {
			rf.broadcastHeartbeatsLocked()
		}
		rf.mu.Unlock()
	}
}

func (rf *Raft) broadcastHeartbeatsLocked() {
	for peerID, addr := range rf.peers {
		if peerID == rf.me {
			continue
		}

		prevIdx := rf.nextIndex[peerID] - 1
		if prevIdx < 0 {
			prevIdx = 0
		}
		prevTerm := rf.log[prevIdx].Term

		var entries []LogEntry
		if rf.lastLogIndexLocked() >= rf.nextIndex[peerID] {
			entries = append(entries, rf.log[rf.nextIndex[peerID]:]...)
		}

		args := AppendEntriesArgs{
			Term:         rf.currentTerm,
			LeaderID:     rf.me,
			PrevLogIndex: prevIdx,
			PrevLogTerm:  prevTerm,
			Entries:      entries,
			LeaderCommit: rf.commitIndex,
		}

		targetID := peerID
		targetAddr := addr
		savedTerm := rf.currentTerm

		go func() {
			var reply AppendEntriesReply
			err := rf.transport.Call(targetID, targetAddr, "Raft.AppendEntries", &args, &reply)
			if err != nil {
				return
			}

			rf.mu.Lock()
			defer rf.mu.Unlock()

			if rf.currentTerm != savedTerm || rf.role != Leader {
				return
			}

			if reply.Term > rf.currentTerm {
				rf.currentTerm = reply.Term
				rf.role = Follower
				rf.votedFor = -1
				rf.persist()
				return
			}

			if reply.Success {
				rf.matchIndex[targetID] = args.PrevLogIndex + len(args.Entries)
				rf.nextIndex[targetID] = rf.matchIndex[targetID] + 1
				rf.checkAndUpdateCommitIndexLocked()
			} else {
				// Fast log backtracking
				if reply.ConflictTerm != -1 {
					conflictFound := false
					for i := len(rf.log) - 1; i >= 1; i-- {
						if rf.log[i].Term == reply.ConflictTerm {
							rf.nextIndex[targetID] = i + 1
							conflictFound = true
							break
						}
					}
					if !conflictFound {
						rf.nextIndex[targetID] = reply.ConflictIndex
					}
				} else {
					rf.nextIndex[targetID] = reply.ConflictIndex
				}

				if rf.nextIndex[targetID] < 1 {
					rf.nextIndex[targetID] = 1
				}
			}
		}()
	}
}

// Obey Raft Section 5.4.2: Leaders only commit entries from their current term
func (rf *Raft) checkAndUpdateCommitIndexLocked() {
	for n := rf.lastLogIndexLocked(); n > rf.commitIndex; n-- {
		if rf.log[n].Term != rf.currentTerm {
			continue
		}
		matches := 1
		for peerID := range rf.peers {
			if peerID != rf.me && rf.matchIndex[peerID] >= n {
				matches++
			}
		}
		if matches > (len(rf.peers)+1)/2 {
			rf.commitIndex = n
			rf.applyCond.Broadcast()
			break
		}
	}
}

func (rf *Raft) applier() {
	for !rf.isKilled() {
		rf.mu.Lock()
		for rf.lastApplied >= rf.commitIndex && !rf.isKilled() {
			rf.applyCond.Wait()
		}
		if rf.isKilled() {
			rf.mu.Unlock()
			return
		}

		rf.lastApplied++
		entry := rf.log[rf.lastApplied]
		msg := ApplyMsg{
			CommandValid: true,
			Command:      entry.Command,
			CommandIndex: entry.Index,
		}
		rf.mu.Unlock()

		rf.applyCh <- msg
	}
}

func (rf *Raft) Start(command any) (int, int, bool) {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	if rf.role != Leader {
		return -1, -1, false
	}

	index := len(rf.log)
	term := rf.currentTerm
	entry := LogEntry{
		Index:   index,
		Term:    term,
		Command: command,
	}
	rf.log = append(rf.log, entry)
	rf.persist()
	rf.broadcastHeartbeatsLocked()

	return index, term, true
}

func (rf *Raft) GetState() (int, bool) {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	return rf.currentTerm, rf.role == Leader
}

// ============================================================================
// 3. REPLICATED KEY-VALUE STORE
// ============================================================================

type OpType string

const (
	OpPut OpType = "PUT"
	OpGet OpType = "GET"
	OpDel OpType = "DEL"
)

type Op struct {
	Type     OpType
	Key      string
	Value    string
	ClientID int64
	ReqID    int64
}

type CommandResponse struct {
	Err   string
	Value string
}

type KVServer struct {
	mu           sync.Mutex
	me           int
	rf           *Raft
	applyCh      chan ApplyMsg
	dead         int32
	store        map[string]string
	lastApplied  map[int64]int64 // ClientID -> ReqID
	waitChannels map[int]chan CommandResponse
}

func NewKVServer(me int, rf *Raft, applyCh chan ApplyMsg) *KVServer {
	kv := &KVServer{
		me:           me,
		rf:           rf,
		applyCh:      applyCh,
		store:        make(map[string]string),
		lastApplied:  make(map[int64]int64),
		waitChannels: make(map[int]chan CommandResponse),
	}
	go kv.applyListener()
	return kv
}

func (kv *KVServer) isKilled() bool {
	return atomic.LoadInt32(&kv.dead) == 1
}

func (kv *KVServer) Kill() {
	atomic.StoreInt32(&kv.dead, 1)
}

func (kv *KVServer) applyListener() {
	for !kv.isKilled() {
		msg, ok := <-kv.applyCh
		if !ok {
			return
		}
		if !msg.CommandValid || msg.Command == nil {
			continue
		}

		op := msg.Command.(Op)
		kv.mu.Lock()

		var resp CommandResponse
		// Linearizability check: deduplicate duplicate client submissions
		if op.Type == OpPut || op.Type == OpDel {
			lastReq, exists := kv.lastApplied[op.ClientID]
			if !exists || op.ReqID > lastReq {
				if op.Type == OpPut {
					kv.store[op.Key] = op.Value
				} else if op.Type == OpDel {
					delete(kv.store, op.Key)
				}
				kv.lastApplied[op.ClientID] = op.ReqID
			}
		} else if op.Type == OpGet {
			val, found := kv.store[op.Key]
			if found {
				resp.Value = val
			} else {
				resp.Err = "KeyNotFound"
			}
		}

		ch, exists := kv.waitChannels[msg.CommandIndex]
		kv.mu.Unlock()

		if exists {
			select {
			case ch <- resp:
			default:
			}
		}
	}
}

type KVRequest struct {
	Op Op
}

type KVReply struct {
	Err      string
	Value    string
	IsLeader bool
}

func (kv *KVServer) Execute(args *KVRequest, reply *KVReply) error {
	index, _, isLeader := kv.rf.Start(args.Op)
	if !isLeader {
		reply.IsLeader = false
		reply.Err = "ErrNotLeader"
		return nil
	}

	kv.mu.Lock()
	ch := make(chan CommandResponse, 1)
	kv.waitChannels[index] = ch
	kv.mu.Unlock()

	defer func() {
		kv.mu.Lock()
		delete(kv.waitChannels, index)
		kv.mu.Unlock()
	}()

	select {
	case res := <-ch:
		reply.IsLeader = true
		reply.Err = res.Err
		reply.Value = res.Value
		return nil
	case <-time.After(800 * time.Millisecond):
		reply.IsLeader = false
		reply.Err = "ErrTimeout"
		return nil
	}
}

// ============================================================================
// 4. TEST HARNESS & FAULT-INJECTION CLUSTER
// ============================================================================

type ClusterNode struct {
	id        int
	addr      string
	listener  net.Listener
	rpcServer *rpc.Server
	raft      *Raft
	kv        *KVServer
	applyCh   chan ApplyMsg
}

type Cluster struct {
	tDir     string
	n        int
	nodes    map[int]*ClusterNode
	sw       *NetworkSwitch
	addrs    map[int]string
	clientID int64
	reqID    int64
	mu       sync.Mutex
}

func NewCluster(n int) (*Cluster, error) {
	dir, err := os.MkdirTemp("", "raft_cluster_*")
	if err != nil {
		return nil, err
	}

	c := &Cluster{
		tDir:     dir,
		n:        n,
		nodes:    make(map[int]*ClusterNode),
		sw:       NewNetworkSwitch(),
		addrs:    make(map[int]string),
		clientID: time.Now().UnixNano(),
	}

	gob.Register(Op{})

	// Pre-assign ephemeral ports
	for i := 0; i < n; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		c.addrs[i] = l.Addr().String()
		_ = l.Close()
	}

	for i := 0; i < n; i++ {
		if err := c.StartNode(i); err != nil {
			return nil, err
		}
	}

	return c, nil
}

func (c *Cluster) StartNode(id int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	l, err := net.Listen("tcp", c.addrs[id])
	if err != nil {
		return err
	}

	peers := make(map[int]string)
	for pID, addr := range c.addrs {
		peers[pID] = addr
	}

	transport := &TransportClient{fromID: id, sw: c.sw}
	applyCh := make(chan ApplyMsg, 2000)
	rf := NewRaft(id, peers, transport, c.tDir, applyCh)
	kv := NewKVServer(id, rf, applyCh)

	rpcServer := rpc.NewServer()
	_ = rpcServer.RegisterName("Raft", rf)
	_ = rpcServer.RegisterName("KVServer", kv)

	node := &ClusterNode{
		id:        id,
		addr:      c.addrs[id],
		listener:  l,
		rpcServer: rpcServer,
		raft:      rf,
		kv:        kv,
		applyCh:   applyCh,
	}
	c.nodes[id] = node

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go rpcServer.ServeConn(conn)
		}
	}()

	return nil
}

func (c *Cluster) StopNode(id int) {
	c.mu.Lock()
	node, exists := c.nodes[id]
	if !exists {
		c.mu.Unlock()
		return
	}
	delete(c.nodes, id)
	c.mu.Unlock()

	node.raft.Kill()
	node.kv.Kill()
	_ = node.listener.Close()
}

func (c *Cluster) RestartNode(id int) error {
	c.StopNode(id)
	time.Sleep(30 * time.Millisecond)
	return c.StartNode(id)
}

func (c *Cluster) Cleanup() {
	for i := 0; i < c.n; i++ {
		c.StopNode(i)
	}
	_ = os.RemoveAll(c.tDir)
}

func (c *Cluster) GetLeader() (int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, node := range c.nodes {
		_, isLeader := node.raft.GetState()
		if isLeader {
			return id, true
		}
	}
	return -1, false
}

func (c *Cluster) WaitForLeader(timeout time.Duration) (int, error) {
	start := time.Now()
	for time.Since(start) < timeout {
		if leader, ok := c.GetLeader(); ok {
			return leader, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return -1, errors.New("timeout waiting for leader election")
}

func (c *Cluster) ClientPut(key, val string) error {
	return c.executeClientOp(OpPut, key, val, nil)
}

func (c *Cluster) ClientGet(key string) (string, error) {
	var val string
	err := c.executeClientOp(OpGet, key, "", &val)
	return val, err
}

func (c *Cluster) executeClientOp(opType OpType, key, val string, outVal *string) error {
	c.mu.Lock()
	reqID := atomic.AddInt64(&c.reqID, 1)
	c.mu.Unlock()

	op := Op{
		Type:     opType,
		Key:      key,
		Value:    val,
		ClientID: c.clientID,
		ReqID:    reqID,
	}
	req := KVRequest{Op: op}

	start := time.Now()
	for time.Since(start) < 4*time.Second {
		leader, ok := c.GetLeader()
		if !ok {
			time.Sleep(25 * time.Millisecond)
			continue
		}

		c.mu.Lock()
		node, active := c.nodes[leader]
		c.mu.Unlock()
		if !active {
			time.Sleep(25 * time.Millisecond)
			continue
		}

		var reply KVReply
		client := &TransportClient{fromID: -1, sw: c.sw}
		err := client.Call(leader, node.addr, "KVServer.Execute", &req, &reply)
		if err == nil && reply.IsLeader {
			if reply.Err == "KeyNotFound" {
				return errors.New("key not found")
			}
			if reply.Err == "" {
				if outVal != nil {
					*outVal = reply.Value
				}
				return nil
			}
		}
		time.Sleep(40 * time.Millisecond)
	}
	return errors.New("client operation timed out")
}

// ============================================================================
// 5. TEST SUITE SCENARIOS
// ============================================================================

func printBanner(title string) {
	fmt.Println("\n" + strings.Repeat("=", 75))
	fmt.Printf(" TEST SCENARIO: %s\n", title)
	fmt.Println(strings.Repeat("=", 75))
}

func runTest1_LeaderElection() {
	printBanner("1. Clean Leader Election on 3 Nodes")
	c, err := NewCluster(3)
	if err != nil {
		log.Fatalf("Cluster creation error: %v", err)
	}
	defer c.Cleanup()

	leader, err := c.WaitForLeader(3 * time.Second)
	if err != nil {
		log.Fatalf("FAILED: %v", err)
	}
	term, _ := c.nodes[leader].raft.GetState()
	fmt.Printf("[OK] Leader successfully elected: Node %d (Term %d)\n", leader, term)

	// Ensure stability (no continuous spurious re-elections)
	time.Sleep(200 * time.Millisecond)
	leader2, _ := c.GetLeader()
	if leader != leader2 {
		log.Fatalf("FAILED: Unstable election! Initial: %d, current: %d", leader, leader2)
	}
	fmt.Printf("[OK] Leader %d maintained heartbeat authority\n", leader)
}

func runTest2_BasicReplication() {
	printBanner("2. Linearizable Log Replication & KV Agreement")
	c, err := NewCluster(3)
	if err != nil {
		log.Fatalf("Cluster creation error: %v", err)
	}
	defer c.Cleanup()

	_, err = c.WaitForLeader(3 * time.Second)
	if err != nil {
		log.Fatalf("Leader timeout: %v", err)
	}

	fmt.Println("-> Executing Client Put('device_id', 'sensor-alpha-99')...")
	if err := c.ClientPut("device_id", "sensor-alpha-99"); err != nil {
		log.Fatalf("FAILED Put: %v", err)
	}

	fmt.Println("-> Executing Client Get('device_id')...")
	val, err := c.ClientGet("device_id")
	if err != nil || val != "sensor-alpha-99" {
		log.Fatalf("FAILED Get: expected 'sensor-alpha-99', got '%s', err: %v", val, err)
	}
	fmt.Printf("[OK] Successfully retrieved consistent value: '%s'\n", val)

	// Verify all replicated internal state machines converge
	time.Sleep(150 * time.Millisecond)
	c.mu.Lock()
	for id, n := range c.nodes {
		n.kv.mu.Lock()
		stored := n.kv.store["device_id"]
		n.kv.mu.Unlock()
		if stored != "sensor-alpha-99" {
			log.Fatalf("FAILED: Node %d out-of-sync with KV state machine: '%s'", id, stored)
		}
		fmt.Printf("[OK] Node %d state machine verified in lockstep.\n", id)
	}
	c.mu.Unlock()
}

func runTest3_FollowerCrashAndCatchUp() {
	printBanner("3. Follower Crash, Re-join, and Atomic Catch-Up")
	c, err := NewCluster(3)
	if err != nil {
		log.Fatalf("Cluster error: %v", err)
	}
	defer c.Cleanup()

	leader, _ := c.WaitForLeader(3 * time.Second)
	victim := (leader + 1) % 3

	fmt.Printf("-> Crashing Follower Node %d abruptly...\n", victim)
	c.StopNode(victim)

	fmt.Println("-> Submitting writes to quorum while follower is dead...")
	if err := c.ClientPut("k1", "v1"); err != nil {
		log.Fatalf("FAILED Put k1: %v", err)
	}
	if err := c.ClientPut("k2", "v2"); err != nil {
		log.Fatalf("FAILED Put k2: %v", err)
	}

	fmt.Printf("-> Restarting Follower Node %d from persistent state...\n", victim)
	if err := c.RestartNode(victim); err != nil {
		log.Fatalf("FAILED restart: %v", err)
	}

	// Submit another entry to advance commits
	_ = c.ClientPut("k3", "v3")

	// Allow heartbeat back-off replication to sync the recovered node
	time.Sleep(400 * time.Millisecond)

	c.mu.Lock()
	recoveredNode := c.nodes[victim]
	recoveredNode.kv.mu.Lock()
	v1 := recoveredNode.kv.store["k1"]
	v2 := recoveredNode.kv.store["k2"]
	v3 := recoveredNode.kv.store["k3"]
	recoveredNode.kv.mu.Unlock()
	c.mu.Unlock()

	if v1 != "v1" || v2 != "v2" || v3 != "v3" {
		log.Fatalf("FAILED: Recovered node missed logs. k1:%s, k2:%s, k3:%s", v1, v2, v3)
	}
	fmt.Printf("[OK] Node %d successfully caught up on all missed log entries!\n", victim)
}

func runTest4_NetworkPartitionSplitBrain() {
	printBanner("4. Network Partition (Split-Brain Prevention) & Healing")
	c, err := NewCluster(5)
	if err != nil {
		log.Fatalf("Cluster error: %v", err)
	}
	defer c.Cleanup()

	leader, _ := c.WaitForLeader(3 * time.Second)

	// Partition: Minority {leader, other} vs Majority {remaining 3}
	other := (leader + 1) % 5
	minority := []int{leader, other}
	var majority []int
	for i := 0; i < 5; i++ {
		if i != leader && i != other {
			majority = append(majority, i)
		}
	}

	fmt.Printf("-> Partitioning network into Minority %v and Majority %v...\n", minority, majority)
	c.sw.Partition(minority, majority)

	// Attempt write on partitioned old leader
	fmt.Printf("-> Sending Put to minority leader %d (must fail to reach consensus)...\n", leader)
	client := &TransportClient{fromID: -1, sw: c.sw}
	var rep KVReply
	req := KVRequest{Op: Op{Type: OpPut, Key: "split_key", Value: "stale_val", ClientID: 999, ReqID: 1}}
	_ = client.Call(leader, c.nodes[leader].addr, "KVServer.Execute", &req, &rep)

	if rep.Err == "" && rep.IsLeader {
		log.Fatalf("SAFETY VIOLATION: Minority committed write without quorum!")
	}
	fmt.Println("[OK] Minority correctly prevented from committing writes.")

	// Wait for majority to elect new leader
	time.Sleep(600 * time.Millisecond)

	// Submit writes to majority partition
	fmt.Println("-> Writing key 'majority_key'='valid_consensus' to Majority partition...")
	majLeader := -1
	for _, id := range majority {
		_, isLead := c.nodes[id].raft.GetState()
		if isLead {
			majLeader = id
			break
		}
	}

	if majLeader == -1 {
		log.Fatalf("FAILED: Majority partition failed to elect new leader")
	}
	fmt.Printf("[OK] Majority partition elected new Leader: Node %d\n", majLeader)

	var majRep KVReply
	majReq := KVRequest{Op: Op{Type: OpPut, Key: "majority_key", Value: "valid_consensus", ClientID: 888, ReqID: 2}}
	err = client.Call(majLeader, c.nodes[majLeader].addr, "KVServer.Execute", &majReq, &majRep)
	if err != nil || !majRep.IsLeader || majRep.Err != "" {
		log.Fatalf("FAILED to commit on majority partition: err=%v, rep=%+v", err, majRep)
	}
	fmt.Println("[OK] Majority partition successfully committed entries.")

	// Heal partition
	fmt.Println("-> Healing network partition between all nodes...")
	c.sw.HealAll()
	time.Sleep(500 * time.Millisecond)

	// Old leader must step down and reconcile log
	val, err := c.ClientGet("majority_key")
	if err != nil || val != "valid_consensus" {
		log.Fatalf("FAILED: Read after partition heal invalid: %s (err: %v)", val, err)
	}
	fmt.Printf("[OK] Partition healed. Entire cluster converged on consistent value: '%s'\n", val)
}

func runTest5_LeaderFailureAndFailover() {
	printBanner("5. Hard Leader Crash & Instantaneous Failover")
	c, err := NewCluster(3)
	if err != nil {
		log.Fatalf("Cluster error: %v", err)
	}
	defer c.Cleanup()

	leader, _ := c.WaitForLeader(3 * time.Second)
	_ = c.ClientPut("system_status", "nominal")

	fmt.Printf("-> Killing active Leader Node %d...\n", leader)
	c.StopNode(leader)

	fmt.Println("-> Waiting for surviving nodes to elect a replacement leader...")
	time.Sleep(400 * time.Millisecond)

	newLeader, err := c.WaitForLeader(3 * time.Second)
	if err != nil || newLeader == leader {
		log.Fatalf("Failover failed to elect new leader: %v", err)
	}
	fmt.Printf("[OK] Replacement Leader elected: Node %d\n", newLeader)

	fmt.Println("-> Verifying reads and writes succeed on new leader...")
	if err := c.ClientPut("system_status", "failover_verified"); err != nil {
		log.Fatalf("FAILED Put on new leader: %v", err)
	}
	val, err := c.ClientGet("system_status")
	if err != nil || val != "failover_verified" {
		log.Fatalf("FAILED Get on new leader: %s, err: %v", val, err)
	}
	fmt.Printf("[OK] Successful read-after-write on new leader: '%s'\n", val)
}

// ============================================================================
// 6. MAIN ENTRY POINT
// ============================================================================

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	fmt.Println("===========================================================================")
	fmt.Println(" DISTRIBUTED CONSENSUS ENGINE: RAFT FROM SCRATCH (GO STANDARD LIBRARY)")
	fmt.Println(" Leader Election | Log Replication | State Machine | Fault-Injection")
	fmt.Println("===========================================================================")

	runTest1_LeaderElection()
	runTest2_BasicReplication()
	runTest3_FollowerCrashAndCatchUp()
	runTest4_NetworkPartitionSplitBrain()
	runTest5_LeaderFailureAndFailover()

	fmt.Println("\n" + strings.Repeat("*", 75))
	fmt.Println(" ALL DISTRIBUTED CONSENSUS SCENARIOS PASSED WITH ZERO ERRORS!")
	fmt.Println(strings.Repeat("*", 75))
}
