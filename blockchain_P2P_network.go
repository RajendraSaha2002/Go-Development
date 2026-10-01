package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	_ "os"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// 1. CRYPTOGRAPHIC SUBSYSTEM: ECDSA & LAMPORT ONE-TIME SIGNATURES (OTS)
// ============================================================================

// --- ECDSA Engine ---

type ECDSAKeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  []byte // Uncompressed bytes: 0x04 || X || Y
	Address    string // Hex encoded SHA-256 of public key
}

func GenerateECDSAKeyPair() (*ECDSAKeyPair, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pubBytes := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	addrHash := sha256.Sum256(pubBytes)
	return &ECDSAKeyPair{
		PrivateKey: priv,
		PublicKey:  pubBytes,
		Address:    hex.EncodeToString(addrHash[:20]),
	}, nil
}

func ECDSASign(priv *ecdsa.PrivateKey, msgHash []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, priv, msgHash)
	if err != nil {
		return nil, err
	}
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)
	return sig, nil
}

func ECDSAVerify(pubBytes []byte, msgHash []byte, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), pubBytes)
	if x == nil || y == nil {
		return false
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub, msgHash, r, s)
}

// --- Lamport One-Time Signature (LOTS) Engine ---
// A hash-based post-quantum signature scheme based strictly on SHA-256.
// For a 256-bit message digest:
// Private key: 256 pairs of 32-byte secret preimages (16,384 bytes).
// Public key: 256 pairs of SHA-256 hashes of preimages (16,384 bytes).
// Signature: 256 preimages corresponding to message bits (8,192 bytes).

type LamportPrivateKey struct {
	KeyPairs [256][2][32]byte
}

type LamportPublicKey struct {
	KeyPairs [256][2][32]byte
	Address  string
}

type LamportSignature struct {
	Preimages [256][32]byte
}

func GenerateLamportKeyPair() (*LamportPrivateKey, *LamportPublicKey, error) {
	var priv LamportPrivateKey
	var pub LamportPublicKey

	var pubHashBuf bytes.Buffer
	for i := 0; i < 256; i++ {
		for j := 0; j < 2; j++ {
			if _, err := rand.Read(priv.KeyPairs[i][j][:]); err != nil {
				return nil, nil, err
			}
			pub.KeyPairs[i][j] = sha256.Sum256(priv.KeyPairs[i][j][:])
			pubHashBuf.Write(pub.KeyPairs[i][j][:])
		}
	}
	addrHash := sha256.Sum256(pubHashBuf.Bytes())
	pub.Address = hex.EncodeToString(addrHash[:20])
	return &priv, &pub, nil
}

func LamportSign(priv *LamportPrivateKey, msgHash [32]byte) *LamportSignature {
	var sig LamportSignature
	for i := 0; i < 256; i++ {
		byteIndex := i / 8
		bitIndex := 7 - (i % 8)
		bit := (msgHash[byteIndex] >> bitIndex) & 1
		sig.Preimages[i] = priv.KeyPairs[i][bit]
	}
	return &sig
}

func LamportVerify(pub *LamportPublicKey, msgHash [32]byte, sig *LamportSignature) bool {
	for i := 0; i < 256; i++ {
		byteIndex := i / 8
		bitIndex := 7 - (i % 8)
		bit := (msgHash[byteIndex] >> bitIndex) & 1
		hash := sha256.Sum256(sig.Preimages[i][:])
		if hash != pub.KeyPairs[i][bit] {
			return false
		}
	}
	return true
}

func RunCryptographicComparison() {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println(" CRYPTOGRAPHIC BENCHMARK: ECDSA (secp256r1) vs. LAMPORT ONE-TIME SIGNATURES")
	fmt.Println(strings.Repeat("=", 80))

	msg := []byte("The Times 03/Jan/2009 Chancellor on brink of second bailout for banks")
	digest := sha256.Sum256(msg)

	// ECDSA Benchmark
	start := time.Now()
	ecdsaKP, _ := GenerateECDSAKeyPair()
	ecdsaKeyGenTime := time.Since(start)

	start = time.Now()
	ecdsaSig, _ := ECDSASign(ecdsaKP.PrivateKey, digest[:])
	ecdsaSignTime := time.Since(start)

	start = time.Now()
	ecdsaValid := ECDSAVerify(ecdsaKP.PublicKey, digest[:], ecdsaSig)
	ecdsaVerifyTime := time.Since(start)

	// Lamport Benchmark
	start = time.Now()
	lampPriv, lampPub, _ := GenerateLamportKeyPair()
	lampKeyGenTime := time.Since(start)

	start = time.Now()
	lampSig := LamportSign(lampPriv, digest)
	lampSignTime := time.Since(start)

	start = time.Now()
	lampValid := LamportVerify(lampPub, digest, lampSig)
	lampVerifyTime := time.Since(start)

	fmt.Printf("%-24s | %-24s | %-24s\n", "Metric", "ECDSA (P-256)", "Lamport OTS (SHA-256)")
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("%-24s | %-24s | %-24s\n", "Public Key Size", fmt.Sprintf("%d bytes", len(ecdsaKP.PublicKey)), "16,384 bytes")
	fmt.Printf("%-24s | %-24s | %-24s\n", "Private Key Size", "32 bytes", "16,384 bytes")
	fmt.Printf("%-24s | %-24s | %-24s\n", "Signature Size", fmt.Sprintf("%d bytes", len(ecdsaSig)), "8,192 bytes")
	fmt.Printf("%-24s | %-24s | %-24s\n", "KeyGen Latency", ecdsaKeyGenTime, lampKeyGenTime)
	fmt.Printf("%-24s | %-24s | %-24s\n", "Signing Latency", ecdsaSignTime, lampSignTime)
	fmt.Printf("%-24s | %-24s | %-24s\n", "Verifying Latency", ecdsaVerifyTime, lampVerifyTime)
	fmt.Printf("%-24s | %-24t | %-24t\n", "Signature Valid", ecdsaValid, lampValid)
	fmt.Printf("%-24s | %-24s | %-24s\n", "Quantum Safe?", "NO (Broken by Shor)", "YES (Hash Preimage Bound)")
	fmt.Printf("%-24s | %-24s | %-24s\n", "Key Reuse Allowed?", "YES (Unlimited)", "NO (CRITICAL: 1-Time Only)")
	fmt.Println(strings.Repeat("=", 80) + "\n")
}

// ============================================================================
// 2. TRANSACTIONS & MERKLE TREE
// ============================================================================

type SigType string

const (
	SigTypeECDSA   SigType = "ECDSA"
	SigTypeLamport SigType = "LAMPORT"
)

type Transaction struct {
	ID        string  `json:"id"`
	Sender    string  `json:"sender"`
	Recipient string  `json:"recipient"`
	Amount    uint64  `json:"amount"`
	Nonce     uint64  `json:"nonce"`
	SigScheme SigType `json:"sig_scheme"`
	PubKey    []byte  `json:"pub_key,omitempty"` // For ECDSA
	Signature []byte  `json:"signature"`
}

func (tx *Transaction) Hash() [32]byte {
	record := fmt.Sprintf("%s:%s:%d:%d:%s", tx.Sender, tx.Recipient, tx.Amount, tx.Nonce, tx.SigScheme)
	return sha256.Sum256([]byte(record))
}

func (tx *Transaction) SignECDSA(kp *ECDSAKeyPair) error {
	digest := tx.Hash()
	sig, err := ECDSASign(kp.PrivateKey, digest[:])
	if err != nil {
		return err
	}
	tx.PubKey = kp.PublicKey
	tx.Signature = sig
	tx.ID = hex.EncodeToString(digest[:])
	return nil
}

func (tx *Transaction) Verify() bool {
	if tx.Sender == "COINBASE" {
		return true
	}
	digest := tx.Hash()
	if tx.SigScheme == SigTypeECDSA {
		return ECDSAVerify(tx.PubKey, digest[:], tx.Signature)
	}
	return false
}

// Binary Merkle Tree
func ComputeMerkleRoot(txs []*Transaction) string {
	if len(txs) == 0 {
		empty := sha256.Sum256([]byte{})
		return hex.EncodeToString(empty[:])
	}
	var hashes [][]byte
	for _, tx := range txs {
		h, _ := hex.DecodeString(tx.ID)
		hashes = append(hashes, h)
	}
	for len(hashes) > 1 {
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}
		var level [][]byte
		for i := 0; i < len(hashes); i += 2 {
			combined := append(hashes[i], hashes[i+1]...)
			h := sha256.Sum256(combined)
			level = append(level, h[:])
		}
		hashes = level
	}
	return hex.EncodeToString(hashes[0])
}

// ============================================================================
// 3. BLOCK & PROOF-OF-WORK
// ============================================================================

// Difficulty: Number of leading zero bits required in block hash.
// Set to 16 for instantaneous cryptographic verification without high CPU overhead.
const MiningDifficulty = 16

type BlockHeader struct {
	Index        uint64 `json:"index"`
	Timestamp    int64  `json:"timestamp"`
	PrevHash     string `json:"prev_hash"`
	MerkleRoot   string `json:"merkle_root"`
	Difficulty   uint32 `json:"difficulty"`
	Nonce        uint64 `json:"nonce"`
	MinerAddress string `json:"miner_address"`
}

type Block struct {
	Header       BlockHeader    `json:"header"`
	Hash         string         `json:"hash"`
	Transactions []*Transaction `json:"transactions"`
}

func (b *Block) ComputeHash() [32]byte {
	record := fmt.Sprintf("%d:%d:%s:%s:%d:%d:%s",
		b.Header.Index,
		b.Header.Timestamp,
		b.Header.PrevHash,
		b.Header.MerkleRoot,
		b.Header.Difficulty,
		b.Header.Nonce,
		b.Header.MinerAddress,
	)
	first := sha256.Sum256([]byte(record))
	return sha256.Sum256(first[:]) // Double SHA-256
}

func CalculateTarget(difficulty uint32) *big.Int {
	target := big.NewInt(1)
	target.Lsh(target, 256-uint(difficulty))
	return target
}

func (b *Block) Mine() {
	target := CalculateTarget(b.Header.Difficulty)
	var hashInt big.Int
	for {
		h := b.ComputeHash()
		hashInt.SetBytes(h[:])
		if hashInt.Cmp(target) < 0 {
			b.Hash = hex.EncodeToString(h[:])
			break
		}
		b.Header.Nonce++
	}
}

func (b *Block) ValidatePoW() bool {
	computed := b.ComputeHash()
	if hex.EncodeToString(computed[:]) != b.Hash {
		return false
	}
	target := CalculateTarget(b.Header.Difficulty)
	var hashInt big.Int
	hashInt.SetBytes(computed[:])
	return hashInt.Cmp(target) < 0
}

// ============================================================================
// 4. BLOCKCHAIN, ACCOUNT LEDGER & FORK REORGANIZATION
// ============================================================================

type LedgerState struct {
	Balances map[string]uint64
	Nonces   map[string]uint64
}

func NewLedgerState() *LedgerState {
	return &LedgerState{
		Balances: make(map[string]uint64),
		Nonces:   make(map[string]uint64),
	}
}

func (ls *LedgerState) Clone() *LedgerState {
	cloned := NewLedgerState()
	for k, v := range ls.Balances {
		cloned.Balances[k] = v
	}
	for k, v := range ls.Nonces {
		cloned.Nonces[k] = v
	}
	return cloned
}

func (ls *LedgerState) ApplyTx(tx *Transaction) error {
	if tx.Sender == "COINBASE" {
		ls.Balances[tx.Recipient] += tx.Amount
		return nil
	}
	if !tx.Verify() {
		return errors.New("invalid transaction signature")
	}
	if ls.Balances[tx.Sender] < tx.Amount {
		return fmt.Errorf("insufficient balance: sender has %d, wants %d", ls.Balances[tx.Sender], tx.Amount)
	}
	if tx.Nonce != ls.Nonces[tx.Sender] {
		return fmt.Errorf("invalid nonce: expected %d, got %d", ls.Nonces[tx.Sender], tx.Nonce)
	}

	ls.Balances[tx.Sender] -= tx.Amount
	ls.Balances[tx.Recipient] += tx.Amount
	ls.Nonces[tx.Sender]++
	return nil
}

type Blockchain struct {
	mu         sync.RWMutex
	Chain      []*Block
	BlockIndex map[string]*Block
	State      *LedgerState
}

func NewBlockchain(genesisMiner string) *Blockchain {
	bc := &Blockchain{
		Chain:      make([]*Block, 0),
		BlockIndex: make(map[string]*Block),
		State:      NewLedgerState(),
	}

	genesisTx := &Transaction{
		ID:        "0000000000000000000000000000000000000000000000000000000000000000",
		Sender:    "COINBASE",
		Recipient: genesisMiner,
		Amount:    50,
		Nonce:     0,
		SigScheme: SigTypeECDSA,
	}

	genesisBlock := &Block{
		Header: BlockHeader{
			Index:        0,
			Timestamp:    time.Now().Unix(),
			PrevHash:     strings.Repeat("0", 64),
			Difficulty:   MiningDifficulty,
			MinerAddress: genesisMiner,
		},
		Transactions: []*Transaction{genesisTx},
	}
	genesisBlock.Header.MerkleRoot = ComputeMerkleRoot(genesisBlock.Transactions)
	genesisBlock.Mine()

	bc.Chain = append(bc.Chain, genesisBlock)
	bc.BlockIndex[genesisBlock.Hash] = genesisBlock
	_ = bc.State.ApplyTx(genesisTx)

	return bc
}

func (bc *Blockchain) Tip() *Block {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.Chain[len(bc.Chain)-1]
}

// Adds block, resolving forks using the Longest Chain Rule (cumulative PoW height)
func (bc *Blockchain) AddBlock(b *Block) (bool, error) {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	if _, exists := bc.BlockIndex[b.Hash]; exists {
		return false, nil // Already processed
	}
	if !b.ValidatePoW() {
		return false, errors.New("proof-of-work validation failed")
	}
	if b.Header.MerkleRoot != ComputeMerkleRoot(b.Transactions) {
		return false, errors.New("merkle root mismatch")
	}

	currentTip := bc.Chain[len(bc.Chain)-1]

	// Case 1: Direct extension of current chain
	if b.Header.PrevHash == currentTip.Hash {
		tempState := bc.State.Clone()
		for _, tx := range b.Transactions {
			if err := tempState.ApplyTx(tx); err != nil {
				return false, fmt.Errorf("transaction execution failed: %w", err)
			}
		}
		bc.State = tempState
		bc.Chain = append(bc.Chain, b)
		bc.BlockIndex[b.Hash] = b
		return true, nil
	}

	// Case 2: Block attaches to an ancestor (Fork detected)
	bc.BlockIndex[b.Hash] = b
	ancestor, exists := bc.BlockIndex[b.Header.PrevHash]
	if !exists {
		return false, errors.New("orphan block: parent unknown")
	}

	// Reconstruct the competing fork branch
	var forkBranch []*Block
	curr := b
	for curr != nil && curr.Header.Index > 0 {
		forkBranch = append([]*Block{curr}, forkBranch...)
		curr = bc.BlockIndex[curr.Header.PrevHash]
	}

	// Longest Chain Rule: Reorganize if the fork branch is longer
	if len(forkBranch) > len(bc.Chain) {
		log.Printf(">>> FORK REORGANIZATION DETECTED: Replacing %d blocks with longer branch of %d blocks",
			len(bc.Chain), len(forkBranch))

		newState := NewLedgerState()
		for _, blk := range forkBranch {
			for _, tx := range blk.Transactions {
				if err := newState.ApplyTx(tx); err != nil {
					return false, fmt.Errorf("reorg rejected, branch invalid: %w", err)
				}
			}
		}
		bc.Chain = forkBranch
		bc.State = newState
		return true, nil
	}

	_ = ancestor
	return false, nil
}

// ============================================================================
// 5. P2P WIRE PROTOCOL & GOSSIP OVER RAW TCP
// ============================================================================

const ProtocolMagic uint32 = 0x424C4F43 // "BLOC"

type MsgType byte

const (
	MsgTypeHandshake MsgType = 0x01
	MsgTypeGetBlocks MsgType = 0x02
	MsgTypeBlocks    MsgType = 0x03
	MsgTypeBlock     MsgType = 0x04
	MsgTypeTx        MsgType = 0x05
)

type HandshakePayload struct {
	ListenAddr string `json:"listen_addr"`
	Height     uint64 `json:"height"`
	BestHash   string `json:"best_hash"`
}

type Node struct {
	Addr       string
	Blockchain *Blockchain
	PeerAddrs  map[string]bool
	listener   net.Listener
	mu         sync.Mutex
	stopChan   chan struct{}
}

func NewNode(addr string, bc *Blockchain) *Node {
	return &Node{
		Addr:       addr,
		Blockchain: bc,
		PeerAddrs:  make(map[string]bool),
		stopChan:   make(chan struct{}),
	}
}

func (n *Node) Start() error {
	l, err := net.Listen("tcp", n.Addr)
	if err != nil {
		return err
	}
	n.listener = l

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				select {
				case <-n.stopChan:
					return
				default:
					continue
				}
			}
			go n.handleConnection(conn)
		}
	}()
	return nil
}

func (n *Node) Stop() {
	close(n.stopChan)
	if n.listener != nil {
		_ = n.listener.Close()
	}
}

func (n *Node) ConnectToPeer(peerAddr string) {
	n.mu.Lock()
	if n.PeerAddrs[peerAddr] || peerAddr == n.Addr {
		n.mu.Unlock()
		return
	}
	n.PeerAddrs[peerAddr] = true
	n.mu.Unlock()

	conn, err := net.DialTimeout("tcp", peerAddr, 2*time.Second)
	if err != nil {
		return
	}

	// Send Handshake
	tip := n.Blockchain.Tip()
	payload, _ := json.Marshal(HandshakePayload{
		ListenAddr: n.Addr,
		Height:     tip.Header.Index,
		BestHash:   tip.Hash,
	})
	_ = writeFrame(conn, MsgTypeHandshake, payload)
	go n.handleConnection(conn)
}

func (n *Node) Broadcast(msgType MsgType, data []byte) {
	n.mu.Lock()
	peers := make([]string, 0, len(n.PeerAddrs))
	for p := range n.PeerAddrs {
		peers = append(peers, p)
	}
	n.mu.Unlock()

	for _, p := range peers {
		go func(addr string) {
			conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
			if err != nil {
				return
			}
			defer conn.Close()
			_ = writeFrame(conn, msgType, data)
		}(p)
	}
}

func (n *Node) handleConnection(conn net.Conn) {
	defer conn.Close()
	for {
		mType, payload, err := readFrame(conn)
		if err != nil {
			return
		}

		switch mType {
		case MsgTypeHandshake:
			var hs HandshakePayload
			if err := json.Unmarshal(payload, &hs); err == nil {
				n.mu.Lock()
				n.PeerAddrs[hs.ListenAddr] = true
				n.mu.Unlock()

				// If peer has longer chain, sync blocks
				localHeight := n.Blockchain.Tip().Header.Index
				if hs.Height > localHeight {
					_ = writeFrame(conn, MsgTypeGetBlocks, nil)
				}
			}

		case MsgTypeGetBlocks:
			n.Blockchain.mu.RLock()
			blocksJSON, _ := json.Marshal(n.Blockchain.Chain)
			n.Blockchain.mu.RUnlock()
			_ = writeFrame(conn, MsgTypeBlocks, blocksJSON)

		case MsgTypeBlocks:
			var blocks []*Block
			if err := json.Unmarshal(payload, &blocks); err == nil {
				for _, b := range blocks {
					_, _ = n.Blockchain.AddBlock(b)
				}
			}

		case MsgTypeBlock:
			var b Block
			if err := json.Unmarshal(payload, &b); err == nil {
				added, err := n.Blockchain.AddBlock(&b)
				if err == nil && added {
					// Forward gossip
					n.Broadcast(MsgTypeBlock, payload)
				}
			}

		case MsgTypeTx:
			var tx Transaction
			if err := json.Unmarshal(payload, &tx); err == nil {
				if tx.Verify() {
					// Forward valid transaction
					n.Broadcast(MsgTypeTx, payload)
				}
			}
		}
	}
}

func writeFrame(w io.Writer, mType MsgType, payload []byte) error {
	var header [9]byte
	binary.BigEndian.PutUint32(header[0:4], ProtocolMagic)
	header[4] = byte(mType)
	binary.BigEndian.PutUint32(header[5:9], uint32(len(payload)))

	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := w.Write(payload)
		return err
	}
	return nil
}

func readFrame(r io.Reader) (MsgType, []byte, error) {
	var header [9]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	magic := binary.BigEndian.Uint32(header[0:4])
	if magic != ProtocolMagic {
		return 0, nil, errors.New("protocol magic mismatch")
	}
	mType := MsgType(header[4])
	length := binary.BigEndian.Uint32(header[5:9])

	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	return mType, payload, nil
}

// ============================================================================
// 6. MULTI-NODE VERIFICATION SUITE & REORG DEMONSTRATION
// ============================================================================

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	// Step 1: Execute Cryptographic Comparison Benchmark
	RunCryptographicComparison()

	fmt.Println(strings.Repeat("=", 80))
	fmt.Println(" DISTRIBUTED BLOCKCHAIN P2P CLUSTER: GOSSIP, FORKS & CHAIN REORGANIZATION")
	fmt.Println(strings.Repeat("=", 80))

	// Setup 2 Wallets
	aliceWallet, _ := GenerateECDSAKeyPair()
	bobWallet, _ := GenerateECDSAKeyPair()
	minerWallet, _ := GenerateECDSAKeyPair()

	// Spin up 2 Independent P2P Nodes
	addrA := "127.0.0.1:19001"
	addrB := "127.0.0.1:19002"

	bcA := NewBlockchain(minerWallet.Address)
	bcB := NewBlockchain(minerWallet.Address)

	nodeA := NewNode(addrA, bcA)
	nodeB := NewNode(addrB, bcB)

	_ = nodeA.Start()
	_ = nodeB.Start()
	defer nodeA.Stop()
	defer nodeB.Stop()

	// Connect Nodes via TCP Gossip
	nodeA.ConnectToPeer(addrB)
	nodeB.ConnectToPeer(addrA)
	time.Sleep(100 * time.Millisecond)

	fmt.Printf("[Cluster Init] Node A running on %s, Node B running on %s\n", addrA, addrB)
	fmt.Printf("[Balances Init] Miner: %d coins\n", bcA.State.Balances[minerWallet.Address])

	// --- PHASE 1: Mined Block Propagation via Gossip ---
	fmt.Println("\n--- PHASE 1: Mining & Propagating Valid Transactions ---")
	tx1 := &Transaction{
		Sender:    minerWallet.Address,
		Recipient: aliceWallet.Address,
		Amount:    20,
		Nonce:     0,
		SigScheme: SigTypeECDSA,
	}
	_ = tx1.SignECDSA(minerWallet)

	block1 := &Block{
		Header: BlockHeader{
			Index:        1,
			Timestamp:    time.Now().Unix(),
			PrevHash:     bcA.Tip().Hash,
			Difficulty:   MiningDifficulty,
			MinerAddress: minerWallet.Address,
		},
		Transactions: []*Transaction{tx1},
	}
	block1.Header.MerkleRoot = ComputeMerkleRoot(block1.Transactions)
	block1.Mine()

	log.Printf("[Node A] Mined Block #1 (Hash: %s...). Broadcasting to cluster...", block1.Hash[:16])
	_, _ = bcA.AddBlock(block1)
	block1Data, _ := json.Marshal(block1)
	nodeA.Broadcast(MsgTypeBlock, block1Data)

	time.Sleep(200 * time.Millisecond)
	log.Printf("[Sync Check] Node A Height: %d | Node B Height: %d", bcA.Tip().Header.Index, bcB.Tip().Header.Index)
	log.Printf("[Ledger State] Alice Balance on Node B: %d coins", bcB.State.Balances[aliceWallet.Address])

	// --- PHASE 2: Lamport One-Time Signature Integration ---
	fmt.Println("\n--- PHASE 2: Post-Quantum Lamport Signature Transaction ---")
	_, lampPub, _ := GenerateLamportKeyPair()
	fmt.Printf("[Post-Quantum Wallet] Lamport Public Address: %s\n", lampPub.Address)

	// Faucet credit for Lamport account
	txCredit := &Transaction{
		Sender:    minerWallet.Address,
		Recipient: lampPub.Address,
		Amount:    15,
		Nonce:     1,
		SigScheme: SigTypeECDSA,
	}
	_ = txCredit.SignECDSA(minerWallet)

	block2 := &Block{
		Header: BlockHeader{
			Index:        2,
			Timestamp:    time.Now().Unix(),
			PrevHash:     bcA.Tip().Hash,
			Difficulty:   MiningDifficulty,
			MinerAddress: minerWallet.Address,
		},
		Transactions: []*Transaction{txCredit},
	}
	block2.Header.MerkleRoot = ComputeMerkleRoot(block2.Transactions)
	block2.Mine()
	_, _ = bcA.AddBlock(block2)
	block2Data, _ := json.Marshal(block2)
	nodeA.Broadcast(MsgTypeBlock, block2Data)

	time.Sleep(200 * time.Millisecond)
	log.Printf("[Post-Quantum Check] Lamport Wallet Balance on Node B: %d coins", bcB.State.Balances[lampPub.Address])

	// --- PHASE 3: Network Partition & Longest-Chain Reorganization ---
	fmt.Println("\n--- PHASE 3: Fork Generation & Longest Chain Reorg ---")
	// Isolate Node B: sever connections
	nodeA.mu.Lock()
	nodeA.PeerAddrs = make(map[string]bool)
	nodeA.mu.Unlock()
	nodeB.mu.Lock()
	nodeB.PeerAddrs = make(map[string]bool)
	nodeB.mu.Unlock()
	log.Println("[Network Split] Node A and Node B partitioned.")

	// Node B (Minority fork) mines 1 block
	txForkB := &Transaction{
		Sender:    aliceWallet.Address,
		Recipient: bobWallet.Address,
		Amount:    5,
		Nonce:     0,
		SigScheme: SigTypeECDSA,
	}
	_ = txForkB.SignECDSA(aliceWallet)

	forkBlockB := &Block{
		Header: BlockHeader{
			Index:        3,
			Timestamp:    time.Now().Unix(),
			PrevHash:     bcB.Tip().Hash,
			Difficulty:   MiningDifficulty,
			MinerAddress: bobWallet.Address,
		},
		Transactions: []*Transaction{txForkB},
	}
	forkBlockB.Header.MerkleRoot = ComputeMerkleRoot(forkBlockB.Transactions)
	forkBlockB.Mine()
	_, _ = bcB.AddBlock(forkBlockB)
	log.Printf("[Fork B] Node B mined conflicting Block #3 (Hash: %s...). Height: %d", forkBlockB.Hash[:16], bcB.Tip().Header.Index)

	// Node A (Dominant chain) mines 2 blocks
	block3A := &Block{
		Header: BlockHeader{
			Index:        3,
			Timestamp:    time.Now().Unix(),
			PrevHash:     bcA.Tip().Hash,
			Difficulty:   MiningDifficulty,
			MinerAddress: minerWallet.Address,
		},
		Transactions: []*Transaction{},
	}
	block3A.Header.MerkleRoot = ComputeMerkleRoot(block3A.Transactions)
	block3A.Mine()
	_, _ = bcA.AddBlock(block3A)

	block4A := &Block{
		Header: BlockHeader{
			Index:        4,
			Timestamp:    time.Now().Unix(),
			PrevHash:     bcA.Tip().Hash,
			Difficulty:   MiningDifficulty,
			MinerAddress: minerWallet.Address,
		},
		Transactions: []*Transaction{},
	}
	block4A.Header.MerkleRoot = ComputeMerkleRoot(block4A.Transactions)
	block4A.Mine()
	_, _ = bcA.AddBlock(block4A)
	log.Printf("[Fork A] Node A mined 2 blocks. Tip is now Block #4 (Hash: %s...). Height: %d", block4A.Hash[:16], bcA.Tip().Header.Index)

	// Reconnect and heal partition
	fmt.Println("\n--- Healing Network Partition: Syncing Chains ---")
	nodeB.ConnectToPeer(addrA)
	time.Sleep(300 * time.Millisecond)

	log.Printf("[Final Convergence] Node A Height: %d | Node B Height: %d", bcA.Tip().Header.Index, bcB.Tip().Header.Index)
	log.Printf("[Final Convergence] Node A Best Hash: %s", bcA.Tip().Hash[:16])
	log.Printf("[Final Convergence] Node B Best Hash: %s", bcB.Tip().Hash[:16])

	if bcA.Tip().Hash == bcB.Tip().Hash {
		fmt.Println("\n" + strings.Repeat("*", 80))
		fmt.Println(" CONSENSUS SUCCESS: Node B successfully rolled back fork and converged to Node A!")
		fmt.Println(strings.Repeat("*", 80))
	} else {
		fmt.Println("\n[FAILURE] Chains did not converge.")
	}
}
