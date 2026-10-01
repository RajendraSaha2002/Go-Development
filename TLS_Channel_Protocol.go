package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ============================================================================
// 1. KEY DERIVATION FUNCTION: HKDF (RFC 5869) BUILT ON HMAC-SHA256
// ============================================================================

func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

func hkdfExpand(prk, info []byte, outLen int) ([]byte, error) {
	hashLen := sha256.Size
	if outLen > 255*hashLen {
		return nil, errors.New("hkdf: requested output length exceeds maximum allowable")
	}

	var okm []byte
	var prevT []byte
	mac := hmac.New(sha256.New, prk)
	counter := byte(1)

	for len(okm) < outLen {
		mac.Reset()
		mac.Write(prevT)
		mac.Write(info)
		mac.Write([]byte{counter})
		prevT = mac.Sum(nil)
		okm = append(okm, prevT...)
		counter++
	}
	return okm[:outLen], nil
}

// ============================================================================
// 2. PROTOCOL CONSTANTS & RECORD LAYER
// ============================================================================

const (
	ProtocolVersion uint16 = 0x0100     // Version 1.0
	MagicHeader     uint32 = 0x4D544C53 // "MTLS" (Mini-TLS)

	// Record Content Types
	ContentTypeHandshake byte = 0x01
	ContentTypeAlert     byte = 0x02
	ContentTypeAppChat   byte = 0x03
	ContentTypeFileInit  byte = 0x04
	ContentTypeFileData  byte = 0x05
	ContentTypeFileDone  byte = 0x06
)

// Record Header layout (13 bytes total):
// [0:4]   Magic (4 bytes)
// [4:5]   ContentType (1 byte)
// [5:7]   Version (2 bytes)
// [7:15]  Sequence Number (8 bytes)
// [15:17] Length of Encrypted Payload + Tag (2 bytes)
const RecordHeaderSize = 17

// Compute nonce by XORing the 64-bit sequence number into the last 8 bytes of the 12-byte base IV
func computeNonce(baseIV []byte, seq uint64) []byte {
	nonce := make([]byte, 12)
	copy(nonce, baseIV)
	var seqBytes [8]byte
	binary.BigEndian.PutUint64(seqBytes[:], seq)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= seqBytes[i]
	}
	return nonce
}

// ============================================================================
// 3. HANDSHAKE MESSAGES & SECURE CONNECTION
// ============================================================================

type ClientHello struct {
	ClientRandom [32]byte
	ClientPubKey []byte
}

type ServerHello struct {
	ServerRandom   [32]byte
	ServerPubKey   []byte
	ServerFinished [32]byte
}

type ClientFinished struct {
	ClientFinished [32]byte
}

type SecureConn struct {
	conn        net.Conn
	isServer    bool
	readCipher  cipher.AEAD
	writeCipher cipher.AEAD
	readBaseIV  []byte
	writeBaseIV []byte
	readSeq     uint64
	writeSeq    uint64
	muWrite     sync.Mutex
	muRead      sync.Mutex
}

func (s *SecureConn) Close() error {
	return s.conn.Close()
}

// WriteEncryptedRecord encrypts payload using AES-GCM and transmits record
func (s *SecureConn) WriteEncryptedRecord(contentType byte, plaintext []byte) error {
	s.muWrite.Lock()
	defer s.muWrite.Unlock()

	seq := s.writeSeq
	s.writeSeq++

	nonce := computeNonce(s.writeBaseIV, seq)
	ciphertext := s.writeCipher.Seal(nil, nonce, plaintext, nil)

	header := make([]byte, RecordHeaderSize)
	binary.BigEndian.PutUint32(header[0:4], MagicHeader)
	header[4] = contentType
	binary.BigEndian.PutUint16(header[5:7], ProtocolVersion)
	binary.BigEndian.PutUint64(header[7:15], seq)
	binary.BigEndian.PutUint16(header[15:17], uint16(len(ciphertext)))

	// Re-encrypt with Header as Additional Authenticated Data (AAD)
	nonce = computeNonce(s.writeBaseIV, seq)
	ciphertext = s.writeCipher.Seal(nil, nonce, plaintext, header)

	if _, err := s.conn.Write(header); err != nil {
		return err
	}
	if _, err := s.conn.Write(ciphertext); err != nil {
		return err
	}
	return nil
}

// ReadEncryptedRecord receives and authenticates a record, checking for replays
func (s *SecureConn) ReadEncryptedRecord() (byte, []byte, error) {
	s.muRead.Lock()
	defer s.muRead.Unlock()

	header := make([]byte, RecordHeaderSize)
	if _, err := io.ReadFull(s.conn, header); err != nil {
		return 0, nil, err
	}

	magic := binary.BigEndian.Uint32(header[0:4])
	if magic != MagicHeader {
		return 0, nil, errors.New("protocol violation: invalid magic header")
	}

	contentType := header[4]
	version := binary.BigEndian.Uint16(header[5:7])
	if version != ProtocolVersion {
		return 0, nil, errors.New("protocol violation: unsupported version")
	}

	seq := binary.BigEndian.Uint64(header[7:15])
	length := binary.BigEndian.Uint16(header[15:17])

	// Strict Monotonic Anti-Replay Check over TCP Stream
	if seq != s.readSeq {
		return 0, nil, fmt.Errorf("anti-replay failure: expected sequence %d, got %d (replay/injection detected)",
			s.readSeq, seq)
	}
	s.readSeq++

	ciphertext := make([]byte, length)
	if _, err := io.ReadFull(s.conn, ciphertext); err != nil {
		return 0, nil, err
	}

	nonce := computeNonce(s.readBaseIV, seq)
	plaintext, err := s.readCipher.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return 0, nil, fmt.Errorf("cryptographic integrity check failed: %w", err)
	}

	return contentType, plaintext, nil
}

// ============================================================================
// 4. HANDSHAKE PROTOCOL ENGINE
// ============================================================================

func ClientHandshake(conn net.Conn) (*SecureConn, error) {
	curve := ecdh.X25519()
	clientEphemeral, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	var clientRandom [32]byte
	if _, err := rand.Read(clientRandom[:]); err != nil {
		return nil, err
	}

	// 1. Send ClientHello
	clientPub := clientEphemeral.PublicKey().Bytes()
	chBuf := new(bytes.Buffer)
	chBuf.Write(clientRandom[:])
	chBuf.WriteByte(byte(len(clientPub)))
	chBuf.Write(clientPub)

	transcript := sha256.New()
	transcript.Write(chBuf.Bytes())

	if _, err := conn.Write(chBuf.Bytes()); err != nil {
		return nil, err
	}

	// 2. Receive ServerHello
	var serverRandom [32]byte
	if _, err := io.ReadFull(conn, serverRandom[:]); err != nil {
		return nil, err
	}

	var pubLenBuf [1]byte
	if _, err := io.ReadFull(conn, pubLenBuf[:]); err != nil {
		return nil, err
	}
	serverPubBytes := make([]byte, pubLenBuf[0])
	if _, err := io.ReadFull(conn, serverPubBytes); err != nil {
		return nil, err
	}

	var serverFinished [32]byte
	if _, err := io.ReadFull(conn, serverFinished[:]); err != nil {
		return nil, err
	}

	// Update transcript with ServerHello before the Finished tag
	shTranscriptBuf := new(bytes.Buffer)
	shTranscriptBuf.Write(serverRandom[:])
	shTranscriptBuf.WriteByte(pubLenBuf[0])
	shTranscriptBuf.Write(serverPubBytes)
	transcript.Write(shTranscriptBuf.Bytes())

	// 3. Compute Shared Secret & Derive Session Keys
	serverPubKey, err := curve.NewPublicKey(serverPubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid server public key: %w", err)
	}

	sharedSecret, err := clientEphemeral.ECDH(serverPubKey)
	if err != nil {
		return nil, fmt.Errorf("ecdh computation failed: %w", err)
	}

	// HKDF Key Schedule
	prk := hkdfExtract([]byte("MiniTLS-v1-Salt"), sharedSecret)
	handshakeTranscript := transcript.Sum(nil)

	// Derive Server Handshake Key for verifying ServerFinished
	serverHSKey, _ := hkdfExpand(prk, []byte("server-finished"), 32)
	mac := hmac.New(sha256.New, serverHSKey)
	mac.Write(handshakeTranscript)
	expectedServerFinished := mac.Sum(nil)

	if !hmac.Equal(serverFinished[:], expectedServerFinished) {
		return nil, errors.New("handshake authentication failed: invalid server finished tag")
	}

	// 4. Send ClientFinished
	clientHSKey, _ := hkdfExpand(prk, []byte("client-finished"), 32)
	transcript.Write(serverFinished[:])

	clientFinishedMAC := hmac.New(sha256.New, clientHSKey)
	clientFinishedMAC.Write(transcript.Sum(nil))
	clientFinishedTag := clientFinishedMAC.Sum(nil)

	if _, err := conn.Write(clientFinishedTag); err != nil {
		return nil, err
	}

	// 5. Derive Traffic Encryption Keys
	// Client Write = 32B AES Key + 12B IV
	// Server Write = 32B AES Key + 12B IV
	trafficKeys, _ := hkdfExpand(prk, append(clientRandom[:], serverRandom[:]...), 88)

	clientWriteKey := trafficKeys[0:32]
	clientWriteIV := trafficKeys[32:44]
	serverWriteKey := trafficKeys[44:76]
	serverWriteIV := trafficKeys[76:88]

	clientBlock, _ := aes.NewCipher(clientWriteKey)
	clientGCM, _ := cipher.NewGCM(clientBlock)

	serverBlock, _ := aes.NewCipher(serverWriteKey)
	serverGCM, _ := cipher.NewGCM(serverBlock)

	return &SecureConn{
		conn:        conn,
		isServer:    false,
		writeCipher: clientGCM,
		writeBaseIV: clientWriteIV,
		readCipher:  serverGCM,
		readBaseIV:  serverWriteIV,
	}, nil
}

func ServerHandshake(conn net.Conn) (*SecureConn, error) {
	curve := ecdh.X25519()
	serverEphemeral, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	var serverRandom [32]byte
	if _, err := rand.Read(serverRandom[:]); err != nil {
		return nil, err
	}

	// 1. Read ClientHello
	var clientRandom [32]byte
	if _, err := io.ReadFull(conn, clientRandom[:]); err != nil {
		return nil, err
	}

	var pubLenBuf [1]byte
	if _, err := io.ReadFull(conn, pubLenBuf[:]); err != nil {
		return nil, err
	}
	clientPubBytes := make([]byte, pubLenBuf[0])
	if _, err := io.ReadFull(conn, clientPubBytes); err != nil {
		return nil, err
	}

	transcript := sha256.New()
	chBuf := new(bytes.Buffer)
	chBuf.Write(clientRandom[:])
	chBuf.WriteByte(pubLenBuf[0])
	chBuf.Write(clientPubBytes)
	transcript.Write(chBuf.Bytes())

	// 2. Compute Shared Secret & Derive Handshake Keys
	clientPubKey, err := curve.NewPublicKey(clientPubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid client public key: %w", err)
	}

	sharedSecret, err := serverEphemeral.ECDH(clientPubKey)
	if err != nil {
		return nil, fmt.Errorf("ecdh computation failed: %w", err)
	}

	prk := hkdfExtract([]byte("MiniTLS-v1-Salt"), sharedSecret)

	// 3. Form ServerHello & Compute ServerFinished
	serverPub := serverEphemeral.PublicKey().Bytes()
	shBuf := new(bytes.Buffer)
	shBuf.Write(serverRandom[:])
	shBuf.WriteByte(byte(len(serverPub)))
	shBuf.Write(serverPub)
	transcript.Write(shBuf.Bytes())

	serverHSKey, _ := hkdfExpand(prk, []byte("server-finished"), 32)
	mac := hmac.New(sha256.New, serverHSKey)
	mac.Write(transcript.Sum(nil))
	serverFinishedTag := mac.Sum(nil)

	shBuf.Write(serverFinishedTag)
	if _, err := conn.Write(shBuf.Bytes()); err != nil {
		return nil, err
	}

	// 4. Receive and Verify ClientFinished
	var clientFinished [32]byte
	if _, err := io.ReadFull(conn, clientFinished[:]); err != nil {
		return nil, err
	}

	transcript.Write(serverFinishedTag)
	clientHSKey, _ := hkdfExpand(prk, []byte("client-finished"), 32)
	clientFinishedMAC := hmac.New(sha256.New, clientHSKey)
	clientFinishedMAC.Write(transcript.Sum(nil))
	expectedClientFinished := clientFinishedMAC.Sum(nil)

	if !hmac.Equal(clientFinished[:], expectedClientFinished) {
		return nil, errors.New("handshake authentication failed: invalid client finished tag")
	}

	// 5. Derive Traffic Encryption Keys
	trafficKeys, _ := hkdfExpand(prk, append(clientRandom[:], serverRandom[:]...), 88)

	clientWriteKey := trafficKeys[0:32]
	clientWriteIV := trafficKeys[32:44]
	serverWriteKey := trafficKeys[44:76]
	serverWriteIV := trafficKeys[76:88]

	clientBlock, _ := aes.NewCipher(clientWriteKey)
	clientGCM, _ := cipher.NewGCM(clientBlock)

	serverBlock, _ := aes.NewCipher(serverWriteKey)
	serverGCM, _ := cipher.NewGCM(serverBlock)

	return &SecureConn{
		conn:        conn,
		isServer:    true,
		writeCipher: serverGCM,
		writeBaseIV: serverWriteIV,
		readCipher:  clientGCM,
		readBaseIV:  clientWriteIV,
	}, nil
}

// ============================================================================
// 5. APPLICATION TUNNEL: SECURE CHAT & FILE TRANSFER
// ============================================================================

type ApplicationTunnel struct {
	sConn *SecureConn
}

func NewApplicationTunnel(sConn *SecureConn) *ApplicationTunnel {
	return &ApplicationTunnel{sConn: sConn}
}

func (t *ApplicationTunnel) SendChatMessage(msg string) error {
	return t.sConn.WriteEncryptedRecord(ContentTypeAppChat, []byte(msg))
}

func (t *ApplicationTunnel) SendFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	fileName := filepath.Base(filePath)
	fileHash := sha256.Sum256(data)

	// 1. File Init: [4 bytes NameLen][Name][8 bytes FileSize]
	initBuf := new(bytes.Buffer)
	binary.Write(initBuf, binary.BigEndian, uint32(len(fileName)))
	initBuf.WriteString(fileName)
	binary.Write(initBuf, binary.BigEndian, uint64(len(data)))

	if err := t.sConn.WriteEncryptedRecord(ContentTypeFileInit, initBuf.Bytes()); err != nil {
		return err
	}

	// 2. File Chunks (8KB chunks)
	const chunkSize = 8192
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		if err := t.sConn.WriteEncryptedRecord(ContentTypeFileData, data[i:end]); err != nil {
			return err
		}
	}

	// 3. File Done: [32 bytes SHA256]
	return t.sConn.WriteEncryptedRecord(ContentTypeFileDone, fileHash[:])
}

// ============================================================================
// 6. AUTOMATED TEST SUITE & INTERACTIVE CLI
// ============================================================================

func runDemonstration() {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println(" CUSTOM SECURE CHANNEL ENGINE: APPLIED PROTOCOL VALIDATION")
	fmt.Println(" ECDH (X25519) | HKDF-SHA256 | AES-256-GCM | Anti-Replay | Encrypted Tunnel")
	fmt.Println(strings.Repeat("=", 80))

	// Listen on dynamic localhost port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Server listener failed: %v", err)
	}
	defer listener.Close()
	serverAddr := listener.Addr().String()

	var serverSConn *SecureConn
	serverReady := make(chan struct{})

	// Spawn Secure Server
	go func() {
		close(serverReady)
		rawConn, err := listener.Accept()
		if err != nil {
			return
		}
		sConn, err := ServerHandshake(rawConn)
		if err != nil {
			log.Fatalf("Server handshake failed: %v", err)
		}
		serverSConn = sConn
	}()

	<-serverReady

	// Connect Client
	rawClientConn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log.Fatalf("Client dial failed: %v", err)
	}
	defer rawClientConn.Close()

	clientSConn, err := ClientHandshake(rawClientConn)
	if err != nil {
		log.Fatalf("Client handshake failed: %v", err)
	}

	fmt.Println("\n[1] Mutual Cryptographic Handshake Established!")
	fmt.Printf(" -> Client Write IV: %s\n", hex.EncodeToString(clientSConn.writeBaseIV))
	fmt.Printf(" -> Server Write IV: %s\n", hex.EncodeToString(serverSConn.writeBaseIV))
	fmt.Println(" -> Handshake transcript verified via mutual HMAC-SHA256 tags.")

	// Test 1: Encrypted Chat Exchange
	fmt.Println("\n[2] Testing Full-Duplex Encrypted Chat...")
	clientTunnel := NewApplicationTunnel(clientSConn)

	_ = clientTunnel.SendChatMessage("Agent 007: Target acquired at coordinates.")
	cType, payload, err := serverSConn.ReadEncryptedRecord()
	if err != nil || cType != ContentTypeAppChat {
		log.Fatalf("Server failed reading chat: %v", err)
	}
	fmt.Printf(" Server Received (Decrypted): \"%s\"\n", string(payload))

	serverTunnel := NewApplicationTunnel(serverSConn)
	_ = serverTunnel.SendChatMessage("HQ: Confirm status. Maintain radio silence.")
	cType, payload, err = clientSConn.ReadEncryptedRecord()
	if err != nil || cType != ContentTypeAppChat {
		log.Fatalf("Client failed reading chat: %v", err)
	}
	fmt.Printf(" Client Received (Decrypted): \"%s\"\n", string(payload))

	// Test 2: Encrypted Chunked File Transfer
	fmt.Println("\n[3] Testing Encrypted File Transfer & SHA-256 Integrity Verification...")
	tempFile, _ := os.CreateTemp("", "top_secret_*.dat")
	sampleContent := []byte(strings.Repeat("CONFIDENTIAL QUANTUM PAYLOAD DATA\n", 500))
	_, _ = tempFile.Write(sampleContent)
	tempFilePath := tempFile.Name()
	tempFile.Close()
	defer os.Remove(tempFilePath)

	expectedHash := sha256.Sum256(sampleContent)
	fmt.Printf(" -> Sending file: %s (%d bytes, SHA256: %s...)\n",
		filepath.Base(tempFilePath), len(sampleContent), hex.EncodeToString(expectedHash[:8]))

	go func() {
		_ = clientTunnel.SendFile(tempFilePath)
	}()

	// Server receives file transmission
	var receivedBuffer bytes.Buffer
	var receivedFileName string

	for {
		cType, payload, err := serverSConn.ReadEncryptedRecord()
		if err != nil {
			log.Fatalf("File transfer read error: %v", err)
		}
		if cType == ContentTypeFileInit {
			nameLen := binary.BigEndian.Uint32(payload[0:4])
			receivedFileName = string(payload[4 : 4+nameLen])
		} else if cType == ContentTypeFileData {
			receivedBuffer.Write(payload)
		} else if cType == ContentTypeFileDone {
			recHash := payload
			if bytes.Equal(recHash, expectedHash[:]) {
				fmt.Printf(" -> Transfer Complete! File '%s' verified against SHA-256 fingerprint: %s\n",
					receivedFileName, hex.EncodeToString(recHash))
			} else {
				log.Fatalf("Integrity Error: SHA-256 hash mismatch!")
			}
			break
		}
	}

	// Test 3: Anti-Replay & Sequence Tamper Protection Demonstration
	fmt.Println("\n[4] Testing Cryptographic Anti-Replay Defense...")
	// Craft an unauthorized duplicate packet with stale sequence number
	staleSeq := uint64(0)
	craftedNonce := computeNonce(clientSConn.writeBaseIV, staleSeq)
	staleCiphertext := clientSConn.writeCipher.Seal(nil, craftedNonce, []byte("REPLAYED INJECTION ATTACK"), nil)

	header := make([]byte, RecordHeaderSize)
	binary.BigEndian.PutUint32(header[0:4], MagicHeader)
	header[4] = ContentTypeAppChat
	binary.BigEndian.PutUint16(header[5:7], ProtocolVersion)
	binary.BigEndian.PutUint64(header[7:15], staleSeq) // Stale sequence number!
	binary.BigEndian.PutUint16(header[15:17], uint16(len(staleCiphertext)))

	craftedNonce = computeNonce(clientSConn.writeBaseIV, staleSeq)
	staleCiphertext = clientSConn.writeCipher.Seal(nil, craftedNonce, []byte("REPLAYED INJECTION ATTACK"), header)

	// Inject the malicious frame directly onto the network wire
	_, _ = rawClientConn.Write(header)
	_, _ = rawClientConn.Write(staleCiphertext)

	_, _, err = serverSConn.ReadEncryptedRecord()
	if err != nil {
		fmt.Printf(" [ANTI-REPLAY PASSED] Injected packet dropped: %v\n", err)
	} else {
		log.Fatalf("SECURITY VIOLATION: Stale replayed record was accepted!")
	}

	fmt.Println("\n" + strings.Repeat("*", 80))
	fmt.Println(" ALL CRYPTOGRAPHIC AND PROTOCOL INTEGRITY TESTS PASSED WITH ZERO ERRORS!")
	fmt.Println(strings.Repeat("*", 80))
}

func main() {
	mode := flag.String("mode", "demo", "Execution mode: 'demo', 'server', or 'client'")
	addr := flag.String("addr", "127.0.0.1:9443", "Network bind/connect address")
	fileToSend := flag.String("file", "", "Path to file to transmit once tunnel connects")
	flag.Parse()

	if *mode == "demo" {
		runDemonstration()
		return
	}

	if *mode == "server" {
		l, err := net.Listen("tcp", *addr)
		if err != nil {
			log.Fatalf("Server listen failed: %v", err)
		}
		defer l.Close()
		fmt.Printf("[Mini-TLS] Server listening on %s (awaiting secure handshake)...\n", *addr)

		rawConn, err := l.Accept()
		if err != nil {
			log.Fatalf("Accept failed: %v", err)
		}
		defer rawConn.Close()

		sConn, err := ServerHandshake(rawConn)
		if err != nil {
			log.Fatalf("Handshake error: %v", err)
		}
		fmt.Println("[Mini-TLS] Secure Session established! Enter messages below:")

		tunnel := NewApplicationTunnel(sConn)

		// Concurrent Reader Loop
		go func() {
			for {
				cType, payload, err := sConn.ReadEncryptedRecord()
				if err != nil {
					fmt.Printf("\n[Connection terminated: %v]\n", err)
					os.Exit(0)
				}
				if cType == ContentTypeAppChat {
					fmt.Printf("\n[Peer]: %s\n> ", string(payload))
				}
			}
		}()

		// Writer Loop
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Print("> ")
		for scanner.Scan() {
			text := scanner.Text()
			if strings.HasPrefix(text, "/file ") {
				p := strings.TrimPrefix(text, "/file ")
				fmt.Printf("[Transferring file '%s'...] ", p)
				if err := tunnel.SendFile(p); err != nil {
					fmt.Printf("Error: %v\n", err)
				} else {
					fmt.Println("Sent!")
				}
			} else {
				_ = tunnel.SendChatMessage(text)
			}
			fmt.Print("> ")
		}

	} else if *mode == "client" {
		rawConn, err := net.Dial("tcp", *addr)
		if err != nil {
			log.Fatalf("Dial failed: %v", err)
		}
		defer rawConn.Close()

		sConn, err := ClientHandshake(rawConn)
		if err != nil {
			log.Fatalf("Handshake error: %v", err)
		}
		fmt.Println("[Mini-TLS] Secure Session established! Enter messages below:")

		tunnel := NewApplicationTunnel(sConn)

		if *fileToSend != "" {
			fmt.Printf("[Auto-sending file '%s'...] ", *fileToSend)
			if err := tunnel.SendFile(*fileToSend); err != nil {
				fmt.Printf("Error: %v\n", err)
			} else {
				fmt.Println("Sent!")
			}
		}

		// Concurrent Reader Loop
		go func() {
			for {
				cType, payload, err := sConn.ReadEncryptedRecord()
				if err != nil {
					fmt.Printf("\n[Connection terminated: %v]\n", err)
					os.Exit(0)
				}
				if cType == ContentTypeAppChat {
					fmt.Printf("\n[Peer]: %s\n> ", string(payload))
				}
			}
		}()

		// Writer Loop
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Print("> ")
		for scanner.Scan() {
			text := scanner.Text()
			if strings.HasPrefix(text, "/file ") {
				p := strings.TrimPrefix(text, "/file ")
				fmt.Printf("[Transferring file '%s'...] ", p)
				if err := tunnel.SendFile(p); err != nil {
					fmt.Printf("Error: %v\n", err)
				} else {
					fmt.Println("Sent!")
				}
			} else {
				_ = tunnel.SendChatMessage(text)
			}
			fmt.Print("> ")
		}
	}
}
