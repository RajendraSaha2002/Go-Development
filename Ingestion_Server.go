package main

import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/lib/pq"
)

const (
	GenesisHash   = "0000000000000000000000000000000000000000000000000000000000000000"
	TCPBindAddr   = "0.0.0.0:9099"
	BatchSize     = 1000
	FlushInterval = 25 * time.Millisecond
)

type LogEntry struct {
	Host    string
	Service string
	Message string
}

type ChainedRecord struct {
	EpochMs     int64
	Host        string
	Service     string
	Message     string
	PrevHash    string
	CurrentHash string
}

type IngestionEngine struct {
	db          *sql.DB
	queue       chan LogEntry
	currentHash string
	hashLock    sync.Mutex
	wg          sync.WaitGroup
	shutdown    chan struct{}
}

func NewIngestionEngine(db *sql.DB) *IngestionEngine {
	engine := &IngestionEngine{
		db:          db,
		queue:       make(chan LogEntry, 100000),
		currentHash: GenesisHash,
		shutdown:    make(chan struct{}),
	}
	engine.initChainState()
	return engine
}

func (e *IngestionEngine) initChainState() {
	var lastHash string
	err := e.db.QueryRow("SELECT current_hash FROM audit_log ORDER BY id DESC LIMIT 1").Scan(&lastHash)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Println("[ENGINE] No records found. Starting from Genesis Block.")
			e.currentHash = GenesisHash
		} else {
			log.Fatalf("[ENGINE] Fatal error querying DB state: %v", err)
		}
	} else {
		e.currentHash = lastHash
		log.Printf("[ENGINE] Resumed chain state. Tip hash: %s\n", e.currentHash)
	}
}

func (e *IngestionEngine) computeHash(prevHash string, epochMs int64, host, service, msg string) string {
	payload := fmt.Sprintf("%s|%d|%s|%s|%s", prevHash, epochMs, host, service, msg)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func (e *IngestionEngine) StartFlusher() {
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		batch := make([]ChainedRecord, 0, BatchSize)
		ticker := time.NewTicker(FlushInterval)
		defer ticker.Stop()

		for {
			select {
			case <-e.shutdown:
				for {
					select {
					case entry := <-e.queue:
						rec := e.chainOne(entry)
						batch = append(batch, rec)
						if len(batch) >= BatchSize {
							e.persistBatch(batch)
							batch = batch[:0]
						}
					default:
						if len(batch) > 0 {
							e.persistBatch(batch)
						}
						return
					}
				}

			case entry := <-e.queue:
				rec := e.chainOne(entry)
				batch = append(batch, rec)
				if len(batch) >= BatchSize {
					e.persistBatch(batch)
					batch = batch[:0]
				}

			case <-ticker.C:
				if len(batch) > 0 {
					e.persistBatch(batch)
					batch = batch[:0]
				}
			}
		}
	}()
}

func (e *IngestionEngine) chainOne(entry LogEntry) ChainedRecord {
	e.hashLock.Lock()
	defer e.hashLock.Unlock()

	epoch := time.Now().UnixMilli()
	curr := e.computeHash(e.currentHash, epoch, entry.Host, entry.Service, entry.Message)
	prev := e.currentHash
	e.currentHash = curr

	return ChainedRecord{
		EpochMs:     epoch,
		Host:        entry.Host,
		Service:     entry.Service,
		Message:     entry.Message,
		PrevHash:    prev,
		CurrentHash: curr,
	}
}

func (e *IngestionEngine) persistBatch(records []ChainedRecord) {
	if len(records) == 0 {
		return
	}

	txn, err := e.db.Begin()
	if err != nil {
		log.Printf("[ERROR] Failed to begin transaction: %v", err)
		return
	}

	stmt, err := txn.Prepare(`
		INSERT INTO audit_log (epoch_ms, host, service, message, prev_hash, current_hash)
		VALUES ($1, $2, $3, $4, $5, $6)
	`)
	if err != nil {
		txn.Rollback()
		log.Printf("[ERROR] Prepared stmt failed: %v", err)
		return
	}
	defer stmt.Close()

	for _, r := range records {
		_, err := stmt.Exec(r.EpochMs, r.Host, r.Service, r.Message, r.PrevHash, r.CurrentHash)
		if err != nil {
			txn.Rollback()
			log.Printf("[ERROR] Batch execution failed: %v", err)
			return
		}
	}

	if err := txn.Commit(); err != nil {
		log.Printf("[ERROR] Commit failed: %v", err)
	}
}

func (e *IngestionEngine) HandleConnection(conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	// Buffer size allows reading large log payloads
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "|", 3)
		if len(parts) < 3 {
			continue // Invalid frame: host|service|message
		}

		e.queue <- LogEntry{
			Host:    parts[0],
			Service: parts[1],
			Message: parts[2],
		}
	}
}

func main() {
	dbConnStr := "host=127.0.0.1 port=5432 user=postgres password=sharma30@ dbname=audit_db sslmode=disable"
	db, err := sql.Open("postgres", dbConnStr)
	if err != nil {
		log.Fatalf("[FATAL] DB Connection failed: %v", err)
	}
	defer db.Close()

	db.SetMaxOpenConns(50)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		log.Fatalf("[FATAL] DB Ping unreachable: %v", err)
	}

	engine := NewIngestionEngine(db)
	engine.StartFlusher()

	listener, err := net.Listen("tcp", TCPBindAddr)
	if err != nil {
		log.Fatalf("[FATAL] TCP bind failed on %s: %v", TCPBindAddr, err)
	}
	defer listener.Close()

	log.Printf("[INGESTION] Listening on TCP: %s\n", TCPBindAddr)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stop
		log.Println("[SHUTDOWN] Signal received. Flushing and closing...")
		listener.Close()
		close(engine.shutdown)
		engine.wg.Wait()
		db.Close()
		os.Exit(0)
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-engine.shutdown:
				return
			default:
				log.Printf("[WARN] Connection accept error: %v", err)
				continue
			}
		}
		go engine.HandleConnection(conn)
	}
}
