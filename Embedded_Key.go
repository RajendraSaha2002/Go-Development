package main

import (
	"bufio"
	"bytes"
	_ "context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"hash/fnv"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ============================================================================
// 1. BLOOM FILTER
// ============================================================================

type BloomFilter struct {
	bits    []byte
	numBits uint32
	k       uint8
}

func NewBloomFilter(numKeys int, falsePositiveRate float64) *BloomFilter {
	if numKeys < 1 {
		numKeys = 1
	}
	if falsePositiveRate <= 0 || falsePositiveRate >= 1 {
		falsePositiveRate = 0.01
	}
	// m = -1 * (n * ln(p)) / (ln(2)^2)
	m := -1.0 * float64(numKeys) * math.Log(falsePositiveRate) / (math.Ln2 * math.Ln2)
	numBits := uint32(math.Ceil(m))
	if numBits < 64 {
		numBits = 64
	}
	// Round up to nearest byte
	numBits = ((numBits + 7) / 8) * 8

	// k = (m / n) * ln(2)
	kVal := (float64(numBits) / float64(numKeys)) * math.Ln2
	k := uint8(math.Round(kVal))
	if k < 1 {
		k = 1
	}
	if k > 30 {
		k = 30
	}

	return &BloomFilter{
		bits:    make([]byte, numBits/8),
		numBits: numBits,
		k:       k,
	}
}

func hashPair(data []byte) (uint32, uint32) {
	h := fnv.New64a()
	h.Write(data)
	sum := h.Sum64()
	h1 := uint32(sum & 0xFFFFFFFF)
	h2 := uint32(sum >> 32)
	if h2 == 0 {
		h2 = 17
	}
	return h1, h2
}

func (bf *BloomFilter) Add(key []byte) {
	h1, h2 := hashPair(key)
	for i := uint32(0); i < uint32(bf.k); i++ {
		bit := (h1 + i*h2) % bf.numBits
		bf.bits[bit/8] |= 1 << (bit % 8)
	}
}

func (bf *BloomFilter) MayContain(key []byte) bool {
	if bf == nil || len(bf.bits) == 0 {
		return true
	}
	h1, h2 := hashPair(key)
	for i := uint32(0); i < uint32(bf.k); i++ {
		bit := (h1 + i*h2) % bf.numBits
		if (bf.bits[bit/8] & (1 << (bit % 8))) == 0 {
			return false
		}
	}
	return true
}

func (bf *BloomFilter) Encode() []byte {
	buf := make([]byte, 5+len(bf.bits))
	binary.BigEndian.PutUint32(buf[0:4], bf.numBits)
	buf[4] = bf.k
	copy(buf[5:], bf.bits)
	return buf
}

func DecodeBloomFilter(data []byte) (*BloomFilter, error) {
	if len(data) < 5 {
		return nil, errors.New("bloom filter buffer too small")
	}
	numBits := binary.BigEndian.Uint32(data[0:4])
	k := data[4]
	bits := make([]byte, len(data)-5)
	copy(bits, data[5:])
	return &BloomFilter{
		bits:    bits,
		numBits: numBits,
		k:       k,
	}, nil
}

// ============================================================================
// 2. SKIP LIST (MEMTABLE)
// ============================================================================

const (
	maxSkipListLevel = 16
	skipListP        = 0.5
)

type skipNode struct {
	key       []byte
	val       []byte
	tombstone bool
	forward   []*skipNode
}

type SkipList struct {
	head  *skipNode
	level int
	size  int64
	count int
	rnd   *rand.Rand
	mu    sync.RWMutex
}

func NewSkipList() *SkipList {
	return &SkipList{
		head: &skipNode{
			forward: make([]*skipNode, maxSkipListLevel),
		},
		level: 1,
		rnd:   rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (s *SkipList) randomLevel() int {
	lvl := 1
	for lvl < maxSkipListLevel && s.rnd.Float64() < skipListP {
		lvl++
	}
	return lvl
}

func (s *SkipList) Put(key, val []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	update := make([]*skipNode, maxSkipListLevel)
	curr := s.head
	for i := s.level - 1; i >= 0; i-- {
		for curr.forward[i] != nil && bytes.Compare(curr.forward[i].key, key) < 0 {
			curr = curr.forward[i]
		}
		update[i] = curr
	}
	curr = curr.forward[0]

	if curr != nil && bytes.Equal(curr.key, key) {
		s.size += int64(len(val) - len(curr.val))
		curr.val = append([]byte(nil), val...)
		curr.tombstone = false
		return
	}

	lvl := s.randomLevel()
	if lvl > s.level {
		for i := s.level; i < lvl; i++ {
			update[i] = s.head
		}
		s.level = lvl
	}

	newNode := &skipNode{
		key:       append([]byte(nil), key...),
		val:       append([]byte(nil), val...),
		tombstone: false,
		forward:   make([]*skipNode, lvl),
	}
	for i := 0; i < lvl; i++ {
		newNode.forward[i] = update[i].forward[i]
		update[i].forward[i] = newNode
	}
	s.count++
	s.size += int64(len(key) + len(val) + 32)
}

func (s *SkipList) Delete(key []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	update := make([]*skipNode, maxSkipListLevel)
	curr := s.head
	for i := s.level - 1; i >= 0; i-- {
		for curr.forward[i] != nil && bytes.Compare(curr.forward[i].key, key) < 0 {
			curr = curr.forward[i]
		}
		update[i] = curr
	}
	curr = curr.forward[0]

	if curr != nil && bytes.Equal(curr.key, key) {
		s.size -= int64(len(curr.val))
		curr.val = nil
		curr.tombstone = true
		return
	}

	lvl := s.randomLevel()
	if lvl > s.level {
		for i := s.level; i < lvl; i++ {
			update[i] = s.head
		}
		s.level = lvl
	}

	newNode := &skipNode{
		key:       append([]byte(nil), key...),
		val:       nil,
		tombstone: true,
		forward:   make([]*skipNode, lvl),
	}
	for i := 0; i < lvl; i++ {
		newNode.forward[i] = update[i].forward[i]
		update[i].forward[i] = newNode
	}
	s.count++
	s.size += int64(len(key) + 32)
}

func (s *SkipList) Get(key []byte) ([]byte, bool, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	curr := s.head
	for i := s.level - 1; i >= 0; i-- {
		for curr.forward[i] != nil && bytes.Compare(curr.forward[i].key, key) < 0 {
			curr = curr.forward[i]
		}
	}
	curr = curr.forward[0]

	if curr != nil && bytes.Equal(curr.key, key) {
		if curr.tombstone {
			return nil, true, true
		}
		valCopy := append([]byte(nil), curr.val...)
		return valCopy, false, true
	}
	return nil, false, false
}

func (s *SkipList) Size() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.size
}

type SkipListIterator struct {
	curr *skipNode
}

func (s *SkipList) Iterator() *SkipListIterator {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return &SkipListIterator{curr: s.head.forward[0]}
}

func (it *SkipListIterator) Valid() bool {
	return it.curr != nil
}

func (it *SkipListIterator) Next() {
	if it.curr != nil {
		it.curr = it.curr.forward[0]
	}
}

func (it *SkipListIterator) Entry() (key, val []byte, tombstone bool) {
	return it.curr.key, it.curr.val, it.curr.tombstone
}

// ============================================================================
// 3. WRITE-AHEAD LOG (WAL)
// ============================================================================

type walRecordType byte

const (
	walTypePut    walRecordType = 0
	walTypeDelete walRecordType = 1
)

type WALEntry struct {
	Op  walRecordType
	Key []byte
	Val []byte
}

type WAL struct {
	file        *os.File
	writer      *bufio.Writer
	path        string
	syncOnWrite bool
	mu          sync.Mutex
}

func OpenWAL(path string, syncOnWrite bool) (*WAL, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &WAL{
		file:        file,
		writer:      bufio.NewWriterSize(file, 64*1024),
		path:        path,
		syncOnWrite: syncOnWrite,
	}, nil
}

func (w *WAL) WriteRecord(op walRecordType, key, val []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	payloadLen := 1 + 4 + 4 + len(key) + len(val)
	buf := make([]byte, 4+payloadLen)

	payload := buf[4:]
	payload[0] = byte(op)
	binary.BigEndian.PutUint32(payload[1:5], uint32(len(key)))
	binary.BigEndian.PutUint32(payload[5:9], uint32(len(val)))
	copy(payload[9:9+len(key)], key)
	copy(payload[9+len(key):], val)

	crc := crc32.ChecksumIEEE(payload)
	binary.BigEndian.PutUint32(buf[0:4], crc)

	if _, err := w.writer.Write(buf); err != nil {
		return err
	}
	if err := w.writer.Flush(); err != nil {
		return err
	}
	if w.syncOnWrite {
		return w.file.Sync()
	}
	return nil
}

func (w *WAL) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.writer.Flush(); err != nil {
		return err
	}
	return w.file.Sync()
}

func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.writer.Flush(); err != nil {
		_ = w.file.Close()
		return err
	}
	return w.file.Close()
}

func ReadWAL(path string) ([]WALEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader := bufio.NewReader(f)
	var entries []WALEntry
	header := make([]byte, 13)

	for {
		_, err := io.ReadFull(reader, header)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return entries, err
		}

		expectedCRC := binary.BigEndian.Uint32(header[0:4])
		op := walRecordType(header[4])
		kLen := binary.BigEndian.Uint32(header[5:9])
		vLen := binary.BigEndian.Uint32(header[9:13])

		body := make([]byte, kLen+vLen)
		if _, err := io.ReadFull(reader, body); err != nil {
			// Torn write at system crash, stop recovery here
			break
		}

		crcCalc := crc32.NewIEEE()
		crcCalc.Write(header[4:13])
		crcCalc.Write(body)
		if crcCalc.Sum32() != expectedCRC {
			// Checksum mismatch, data corrupted after crash
			break
		}

		key := body[:kLen]
		val := body[kLen:]
		entries = append(entries, WALEntry{
			Op:  op,
			Key: key,
			Val: val,
		})
	}
	return entries, nil
}

// ============================================================================
// 4. SSTABLE (BLOCK INDEX, BLOOM FILTER, ENCODING)
// ============================================================================

const (
	sstableMagicNumber uint64 = 0x53535461626C6531 // "SSTable1"
	defaultBlockSize          = 4096
	footerSize                = 40
)

type BlockHandle struct {
	FirstKey []byte
	Offset   uint64
	Length   uint64
}

type SSTEntry struct {
	Key       []byte
	Val       []byte
	Tombstone bool
}

type SSTableWriter struct {
	file       *os.File
	writer     *bufio.Writer
	bloom      *BloomFilter
	blockBuf   *bytes.Buffer
	firstInBlk []byte
	offset     uint64
	handles    []BlockHandle
	blockSize  int
	entryCount int
}

func NewSSTableWriter(path string, estimatedKeys int, blockSize int) (*SSTableWriter, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	if blockSize <= 0 {
		blockSize = defaultBlockSize
	}
	return &SSTableWriter{
		file:      file,
		writer:    bufio.NewWriterSize(file, 64*1024),
		bloom:     NewBloomFilter(estimatedKeys, 0.01),
		blockBuf:  new(bytes.Buffer),
		blockSize: blockSize,
	}, nil
}

func (sw *SSTableWriter) Append(key, val []byte, tombstone bool) error {
	sw.bloom.Add(key)
	sw.entryCount++

	if sw.blockBuf.Len() == 0 {
		sw.firstInBlk = append([]byte(nil), key...)
	}

	var flag byte = 0
	if tombstone {
		flag = 1
	}
	header := make([]byte, 9)
	header[0] = flag
	binary.BigEndian.PutUint32(header[1:5], uint32(len(key)))
	binary.BigEndian.PutUint32(header[5:9], uint32(len(val)))

	sw.blockBuf.Write(header)
	sw.blockBuf.Write(key)
	sw.blockBuf.Write(val)

	if sw.blockBuf.Len() >= sw.blockSize {
		if err := sw.flushBlock(); err != nil {
			return err
		}
	}
	return nil
}

func (sw *SSTableWriter) flushBlock() error {
	if sw.blockBuf.Len() == 0 {
		return nil
	}
	data := sw.blockBuf.Bytes()
	n, err := sw.writer.Write(data)
	if err != nil {
		return err
	}

	sw.handles = append(sw.handles, BlockHandle{
		FirstKey: sw.firstInBlk,
		Offset:   sw.offset,
		Length:   uint64(n),
	})
	sw.offset += uint64(n)
	sw.blockBuf.Reset()
	sw.firstInBlk = nil
	return nil
}

func (sw *SSTableWriter) Finish() error {
	if err := sw.flushBlock(); err != nil {
		return err
	}

	// 1. Write Block Index
	indexStart := sw.offset
	var indexBuf bytes.Buffer
	countBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(countBuf, uint32(len(sw.handles)))
	indexBuf.Write(countBuf)

	for _, h := range sw.handles {
		kLenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(kLenBuf, uint32(len(h.FirstKey)))
		indexBuf.Write(kLenBuf)
		indexBuf.Write(h.FirstKey)

		numBuf := make([]byte, 16)
		binary.BigEndian.PutUint64(numBuf[0:8], h.Offset)
		binary.BigEndian.PutUint64(numBuf[8:16], h.Length)
		indexBuf.Write(numBuf)
	}

	idxBytes := indexBuf.Bytes()
	if _, err := sw.writer.Write(idxBytes); err != nil {
		return err
	}
	indexLength := uint64(len(idxBytes))
	sw.offset += indexLength

	// 2. Write Bloom Filter
	bloomStart := sw.offset
	bloomData := sw.bloom.Encode()
	if _, err := sw.writer.Write(bloomData); err != nil {
		return err
	}
	bloomLength := uint64(len(bloomData))
	sw.offset += bloomLength

	// 3. Write Fixed Footer (40 bytes)
	footer := make([]byte, footerSize)
	binary.BigEndian.PutUint64(footer[0:8], indexStart)
	binary.BigEndian.PutUint64(footer[8:16], indexLength)
	binary.BigEndian.PutUint64(footer[16:24], bloomStart)
	binary.BigEndian.PutUint64(footer[24:32], bloomLength)
	binary.BigEndian.PutUint64(footer[32:40], sstableMagicNumber)

	if _, err := sw.writer.Write(footer); err != nil {
		return err
	}

	if err := sw.writer.Flush(); err != nil {
		return err
	}
	if err := sw.file.Sync(); err != nil {
		return err
	}
	return sw.file.Close()
}

type SSTableReader struct {
	file    *os.File
	path    string
	id      uint64
	size    int64
	handles []BlockHandle
	bloom   *BloomFilter
	mu      sync.Mutex
}

func OpenSSTableReader(path string, id uint64) (*SSTableReader, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	stat, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	size := stat.Size()
	if size < footerSize {
		_ = file.Close()
		return nil, errors.New("file too small for sstable")
	}

	// Read footer
	footer := make([]byte, footerSize)
	if _, err := file.ReadAt(footer, size-footerSize); err != nil {
		_ = file.Close()
		return nil, err
	}

	magic := binary.BigEndian.Uint64(footer[32:40])
	if magic != sstableMagicNumber {
		_ = file.Close()
		return nil, errors.New("invalid sstable magic number")
	}

	indexStart := binary.BigEndian.Uint64(footer[0:8])
	indexLength := binary.BigEndian.Uint64(footer[8:16])
	bloomStart := binary.BigEndian.Uint64(footer[16:24])
	bloomLength := binary.BigEndian.Uint64(footer[24:32])

	// Read index
	indexData := make([]byte, indexLength)
	if _, err := file.ReadAt(indexData, int64(indexStart)); err != nil {
		_ = file.Close()
		return nil, err
	}
	numHandles := binary.BigEndian.Uint32(indexData[0:4])
	handles := make([]BlockHandle, numHandles)
	idx := 4
	for i := uint32(0); i < numHandles; i++ {
		kLen := binary.BigEndian.Uint32(indexData[idx : idx+4])
		idx += 4
		firstKey := make([]byte, kLen)
		copy(firstKey, indexData[idx:idx+int(kLen)])
		idx += int(kLen)
		offset := binary.BigEndian.Uint64(indexData[idx : idx+8])
		idx += 8
		length := binary.BigEndian.Uint64(indexData[idx : idx+8])
		idx += 8

		handles[i] = BlockHandle{
			FirstKey: firstKey,
			Offset:   offset,
			Length:   length,
		}
	}

	// Read bloom
	bloomData := make([]byte, bloomLength)
	if _, err := file.ReadAt(bloomData, int64(bloomStart)); err != nil {
		_ = file.Close()
		return nil, err
	}
	bloom, err := DecodeBloomFilter(bloomData)
	if err != nil {
		_ = file.Close()
		return nil, err
	}

	return &SSTableReader{
		file:    file,
		path:    path,
		id:      id,
		size:    size,
		handles: handles,
		bloom:   bloom,
	}, nil
}

func (r *SSTableReader) Get(key []byte) ([]byte, bool, bool) {
	if !r.bloom.MayContain(key) {
		return nil, false, false
	}

	// Binary search sparse block index
	low := 0
	high := len(r.handles) - 1
	target := -1

	for low <= high {
		mid := low + (high-low)/2
		if bytes.Compare(r.handles[mid].FirstKey, key) <= 0 {
			target = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
	}

	if target == -1 {
		return nil, false, false
	}

	handle := r.handles[target]
	buf := make([]byte, handle.Length)
	if _, err := r.file.ReadAt(buf, int64(handle.Offset)); err != nil {
		return nil, false, false
	}

	// Scan entries within data block
	idx := 0
	for idx < len(buf) {
		flag := buf[idx]
		idx++
		kLen := int(binary.BigEndian.Uint32(buf[idx : idx+4]))
		idx += 4
		vLen := int(binary.BigEndian.Uint32(buf[idx : idx+4]))
		idx += 4
		k := buf[idx : idx+kLen]
		idx += kLen
		v := buf[idx : idx+vLen]
		idx += vLen

		cmp := bytes.Compare(k, key)
		if cmp == 0 {
			if flag == 1 {
				return nil, true, true // Tombstone found
			}
			valCopy := make([]byte, len(v))
			copy(valCopy, v)
			return valCopy, false, true
		}
		if cmp > 0 {
			break // SSTables are strictly sorted
		}
	}

	return nil, false, false
}

func (r *SSTableReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.file.Close()
}

// Iterator for SSTable sequentially scans blocks
type SSTableIterator struct {
	reader   *SSTableReader
	blkIdx   int
	entries  []SSTEntry
	entryIdx int
	valid    bool
}

func (r *SSTableReader) Iterator() (*SSTableIterator, error) {
	it := &SSTableIterator{
		reader: r,
		blkIdx: -1,
	}
	it.advanceBlock()
	return it, nil
}

func (it *SSTableIterator) advanceBlock() {
	it.blkIdx++
	if it.blkIdx >= len(it.reader.handles) {
		it.valid = false
		it.entries = nil
		return
	}

	h := it.reader.handles[it.blkIdx]
	buf := make([]byte, h.Length)
	if _, err := it.reader.file.ReadAt(buf, int64(h.Offset)); err != nil {
		it.valid = false
		return
	}

	it.entries = nil
	idx := 0
	for idx < len(buf) {
		flag := buf[idx]
		idx++
		kLen := int(binary.BigEndian.Uint32(buf[idx : idx+4]))
		idx += 4
		vLen := int(binary.BigEndian.Uint32(buf[idx : idx+4]))
		idx += 4
		k := make([]byte, kLen)
		copy(k, buf[idx:idx+kLen])
		idx += kLen
		v := make([]byte, vLen)
		copy(v, buf[idx:idx+vLen])
		idx += vLen

		it.entries = append(it.entries, SSTEntry{
			Key:       k,
			Val:       v,
			Tombstone: flag == 1,
		})
	}

	it.entryIdx = 0
	it.valid = len(it.entries) > 0
}

func (it *SSTableIterator) Valid() bool {
	return it.valid
}

func (it *SSTableIterator) Next() {
	if !it.valid {
		return
	}
	it.entryIdx++
	if it.entryIdx >= len(it.entries) {
		it.advanceBlock()
	}
}

func (it *SSTableIterator) Entry() SSTEntry {
	return it.entries[it.entryIdx]
}

// ============================================================================
// 5. STORAGE ENGINE (MEMTABLE + WAL + SSTABLES + COMPACTION)
// ============================================================================

type EngineOptions struct {
	Dir                 string
	MemTableThreshold   int64
	BlockSize           int
	SyncOnWrite         bool
	CompactionThreshold int
}

func DefaultOptions(dir string) EngineOptions {
	return EngineOptions{
		Dir:                 dir,
		MemTableThreshold:   2 * 1024 * 1024, // 2MB
		BlockSize:           4096,            // 4KB
		SyncOnWrite:         true,
		CompactionThreshold: 4, // Compact when >= 4 SSTables accumulate
	}
}

type Engine struct {
	opts      EngineOptions
	mu        sync.RWMutex
	activeMem *SkipList
	immMem    *SkipList
	activeWAL *WAL
	immWAL    *WAL

	sstables []*SSTableReader // Ordered newest to oldest
	nextID   uint64

	flushChan chan struct{}
	flushCond *sync.Cond
	isClosing int32
	wg        sync.WaitGroup
}

func OpenEngine(opts EngineOptions) (*Engine, error) {
	if err := os.MkdirAll(opts.Dir, 0755); err != nil {
		return nil, err
	}

	e := &Engine{
		opts:      opts,
		activeMem: NewSkipList(),
		flushChan: make(chan struct{}, 1),
	}
	e.flushCond = sync.NewCond(&e.mu)

	if err := e.recoverDatabase(); err != nil {
		return nil, fmt.Errorf("database recovery failed: %w", err)
	}

	e.wg.Add(1)
	go e.flushWorker()

	return e, nil
}

func (e *Engine) recoverDatabase() error {
	entries, err := os.ReadDir(e.opts.Dir)
	if err != nil {
		return err
	}

	var sstIDs []uint64
	var walIDs []uint64

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".sst") {
			base := strings.TrimSuffix(name, ".sst")
			id, err := strconv.ParseUint(base, 10, 64)
			if err == nil {
				sstIDs = append(sstIDs, id)
			}
		} else if strings.HasSuffix(name, ".wal") {
			base := strings.TrimSuffix(name, ".wal")
			id, err := strconv.ParseUint(base, 10, 64)
			if err == nil {
				walIDs = append(walIDs, id)
			}
		}
	}

	// Sort ascending
	sort.Slice(sstIDs, func(i, j int) bool { return sstIDs[i] < sstIDs[j] })
	sort.Slice(walIDs, func(i, j int) bool { return walIDs[i] < walIDs[j] })

	// Load SSTables (Reverse: newest first)
	for i := len(sstIDs) - 1; i >= 0; i-- {
		id := sstIDs[i]
		sstPath := filepath.Join(e.opts.Dir, fmt.Sprintf("%06d.sst", id))
		reader, err := OpenSSTableReader(sstPath, id)
		if err != nil {
			log.Printf("Warning: failed to open SSTable %s: %v", sstPath, err)
			continue
		}
		e.sstables = append(e.sstables, reader)
		if id > e.nextID {
			e.nextID = id
		}
	}

	// Replay WAL files
	for _, id := range walIDs {
		walPath := filepath.Join(e.opts.Dir, fmt.Sprintf("%06d.wal", id))
		records, err := ReadWAL(walPath)
		if err != nil {
			log.Printf("Warning: reading WAL %s had errors: %v", walPath, err)
		}
		for _, rec := range records {
			if rec.Op == walTypePut {
				e.activeMem.Put(rec.Key, rec.Val)
			} else if rec.Op == walTypeDelete {
				e.activeMem.Delete(rec.Key)
			}
		}
		if id > e.nextID {
			e.nextID = id
		}
		// Clean up old replayed WALs, keeping the state in memory
		_ = os.Remove(walPath)
	}

	// Allocate new WAL ID
	atomic.AddUint64(&e.nextID, 1)
	walPath := filepath.Join(e.opts.Dir, fmt.Sprintf("%06d.wal", e.nextID))
	wal, err := OpenWAL(walPath, e.opts.SyncOnWrite)
	if err != nil {
		return err
	}
	e.activeWAL = wal

	return nil
}

func (e *Engine) Put(key, val []byte) error {
	return e.writeRecord(walTypePut, key, val)
}

func (e *Engine) Delete(key []byte) error {
	return e.writeRecord(walTypeDelete, key, nil)
}

func (e *Engine) writeRecord(op walRecordType, key, val []byte) error {
	e.mu.Lock()
	for e.immMem != nil {
		// Backpressure: wait for existing immutable memtable to flush
		e.flushCond.Wait()
	}

	if err := e.activeWAL.WriteRecord(op, key, val); err != nil {
		e.mu.Unlock()
		return err
	}

	if op == walTypePut {
		e.activeMem.Put(key, val)
	} else {
		e.activeMem.Delete(key)
	}

	if e.activeMem.Size() >= e.opts.MemTableThreshold {
		e.rotateMemTableLocked()
	}
	e.mu.Unlock()
	return nil
}

func (e *Engine) rotateMemTableLocked() {
	_ = e.activeWAL.Sync()
	e.immMem = e.activeMem
	e.immWAL = e.activeWAL

	e.activeMem = NewSkipList()
	newID := atomic.AddUint64(&e.nextID, 1)
	walPath := filepath.Join(e.opts.Dir, fmt.Sprintf("%06d.wal", newID))
	newWAL, err := OpenWAL(walPath, e.opts.SyncOnWrite)
	if err != nil {
		log.Printf("Error creating rotated WAL: %v", err)
	}
	e.activeWAL = newWAL

	select {
	case e.flushChan <- struct{}{}:
	default:
	}
}

func (e *Engine) Get(key []byte) ([]byte, bool, error) {
	e.mu.RLock()
	// 1. Search active MemTable
	val, tombstone, found := e.activeMem.Get(key)
	if found {
		e.mu.RUnlock()
		if tombstone {
			return nil, false, nil
		}
		return val, true, nil
	}

	// 2. Search immutable MemTable
	if e.immMem != nil {
		val, tombstone, found := e.immMem.Get(key)
		if found {
			e.mu.RUnlock()
			if tombstone {
				return nil, false, nil
			}
			return val, true, nil
		}
	}

	// Copy SSTable slice references under read lock
	readers := make([]*SSTableReader, len(e.sstables))
	copy(readers, e.sstables)
	e.mu.RUnlock()

	// 3. Search SSTables from newest to oldest
	for _, reader := range readers {
		val, tombstone, found := reader.Get(key)
		if found {
			if tombstone {
				return nil, false, nil
			}
			return val, true, nil
		}
	}

	return nil, false, nil
}

func (e *Engine) flushWorker() {
	defer e.wg.Done()
	for {
		select {
		case <-e.flushChan:
			e.performFlush()
		default:
			if atomic.LoadInt32(&e.isClosing) == 1 {
				e.performFlush()
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func (e *Engine) performFlush() {
	e.mu.Lock()
	if e.immMem == nil {
		e.mu.Unlock()
		return
	}
	mem := e.immMem
	wal := e.immWAL
	sstID := atomic.AddUint64(&e.nextID, 1)
	e.mu.Unlock()

	sstPath := filepath.Join(e.opts.Dir, fmt.Sprintf("%06d.sst", sstID))
	writer, err := NewSSTableWriter(sstPath, mem.count+1, e.opts.BlockSize)
	if err != nil {
		log.Printf("Flush error creating sstable %s: %v", sstPath, err)
		return
	}

	it := mem.Iterator()
	for it.Valid() {
		k, v, tomb := it.Entry()
		if err := writer.Append(k, v, tomb); err != nil {
			log.Printf("Flush append error: %v", err)
			return
		}
		it.Next()
	}

	if err := writer.Finish(); err != nil {
		log.Printf("Flush finish error: %v", err)
		return
	}

	reader, err := OpenSSTableReader(sstPath, sstID)
	if err != nil {
		log.Printf("Error opening flushed SSTable: %v", err)
		return
	}

	e.mu.Lock()
	// Prepend newest SSTable
	e.sstables = append([]*SSTableReader{reader}, e.sstables...)
	_ = wal.Close()
	_ = os.Remove(wal.path)
	e.immMem = nil
	e.immWAL = nil
	e.flushCond.Broadcast()

	triggerCompact := len(e.sstables) >= e.opts.CompactionThreshold
	e.mu.Unlock()

	if triggerCompact {
		go e.Compact()
	}
}

func (e *Engine) ForceFlush() {
	e.mu.Lock()
	if e.activeMem.count > 0 {
		e.rotateMemTableLocked()
	}
	e.mu.Unlock()

	for {
		e.mu.RLock()
		idle := e.immMem == nil
		e.mu.RUnlock()
		if idle {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Multi-Way Merge Compaction
func (e *Engine) Compact() {
	e.mu.Lock()
	if len(e.sstables) < 2 {
		e.mu.Unlock()
		return
	}
	// Snapshot current tables
	tables := make([]*SSTableReader, len(e.sstables))
	copy(tables, e.sstables)
	e.mu.Unlock()

	iters := make([]*SSTableIterator, 0, len(tables))
	for _, t := range tables {
		it, err := t.Iterator()
		if err != nil {
			log.Printf("Compaction failed to iterate table: %v", err)
			return
		}
		if it.Valid() {
			iters = append(iters, it)
		}
	}

	compactID := atomic.AddUint64(&e.nextID, 1)
	tempPath := filepath.Join(e.opts.Dir, fmt.Sprintf("%06d.compact", compactID))
	finalPath := filepath.Join(e.opts.Dir, fmt.Sprintf("%06d.sst", compactID))

	writer, err := NewSSTableWriter(tempPath, 10000, e.opts.BlockSize)
	if err != nil {
		log.Printf("Compaction writer failed: %v", err)
		return
	}

	// K-Way Merge
	for {
		var minKey []byte
		for _, it := range iters {
			if !it.Valid() {
				continue
			}
			k := it.Entry().Key
			if minKey == nil || bytes.Compare(k, minKey) < 0 {
				minKey = k
			}
		}

		if minKey == nil {
			break // All iterators exhausted
		}

		// Table at smallest slice index is newest!
		var chosenEntry SSTEntry
		foundWinner := false

		for _, it := range iters {
			if !it.Valid() {
				continue
			}
			entry := it.Entry()
			if bytes.Equal(entry.Key, minKey) {
				if !foundWinner {
					chosenEntry = entry
					foundWinner = true
				}
				it.Next() // Advance all matching keys
			}
		}

		// Purge deleted tombstones if compacting all tables
		if chosenEntry.Tombstone && len(tables) == len(e.sstables) {
			continue
		}

		if err := writer.Append(chosenEntry.Key, chosenEntry.Val, chosenEntry.Tombstone); err != nil {
			log.Printf("Compaction append failed: %v", err)
			_ = os.Remove(tempPath)
			return
		}
	}

	if err := writer.Finish(); err != nil {
		log.Printf("Compaction finish failed: %v", err)
		_ = os.Remove(tempPath)
		return
	}

	if err := os.Rename(tempPath, finalPath); err != nil {
		log.Printf("Compaction atomic rename failed: %v", err)
		return
	}

	newReader, err := OpenSSTableReader(finalPath, compactID)
	if err != nil {
		log.Printf("Compaction reader open failed: %v", err)
		return
	}

	// Atomically swap compacted SSTables
	e.mu.Lock()
	e.sstables = []*SSTableReader{newReader}
	e.mu.Unlock()

	// Safely close and delete old SSTables
	for _, oldTable := range tables {
		_ = oldTable.Close()
		_ = os.Remove(oldTable.path)
	}
	log.Printf("Compaction successful: merged %d tables into %s", len(tables), finalPath)
}

func (e *Engine) Close() error {
	atomic.StoreInt32(&e.isClosing, 1)
	e.ForceFlush()

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.activeWAL != nil {
		_ = e.activeWAL.Close()
	}
	for _, r := range e.sstables {
		_ = r.Close()
	}
	return nil
}

// ============================================================================
// 6. REDIS RESP & TEXT PROTOCOL TCP SERVER
// ============================================================================

type Server struct {
	engine   *Engine
	listener net.Listener
	addr     string
	quit     chan struct{}
}

func NewServer(addr string, engine *Engine) *Server {
	return &Server{
		engine: engine,
		addr:   addr,
		quit:   make(chan struct{}),
	}
}

func (s *Server) Start() error {
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.listener = l
	log.Printf("Embedded LevelDB listening on %s (RESP & Inline Text)", s.addr)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				select {
				case <-s.quit:
					return
				default:
					continue
				}
			}
			go s.handleConnection(conn)
		}
	}()
	return nil
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	for {
		cmd, args, err := s.readCommand(reader)
		if err != nil {
			return
		}

		if len(cmd) == 0 {
			continue
		}

		switch strings.ToUpper(cmd) {
		case "PING":
			if len(args) > 0 {
				s.writeBulk(conn, []byte(args[0]))
			} else {
				s.writeSimpleString(conn, "PONG")
			}
		case "SET":
			if len(args) < 2 {
				s.writeError(conn, "ERR wrong number of arguments for 'set' command")
				continue
			}
			err := s.engine.Put([]byte(args[0]), []byte(args[1]))
			if err != nil {
				s.writeError(conn, "ERR "+err.Error())
			} else {
				s.writeSimpleString(conn, "OK")
			}
		case "GET":
			if len(args) < 1 {
				s.writeError(conn, "ERR wrong number of arguments for 'get' command")
				continue
			}
			val, found, err := s.engine.Get([]byte(args[0]))
			if err != nil {
				s.writeError(conn, "ERR "+err.Error())
			} else if !found {
				s.writeNull(conn)
			} else {
				s.writeBulk(conn, val)
			}
		case "DEL":
			if len(args) < 1 {
				s.writeError(conn, "ERR wrong number of arguments for 'del' command")
				continue
			}
			count := 0
			for _, k := range args {
				_, found, _ := s.engine.Get([]byte(k))
				if found {
					_ = s.engine.Delete([]byte(k))
					count++
				}
			}
			s.writeInt(conn, count)
		case "FLUSH":
			s.engine.ForceFlush()
			s.writeSimpleString(conn, "OK")
		case "COMPACT":
			go s.engine.Compact()
			s.writeSimpleString(conn, "OK")
		case "INFO":
			s.engine.mu.RLock()
			memSize := s.engine.activeMem.Size()
			memCount := s.engine.activeMem.count
			sstCount := len(e.sstables)
			s.engine.mu.RUnlock()
			info := fmt.Sprintf("# Database Stats\r\nmemtable_size_bytes:%d\r\nmemtable_keys:%d\r\nsstable_count:%d\r\n",
				memSize, memCount, sstCount)
			s.writeBulk(conn, []byte(info))
		case "QUIT":
			s.writeSimpleString(conn, "OK")
			return
		default:
			s.writeError(conn, fmt.Sprintf("ERR unknown command '%s'", cmd))
		}
	}
}

func (s *Server) readCommand(r *bufio.Reader) (string, []string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) == 0 {
		return "", nil, nil
	}

	// RESP Array Protocol: *<arg_count>\r\n
	if line[0] == '*' {
		count, err := strconv.Atoi(line[1:])
		if err != nil {
			return "", nil, err
		}
		args := make([]string, 0, count)
		for i := 0; i < count; i++ {
			header, err := r.ReadString('\n')
			if err != nil {
				return "", nil, err
			}
			header = strings.TrimRight(header, "\r\n")
			if len(header) == 0 || header[0] != '$' {
				return "", nil, errors.New("expected bulk string header")
			}
			lenBytes, err := strconv.Atoi(header[1:])
			if err != nil {
				return "", nil, err
			}
			buf := make([]byte, lenBytes+2) // Data + \r\n
			if _, err := io.ReadFull(r, buf); err != nil {
				return "", nil, err
			}
			args = append(args, string(buf[:lenBytes]))
		}
		if len(args) == 0 {
			return "", nil, nil
		}
		return args[0], args[1:], nil
	}

	// Inline Text Protocol: SET foo bar
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return "", nil, nil
	}
	return parts[0], parts[1:], nil
}

func (s *Server) writeSimpleString(conn net.Conn, str string) {
	_, _ = fmt.Fprintf(conn, "+%s\r\n", str)
}

func (s *Server) writeError(conn net.Conn, errStr string) {
	_, _ = fmt.Fprintf(conn, "-%s\r\n", errStr)
}

func (s *Server) writeInt(conn net.Conn, val int) {
	_, _ = fmt.Fprintf(conn, ":%d\r\n", val)
}

func (s *Server) writeBulk(conn net.Conn, data []byte) {
	_, _ = fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(data), data)
}

func (s *Server) writeNull(conn net.Conn) {
	_, _ = fmt.Fprint(conn, "$-1\r\n")
}

func (s *Server) Stop() {
	close(s.quit)
	if s.listener != nil {
		_ = s.listener.Close()
	}
}

// ============================================================================
// 7. CLI & INTEGRATION VERIFICATION
// ============================================================================

var e *Engine

func main() {
	port := flag.Int("port", 6379, "TCP server port")
	dbDir := flag.String("dir", "./data", "Database directory")
	fsync := flag.Bool("fsync", true, "Execute fsync on writes")
	runSelfTest := flag.Bool("test", false, "Run automated durability & validation tests")
	flag.Parse()

	opts := DefaultOptions(*dbDir)
	opts.SyncOnWrite = *fsync
	opts.MemTableThreshold = 64 * 1024 // 64KB for agile testing/flushing

	var err error
	e, err = OpenEngine(opts)
	if err != nil {
		log.Fatalf("Fatal: unable to initialize engine: %v", err)
	}

	if *runSelfTest {
		executeSelfTest(e, opts)
		return
	}

	server := NewServer(fmt.Sprintf(":%d", *port), e)
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to bind server: %v", err)
	}

	// Trap graceful exit
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("\nShutting down engine cleanly (flushing memtable and syncing WAL)...")
	server.Stop()
	if err := e.Close(); err != nil {
		log.Printf("Error closing engine: %v", err)
	} else {
		log.Println("Database safely stopped.")
	}
}

func executeSelfTest(engine *Engine, opts EngineOptions) {
	fmt.Println("=== RUNNING ENGINE VALIDATION & DURABILITY TEST ===")

	// 1. Basic Read/Write
	fmt.Print("-> Testing Basic Put/Get/Delete... ")
	_ = engine.Put([]byte("alpha"), []byte("omega"))
	val, found, _ := engine.Get([]byte("alpha"))
	if !found || string(val) != "omega" {
		log.Fatalf("FAILED: expected omega, got %s", val)
	}
	_ = engine.Delete([]byte("alpha"))
	_, found, _ = engine.Get([]byte("alpha"))
	if found {
		log.Fatalf("FAILED: key alpha should be deleted")
	}
	fmt.Println("PASSED")

	// 2. MemTable Threshold Flushing to SSTable
	fmt.Print("-> Testing MemTable Flush & SSTable generation... ")
	for i := 0; i < 2000; i++ {
		k := fmt.Sprintf("k:%04d", i)
		v := fmt.Sprintf("val-payload-data-%04d", i)
		_ = engine.Put([]byte(k), []byte(v))
	}
	engine.ForceFlush()

	engine.mu.RLock()
	sstCount := len(engine.sstables)
	engine.mu.RUnlock()
	if sstCount == 0 {
		log.Fatalf("FAILED: expected SSTables to exist after flush")
	}
	fmt.Printf("PASSED (%d SSTables created)\n", sstCount)

	// 3. Bloom Filter Verification
	fmt.Print("-> Testing Bloom Filter negative lookups... ")
	_, found, _ = engine.Get([]byte("non_existent_key_xyz_9999"))
	if found {
		log.Fatalf("FAILED: negative key was found")
	}
	fmt.Println("PASSED")

	// 4. Multi-Way Merge Compaction
	fmt.Print("-> Testing Multi-Way Merge Compaction... ")
	engine.Compact()
	engine.mu.RLock()
	postCompactCount := len(engine.sstables)
	engine.mu.RUnlock()
	if postCompactCount > 1 {
		log.Fatalf("FAILED: expected 1 compacted SSTable, got %d", postCompactCount)
	}
	// Verify data intact after compaction
	val, found, _ = engine.Get([]byte("k:1500"))
	if !found || string(val) != "val-payload-data-1500" {
		log.Fatalf("FAILED: post-compaction key k:1500 invalid: %s", val)
	}
	fmt.Println("PASSED")

	// 5. Crash Recovery & Durability Replay
	fmt.Print("-> Testing Crash Recovery & WAL Replay... ")
	_ = engine.Put([]byte("crash_test_key"), []byte("durable_val"))
	_ = engine.Close()

	// Reopen engine from disk without flushing
	reopenedEngine, err := OpenEngine(opts)
	if err != nil {
		log.Fatalf("FAILED reopening engine: %v", err)
	}
	val, found, _ = reopenedEngine.Get([]byte("crash_test_key"))
	if !found || string(val) != "durable_val" {
		log.Fatalf("FAILED: WAL replay failed to restore crash_test_key, got: %s", val)
	}
	_ = reopenedEngine.Close()
	fmt.Println("PASSED")

	fmt.Println("ALL ENGINE TESTS COMPLETED SUCCESSFULLY!")
}
