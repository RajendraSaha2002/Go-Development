package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ============================================================================
// 1. CUSTOM LATENCY HISTOGRAM & METRICS REGISTRY
// ============================================================================

// Buckets in milliseconds
var defaultBuckets = []float64{
	0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0,
}

type LatencyHistogram struct {
	mu           sync.RWMutex
	buckets      []float64
	bucketCounts []uint64
	count        uint64
	sum          float64 // in ms
	min          float64
	max          float64
}

func NewLatencyHistogram(buckets []float64) *LatencyHistogram {
	if len(buckets) == 0 {
		buckets = defaultBuckets
	}
	sorted := make([]float64, len(buckets))
	copy(sorted, buckets)
	sort.Float64s(sorted)

	return &LatencyHistogram{
		buckets:      sorted,
		bucketCounts: make([]uint64, len(sorted)),
		min:          math.MaxFloat64,
	}
}

func (h *LatencyHistogram) Record(valMs float64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.count++
	h.sum += valMs
	if valMs < h.min {
		h.min = valMs
	}
	if valMs > h.max {
		h.max = valMs
	}

	for i, b := range h.buckets {
		if valMs <= b {
			h.bucketCounts[i]++
			return
		}
	}
}

func (h *LatencyHistogram) Percentile(p float64) float64 {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.count == 0 {
		return 0.0
	}
	targetRank := uint64(math.Ceil(p * float64(h.count)))
	var accumulated uint64

	for i, count := range h.bucketCounts {
		accumulated += count
		if accumulated >= targetRank {
			return h.buckets[i]
		}
	}
	return h.max
}

type MetricsSnapshot struct {
	TotalRequests      uint64             `json:"total_requests"`
	Total2xx           uint64             `json:"total_2xx"`
	Total4xx           uint64             `json:"total_4xx"`
	Total5xx           uint64             `json:"total_5xx"`
	RateLimitedDrops   uint64             `json:"rate_limited_drops"`
	CircuitBreakerDrop uint64             `json:"circuit_breaker_drops"`
	LatencyP50Ms       float64            `json:"latency_p50_ms"`
	LatencyP90Ms       float64            `json:"latency_p90_ms"`
	LatencyP95Ms       float64            `json:"latency_p95_ms"`
	LatencyP99Ms       float64            `json:"latency_p99_ms"`
	LatencyAvgMs       float64            `json:"latency_avg_ms"`
	Backends           []BackendTelemetry `json:"backends"`
}

type BackendTelemetry struct {
	URL          string `json:"url"`
	Alive        bool   `json:"alive"`
	CBState      string `json:"circuit_breaker_state"`
	ActiveConns  int64  `json:"active_connections"`
	TotalServed  uint64 `json:"total_requests_served"`
	FailedProbes uint64 `json:"failed_probes"`
}

type MetricsRegistry struct {
	requestsTotal      uint64
	status2xx          uint64
	status4xx          uint64
	status5xx          uint64
	rateLimitedDrops   uint64
	circuitBreakerDrop uint64
	histogram          *LatencyHistogram
}

func NewMetricsRegistry() *MetricsRegistry {
	return &MetricsRegistry{
		histogram: NewLatencyHistogram(defaultBuckets),
	}
}

// ============================================================================
// 2. TOKEN-BUCKET RATE LIMITER
// ============================================================================

type TokenBucket struct {
	capacity   float64
	tokens     float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	mu         sync.Mutex
}

func NewTokenBucket(capacity, refillRate float64) *TokenBucket {
	return &TokenBucket{
		capacity:   capacity,
		tokens:     capacity,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.lastRefill = now

	// Refill tokens
	tb.tokens = math.Min(tb.capacity, tb.tokens+(elapsed*tb.refillRate))

	if tb.tokens >= 1.0 {
		tb.tokens -= 1.0
		return true
	}
	return false
}

type IPRateLimiter struct {
	mu         sync.RWMutex
	buckets    map[string]*TokenBucket
	capacity   float64
	refillRate float64
}

func NewIPRateLimiter(capacity, refillRate float64) *IPRateLimiter {
	limiter := &IPRateLimiter{
		buckets:    make(map[string]*TokenBucket),
		capacity:   capacity,
		refillRate: refillRate,
	}
	// Background cleanup of stale buckets
	go func() {
		ticker := time.NewTicker(3 * time.Minute)
		for range ticker.C {
			limiter.mu.Lock()
			now := time.Now()
			for ip, b := range limiter.buckets {
				b.mu.Lock()
				if now.Sub(b.lastRefill) > 5*time.Minute {
					delete(limiter.buckets, ip)
				}
				b.mu.Unlock()
			}
			limiter.mu.Unlock()
		}
	}()
	return limiter
}

func (l *IPRateLimiter) Allow(ip string) bool {
	l.mu.RLock()
	bucket, exists := l.buckets[ip]
	l.mu.RUnlock()

	if !exists {
		l.mu.Lock()
		bucket, exists = l.buckets[ip]
		if !exists {
			bucket = NewTokenBucket(l.capacity, l.refillRate)
			l.buckets[ip] = bucket
		}
		l.mu.Unlock()
	}
	return bucket.Allow()
}

// ============================================================================
// 3. CIRCUIT BREAKER
// ============================================================================

type CBState int

const (
	StateClosed CBState = iota
	StateHalfOpen
	StateOpen
)

func (s CBState) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateHalfOpen:
		return "HALF-OPEN"
	case StateOpen:
		return "OPEN"
	default:
		return "UNKNOWN"
	}
}

type CircuitBreaker struct {
	mu               sync.RWMutex
	state            CBState
	failureThreshold uint32
	successThreshold uint32
	recoveryTimeout  time.Duration
	consecutiveFails uint32
	consecutiveWins  uint32
	lastStateChange  time.Time
}

func NewCircuitBreaker(fails uint32, recovery time.Duration, wins uint32) *CircuitBreaker {
	return &CircuitBreaker{
		state:            StateClosed,
		failureThreshold: fails,
		recoveryTimeout:  recovery,
		successThreshold: wins,
		lastStateChange:  time.Now(),
	}
}

func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()
	if cb.state == StateOpen {
		if now.Sub(cb.lastStateChange) >= cb.recoveryTimeout {
			cb.state = StateHalfOpen
			cb.consecutiveWins = 0
			cb.lastStateChange = now
			return true // Allow canary trial
		}
		return false
	}
	return true
}

func (cb *CircuitBreaker) OnSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == StateHalfOpen {
		cb.consecutiveWins++
		if cb.consecutiveWins >= cb.successThreshold {
			cb.state = StateClosed
			cb.consecutiveFails = 0
			cb.lastStateChange = time.Now()
		}
	} else if cb.state == StateClosed {
		cb.consecutiveFails = 0
	}
}

func (cb *CircuitBreaker) OnFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.consecutiveFails++
	if cb.state == StateHalfOpen || cb.consecutiveFails >= cb.failureThreshold {
		cb.state = StateOpen
		cb.lastStateChange = time.Now()
	}
}

func (cb *CircuitBreaker) State() CBState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// ============================================================================
// 4. BACKEND & CONNECTION-POOLED REVERSE PROXY
// ============================================================================

type Backend struct {
	URL            *url.URL
	Alive          bool
	ActiveConns    int64
	TotalServed    uint64
	FailedProbes   uint64
	CircuitBreaker *CircuitBreaker
	ReverseProxy   *httputil.ReverseProxy
	mu             sync.RWMutex
}

func NewBackend(rawURL string, transport *http.Transport) (*Backend, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	b := &Backend{
		URL:            u,
		Alive:          true,
		CircuitBreaker: NewCircuitBreaker(3, 5*time.Second, 2),
	}

	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.Transport = transport

	// Custom Director appending standard proxy forwarding headers
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Header.Set("X-Forwarded-Proto", "http")
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Set("X-Served-By", u.String())
		return nil
	}

	b.ReverseProxy = proxy
	return b, nil
}

func (b *Backend) IsAvailable() bool {
	b.mu.RLock()
	alive := b.Alive
	b.mu.RUnlock()
	return alive && b.CircuitBreaker.Allow()
}

func (b *Backend) SetAlive(alive bool) {
	b.mu.Lock()
	b.Alive = alive
	b.mu.Unlock()
}

// ============================================================================
// 5. LOAD BALANCING STRATEGIES & CONSISTENT HASH RING
// ============================================================================

type Algorithm string

const (
	AlgoRoundRobin       Algorithm = "round-robin"
	AlgoLeastConnections Algorithm = "least-connections"
	AlgoConsistentHash   Algorithm = "consistent-hash"
)

type HashRing struct {
	mu      sync.RWMutex
	vnodes  int
	ring    []uint32
	nodeMap map[uint32]*Backend
}

func NewHashRing(vnodes int) *HashRing {
	return &HashRing{
		vnodes:  vnodes,
		nodeMap: make(map[uint32]*Backend),
	}
}

func hashKey(val string) uint32 {
	h := sha256.Sum256([]byte(val))
	return binary.BigEndian.Uint32(h[:4])
}

func (hr *HashRing) UpdateBackends(backends []*Backend) {
	hr.mu.Lock()
	defer hr.mu.Unlock()

	hr.ring = nil
	hr.nodeMap = make(map[uint32]*Backend)

	for _, b := range backends {
		for i := 0; i < hr.vnodes; i++ {
			vKey := fmt.Sprintf("%s#%d", b.URL.String(), i)
			h := hashKey(vKey)
			hr.ring = append(hr.ring, h)
			hr.nodeMap[h] = b
		}
	}
	sort.Slice(hr.ring, func(i, j int) bool { return hr.ring[i] < hr.ring[j] })
}

func (hr *HashRing) Route(key string) *Backend {
	hr.mu.RLock()
	defer hr.mu.RUnlock()

	if len(hr.ring) == 0 {
		return nil
	}

	h := hashKey(key)
	idx := sort.Search(len(hr.ring), func(i int) bool {
		return hr.ring[i] >= h
	})
	if idx == len(hr.ring) {
		idx = 0
	}

	// Walk ring clockwise to find first available backend
	for i := 0; i < len(hr.ring); i++ {
		candidate := hr.nodeMap[hr.ring[(idx+i)%len(hr.ring)]]
		if candidate.IsAvailable() {
			return candidate
		}
	}
	return nil
}

// ============================================================================
// 6. CORE REVERSE PROXY & LOAD BALANCER ENGINE
// ============================================================================

type LoadBalancer struct {
	backends    []*Backend
	algorithm   Algorithm
	rrIndex     uint64
	hashRing    *HashRing
	rateLimiter *IPRateLimiter
	metrics     *MetricsRegistry
	transport   *http.Transport
	mu          sync.RWMutex
}

func NewLoadBalancer(backendURLs []string, algo Algorithm) (*LoadBalancer, error) {
	// Connection Pool with HTTP Keep-Alives
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          1000,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	lb := &LoadBalancer{
		algorithm:   algo,
		hashRing:    NewHashRing(50),
		rateLimiter: NewIPRateLimiter(50, 20), // Burst: 50, Refill: 20 req/s
		metrics:     NewMetricsRegistry(),
		transport:   transport,
	}

	for _, raw := range backendURLs {
		b, err := NewBackend(raw, transport)
		if err != nil {
			return nil, err
		}
		lb.backends = append(lb.backends, b)
	}

	lb.hashRing.UpdateBackends(lb.backends)
	go lb.startActiveHealthChecker(3 * time.Second)

	return lb, nil
}

func (lb *LoadBalancer) SelectBackend(req *http.Request) *Backend {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	switch lb.algorithm {
	case AlgoLeastConnections:
		var best *Backend
		for _, b := range lb.backends {
			if !b.IsAvailable() {
				continue
			}
			if best == nil || atomic.LoadInt64(&b.ActiveConns) < atomic.LoadInt64(&best.ActiveConns) {
				best = b
			}
		}
		return best

	case AlgoConsistentHash:
		clientIP := getClientIP(req)
		return lb.hashRing.Route(clientIP)

	case AlgoRoundRobin:
		fallthrough
	default:
		total := uint64(len(lb.backends))
		for i := uint64(0); i < total; i++ {
			idx := (atomic.AddUint64(&lb.rrIndex, 1) - 1) % total
			candidate := lb.backends[idx]
			if candidate.IsAvailable() {
				return candidate
			}
		}
		return nil
	}
}

func (lb *LoadBalancer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Diagnostic & Metrics Endpoints
	if r.URL.Path == "/metrics" || r.URL.Path == "/_status" {
		lb.handleMetrics(w, r)
		return
	}

	start := time.Now()
	atomic.AddUint64(&lb.metrics.requestsTotal, 1)

	// Rate Limiting (Token Bucket)
	clientIP := getClientIP(r)
	if !lb.rateLimiter.Allow(clientIP) {
		atomic.AddUint64(&lb.metrics.rateLimitedDrops, 1)
		atomic.AddUint64(&lb.metrics.status4xx, 1)
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Too Many Requests (Rate limit exceeded)", http.StatusTooManyRequests)
		return
	}

	// Select Target Upstream Backend
	backend := lb.SelectBackend(r)
	if backend == nil {
		atomic.AddUint64(&lb.metrics.circuitBreakerDrop, 1)
		atomic.AddUint64(&lb.metrics.status5xx, 1)
		http.Error(w, "Service Unavailable (All backends offline or circuit open)", http.StatusServiceUnavailable)
		return
	}

	// Active Connections Accounting
	atomic.AddInt64(&backend.ActiveConns, 1)
	defer atomic.AddInt64(&backend.ActiveConns, -1)

	// Proxy Execution & Status Capturing
	rw := &responseInterceptor{ResponseWriter: w, statusCode: http.StatusOK}

	// Execute Reverse Proxy Request
	backend.ReverseProxy.ServeHTTP(rw, r)

	elapsed := float64(time.Since(start).Microseconds()) / 1000.0 // in ms
	lb.metrics.histogram.Record(elapsed)

	// Update Backend & Metrics Counters
	atomic.AddUint64(&backend.TotalServed, 1)
	if rw.statusCode >= 200 && rw.statusCode < 300 {
		atomic.AddUint64(&lb.metrics.status2xx, 1)
		backend.CircuitBreaker.OnSuccess()
	} else if rw.statusCode >= 400 && rw.statusCode < 500 {
		atomic.AddUint64(&lb.metrics.status4xx, 1)
	} else if rw.statusCode >= 500 {
		atomic.AddUint64(&lb.metrics.status5xx, 1)
		backend.CircuitBreaker.OnFailure() // Passive failure detection
	}
}

type responseInterceptor struct {
	http.ResponseWriter
	statusCode int
}

func (ri *responseInterceptor) WriteHeader(code int) {
	ri.statusCode = code
	ri.ResponseWriter.WriteHeader(code)
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// Active Background Health Checker (Periodic Pings)
func (lb *LoadBalancer) startActiveHealthChecker(interval time.Duration) {
	client := &http.Client{
		Timeout:   1500 * time.Millisecond,
		Transport: lb.transport,
	}

	ticker := time.NewTicker(interval)
	for range ticker.C {
		for _, b := range lb.backends {
			go func(b *Backend) {
				pingURL := fmt.Sprintf("%s://%s/health", b.URL.Scheme, b.URL.Host)
				resp, err := client.Get(pingURL)

				if err == nil && resp.StatusCode == http.StatusOK {
					b.SetAlive(true)
					b.CircuitBreaker.OnSuccess()
					_ = resp.Body.Close()
				} else {
					atomic.AddUint64(&b.FailedProbes, 1)
					b.CircuitBreaker.OnFailure()
					if b.CircuitBreaker.State() == StateOpen {
						b.SetAlive(false)
					}
					if resp != nil {
						_ = resp.Body.Close()
					}
				}
			}(b)
		}
	}
}

func (lb *LoadBalancer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	snap := MetricsSnapshot{
		TotalRequests:      atomic.LoadUint64(&lb.metrics.requestsTotal),
		Total2xx:           atomic.LoadUint64(&lb.metrics.status2xx),
		Total4xx:           atomic.LoadUint64(&lb.metrics.status4xx),
		Total5xx:           atomic.LoadUint64(&lb.metrics.status5xx),
		RateLimitedDrops:   atomic.LoadUint64(&lb.metrics.rateLimitedDrops),
		CircuitBreakerDrop: atomic.LoadUint64(&lb.metrics.circuitBreakerDrop),
		LatencyP50Ms:       lb.metrics.histogram.Percentile(0.50),
		LatencyP90Ms:       lb.metrics.histogram.Percentile(0.90),
		LatencyP95Ms:       lb.metrics.histogram.Percentile(0.95),
		LatencyP99Ms:       lb.metrics.histogram.Percentile(0.99),
	}

	lb.metrics.histogram.mu.RLock()
	if lb.metrics.histogram.count > 0 {
		snap.LatencyAvgMs = lb.metrics.histogram.sum / float64(lb.metrics.histogram.count)
	}
	lb.metrics.histogram.mu.RUnlock()

	lb.mu.RLock()
	for _, b := range lb.backends {
		b.mu.RLock()
		snap.Backends = append(snap.Backends, BackendTelemetry{
			URL:          b.URL.String(),
			Alive:        b.Alive,
			CBState:      b.CircuitBreaker.State().String(),
			ActiveConns:  atomic.LoadInt64(&b.ActiveConns),
			TotalServed:  atomic.LoadUint64(&b.TotalServed),
			FailedProbes: atomic.LoadUint64(&b.FailedProbes),
		})
		b.mu.RUnlock()
	}
	lb.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(snap)
}

// ============================================================================
// 7. SELF-CONTAINED BACKEND SIMULATION & TEST RUNNER
// ============================================================================

type UpstreamMock struct {
	server *http.Server
	port   int
	isDown int32
}

func startMockServer(port int, simulatedDelay time.Duration) *UpstreamMock {
	mock := &UpstreamMock{port: port}
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&mock.isDown) == 1 {
			http.Error(w, "Chaos: Down", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&mock.isDown) == 1 {
			http.Error(w, "Chaos Induced Error", http.StatusInternalServerError)
			return
		}
		if simulatedDelay > 0 {
			time.Sleep(simulatedDelay)
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintf(w, "Hello from Upstream Server :%d (Path: %s)\n", port, r.URL.Path)
	})

	mock.server = &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", port),
		Handler: mux,
	}

	go func() {
		_ = mock.server.ListenAndServe()
	}()
	return mock
}

func main() {
	proxyPort := flag.Int("port", 8080, "Load balancer proxy port")
	algoFlag := flag.String("algo", "round-robin", "Algorithm: 'round-robin', 'least-connections', 'consistent-hash'")
	flag.Parse()

	// Spin up 3 mock upstream servers with varying latencies
	s1 := startMockServer(9001, 10*time.Millisecond)
	s2 := startMockServer(9002, 25*time.Millisecond)
	s3 := startMockServer(9003, 50*time.Millisecond)
	defer s1.server.Close()
	defer s2.server.Close()
	defer s3.server.Close()

	time.Sleep(100 * time.Millisecond)

	backendURLs := []string{
		"http://127.0.0.1:9001",
		"http://127.0.0.1:9002",
		"http://127.0.0.1:9003",
	}

	algo := Algorithm(*algoFlag)
	lb, err := NewLoadBalancer(backendURLs, algo)
	if err != nil {
		log.Fatalf("Failed to initialize load balancer: %v", err)
	}

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", *proxyPort),
		Handler: lb,
	}

	go func() {
		log.Printf("[LOAD BALANCER] Listening on http://127.0.0.1:%d", *proxyPort)
		log.Printf("[STRATEGY] %s | Upstreams: %v", algo, backendURLs)
		log.Printf("[ENDPOINTS] Proxy: '/' | Metrics: '/metrics' or '/_status'")
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Server listen failed: %v", err)
		}
	}()

	// Automatic traffic generation & live dashboard runner
	go runDemonstrationTraffic(*proxyPort, s3)

	// Clean shutdown trap
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("\nShutting down Load Balancer gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}

func runDemonstrationTraffic(port int, chaosServer *UpstreamMock) {
	time.Sleep(500 * time.Millisecond)
	client := &http.Client{Timeout: 1 * time.Second}
	proxyBase := fmt.Sprintf("http://127.0.0.1:%d", port)

	fmt.Println("\n==========================================================================")
	fmt.Println(" RUNNING AUTOMATED LOAD GENERATION & FAULT INJECTION")
	fmt.Println("==========================================================================")

	// Fire initial distributed traffic
	for i := 0; i < 60; i++ {
		req, _ := http.NewRequest("GET", proxyBase+"/api/resource", nil)
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("192.168.1.%d", (i%4)+10))
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		time.Sleep(15 * time.Millisecond)
	}

	// Trigger Chaos: Fail Server 3 to demonstrate Circuit Breaking
	fmt.Println("\n>>> [CHAOS EVENT] Inducing failures on Server :9003 to trip Circuit Breaker...")
	atomic.StoreInt32(&chaosServer.isDown, 1)

	// Continue traffic to demonstrate circuit breaker opening and rerouting
	for i := 0; i < 40; i++ {
		req, _ := http.NewRequest("GET", proxyBase+"/api/orders", nil)
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Recover Server 3
	fmt.Println("\n>>> [RECOVERY EVENT] Healing Server :9003. Circuit Breaker will enter HALF-OPEN...")
	atomic.StoreInt32(&chaosServer.isDown, 0)
	time.Sleep(4 * time.Second) // Wait for recovery timeout & canary probes

	// Pull and render Metrics Snapshot
	metricsResp, err := client.Get(proxyBase + "/metrics")
	if err == nil {
		fmt.Println("\n==========================================================================")
		fmt.Println(" LIVE TELEMETRY & HISTOGRAM REPORT (/metrics)")
		fmt.Println("==========================================================================")
		body, _ := io.ReadAll(metricsResp.Body)
		_ = metricsResp.Body.Close()
		fmt.Println(string(body))
	}
	fmt.Println("You can send your own requests via terminal:")
	fmt.Printf("   curl -i http://127.0.0.1:%d/\n", port)
	fmt.Printf("   curl http://127.0.0.1:%d/metrics\n\n", port)
}
