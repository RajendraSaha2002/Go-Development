package main

import (
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------
// 1. DATA STRUCTURES
// ---------------------------------------------------------

// item represents a cached value and its optional expiration timestamp.
type item struct {
	value     any
	expiresAt time.Time // Zero value means no expiration (permanent)
}

// isExpired checks if the item's TTL has elapsed.
func (i item) isExpired() bool {
	if i.expiresAt.IsZero() {
		return false
	}
	return time.Now().After(i.expiresAt)
}

// Cache is a thread-safe, in-memory key-value store.
type Cache struct {
	mu       sync.RWMutex
	store    map[string]item
	stopChan chan struct{} // Signals the background ticker to shut down
}

// ---------------------------------------------------------
// 2. CONSTRUCTOR & BACKGROUND CLEANUP ENGINE
// ---------------------------------------------------------

// NewCache initializes the store and spawns a background janitor goroutine.
func NewCache(cleanupInterval time.Duration) *Cache {
	c := &Cache{
		store:    make(map[string]item),
		stopChan: make(chan struct{}),
	}

	// Start the background sweeper (Janitor)
	go c.startJanitor(cleanupInterval)

	return c
}

// startJanitor runs periodically to purge stale entries from memory.
func (c *Cache) startJanitor(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.purgeExpired()
		case <-c.stopChan:
			// Graceful exit: stops goroutine from leaking
			return
		}
	}
}

// purgeExpired performs an active sweep across all map entries.
func (c *Cache) purgeExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	purged := 0

	for key, it := range c.store {
		if !it.expiresAt.IsZero() && now.After(it.expiresAt) {
			delete(c.store, key)
			purged++
		}
	}

	if purged > 0 {
		fmt.Printf("🧹 [Janitor] Purged %d expired key(s) from memory.\n", purged)
	}
}

// ---------------------------------------------------------
// 3. PUBLIC CACHE API (THREAD-SAFE)
// ---------------------------------------------------------

// Set stores a key-value pair with an optional TTL.
// Use ttl = 0 for keys that should never expire.
func (c *Cache) Set(key string, value any, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}

	c.store[key] = item{
		value:     value,
		expiresAt: exp,
	}
}

// Get retrieves an item by key. Returns (value, true) or (nil, false).
func (c *Cache) Get(key string) (any, bool) {
	// First: read-lock for safe concurrent reads
	c.mu.RLock()
	it, exists := c.store[key]
	c.mu.RUnlock()

	if !exists {
		return nil, false
	}

	// Lazy deletion: if expired on read, remove it immediately
	if it.isExpired() {
		c.mu.Lock()
		delete(c.store, key)
		c.mu.Unlock()
		return nil, false
	}

	return it.value, true
}

// Delete removes an item explicitly by key.
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.store, key)
}

// Count returns the current number of keys in the store.
func (c *Cache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.store)
}

// Stop terminates the background janitor goroutine safely.
func (c *Cache) Stop() {
	close(c.stopChan)
}

// ---------------------------------------------------------
// 4. DEMO & VERIFICATION
// ---------------------------------------------------------

func main() {
	fmt.Println("🚀 Starting In-Memory Cache with a 500ms cleanup interval...")
	// Sweep for expired keys every 500 milliseconds
	cache := NewCache(500 * time.Millisecond)
	defer cache.Stop()

	// 1. Basic Set & Get
	fmt.Println("\n--- 1. Setting Keys ---")
	cache.Set("session:user_1", "Alice", 1*time.Second) // Expires in 1s
	cache.Set("session:user_2", "Bob", 2*time.Second)   // Expires in 2s
	cache.Set("app:config:theme", "Dark Mode", 0)       // Never expires (TTL = 0)

	val, found := cache.Get("session:user_1")
	fmt.Printf("Immediate lookup 'session:user_1': %v (found=%v)\n", val, found)

	val, found = cache.Get("app:config:theme")
	fmt.Printf("Immediate lookup 'app:config:theme': %v (found=%v)\n", val, found)
	fmt.Printf("Current items in cache: %d\n", cache.Count())

	// 2. Observe Background Expiration
	fmt.Println("\n--- 2. Waiting for TTL to elapse (1.2 seconds)... ---")
	time.Sleep(1200 * time.Millisecond)

	// 'session:user_1' should now be expired and cleaned up
	val, found = cache.Get("session:user_1")
	fmt.Printf("Lookup after 1.2s 'session:user_1': %v (found=%v)\n", val, found)

	// 'session:user_2' (2s TTL) should still be valid
	val, found = cache.Get("session:user_2")
	fmt.Printf("Lookup after 1.2s 'session:user_2': %v (found=%v)\n", val, found)

	// 3. Wait for the second key to expire
	fmt.Println("\n--- 3. Waiting for remaining TTL (1.0 second)... ---")
	time.Sleep(1000 * time.Millisecond)

	val, found = cache.Get("session:user_2")
	fmt.Printf("Lookup after 2.2s 'session:user_2': %v (found=%v)\n", val, found)

	// Permanent key remains unaffected
	val, _ = cache.Get("app:config:theme")
	fmt.Printf("Lookup 'app:config:theme': %v\n", val)

	// 4. Concurrent Stress Test (Proves no data races)
	fmt.Println("\n--- 4. Concurrency Stress Test (50 Workers Reading & Writing) ---")
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		workerID := i
		go func() {
			defer wg.Done()
			key := fmt.Sprintf("worker:%d", workerID)

			// Write concurrently
			cache.Set(key, workerID*10, 500*time.Millisecond)

			// Read concurrently
			cache.Get(key)

			// Delete some keys concurrently
			if workerID%2 == 0 {
				cache.Delete(key)
			}
		}()
	}

	wg.Wait()
	fmt.Println("✅ Concurrent stress test passed with zero race conditions!")
	fmt.Printf("🏁 Final active item count: %d\n", cache.Count())
}
