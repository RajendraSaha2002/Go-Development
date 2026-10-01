package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Result holds the diagnostic data for each checked URL.
type Result struct {
	URL        string
	StatusCode int
	Duration   time.Duration
	Err        error
}

// checkURL performs an HTTP GET request concurrently.
func checkURL(url string, client *http.Client, results chan<- Result, wg *sync.WaitGroup) {
	// Signal WaitGroup that this goroutine is done when the function exits
	defer wg.Done()

	// Normalize URL scheme if missing
	targetURL := url
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	start := time.Now()
	resp, err := client.Get(targetURL)
	duration := time.Since(start)

	if err != nil {
		results <- Result{
			URL:      targetURL,
			Duration: duration,
			Err:      err,
		}
		return
	}
	// Always close the response body to prevent resource leaks
	defer resp.Body.Close()

	results <- Result{
		URL:        targetURL,
		StatusCode: resp.StatusCode,
		Duration:   duration,
		Err:        nil,
	}
}

func main() {
	// 1. Determine which URLs to check (take from CLI args, or use defaults)
	urls := os.Args[1:]
	if len(urls) == 0 {
		urls = []string{
			"google.com",
			"github.com",
			"golang.org",
			"stackoverflow.com",
			"cloudflare.com",
			"this-domain-does-not-exist-12345.com", // Deliberately failing test
			"httpstat.us/503",                      // Deliberate 503 Service Unavailable
		}
		fmt.Println("ℹ️  No URLs passed. Using default target list.")
	}

	fmt.Printf("🔍 Checking %d websites concurrently...\n\n", len(urls))
	overallStart := time.Now()

	// 2. Initialize concurrency primitives
	var wg sync.WaitGroup
	// Buffered channel sized to the number of URLs to prevent blocking
	resultsChan := make(chan Result, len(urls))

	// 3. Configure HTTP Client with a strict timeout
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
	}

	// 4. Launch a Goroutine for each URL
	for _, url := range urls {
		wg.Add(1)
		go checkURL(url, httpClient, resultsChan, &wg)
	}

	// 5. Monitor Goroutines and close the channel when all are done
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// 6. Process results as they arrive on the channel
	var totalUp, totalDown int
	for res := range resultsChan {
		if res.Err != nil {
			totalDown++
			fmt.Printf("❌ [DOWN] %-35s | Latency: %8v | Error: %v\n",
				res.URL, res.Duration.Round(time.Millisecond), res.Err)
		} else if res.StatusCode >= 400 {
			totalDown++
			fmt.Printf("⚠️  [WARN] %-35s | Latency: %8v | Status: %d\n",
				res.URL, res.Duration.Round(time.Millisecond), res.StatusCode)
		} else {
			totalUp++
			fmt.Printf("✅ [UP]   %-35s | Latency: %8v | Status: %d\n",
				res.URL, res.Duration.Round(time.Millisecond), res.StatusCode)
		}
	}

	// 7. Print summary statistics
	totalElapsed := time.Since(overallStart)
	fmt.Println("\n" + strings.Repeat("-", 65))
	fmt.Printf("🏁 Finished in: %v\n", totalElapsed.Round(time.Millisecond))
	fmt.Printf("📊 Summary: Total: %d | Up: %d | Down/Error: %d\n", len(urls), totalUp, totalDown)
	fmt.Println(strings.Repeat("-", 65))
}
