package web

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/megactek/scanner_lite/internals/config"
	"github.com/megactek/scanner_lite/internals/logger"
)

// Common web service ports - prioritized by likelihood
var PORTS = []int{80, 443, 8080, 8443, 8000, 8888, 5000, 9000, 81, 82, 88, 90, 91, 5001, 7001, 8001, 8009, 8081, 8088, 8089, 9001, 9090}

// HTTP headers for requests
var HEADERS = map[string]string{
	"Accept":          "*/*",
	"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
	"Accept-Encoding": "gzip, deflate",
	"Connection":      "close", // Important for faster scanning
}

// Connection timeouts
const (
	portScanTimeout  = 200 * time.Millisecond
	httpTimeout      = 2 * time.Second
	bufferFlushSize  = 10 * 1024 // Reduced to 10KB for more frequent flushing
	maxThreads       = 1000      // Reduced for lower memory usage
	defaultThreads   = 300       // Better default for 4GB system
	ipBatchSize      = 500       // Smaller batch size
	progressInterval = 2 * time.Second
	// Memory management constants
	memoryCheckInterval = 5 * time.Second
	maxMemoryUsageMB    = 3000 // 3GB max memory usage (leave 1GB for OS)
	gcTriggerThreshold  = 2500 // 2.5GB trigger garbage collection
)

type WebServiceChecker struct {
	ips      []string
	logger   *logger.Logger
	conf     *config.Config
	lock     sync.RWMutex // Use RWMutex for better concurrency
	ip_ports map[string]struct{}
	thread   int
	buffer   *bytes.Buffer
	// Add channels for concurrent port scanning
	portResults chan portScanResult
}

type portScanResult struct {
	ip   string
	port int
	open bool
}

// Create a shared HTTP client for all goroutines instead of one per request

var sharedTransport = &http.Transport{

	TLSClientConfig: &tls.Config{

		InsecureSkipVerify: true,

		MinVersion: tls.VersionTLS10,
	},

	DisableKeepAlives: true,

	MaxIdleConnsPerHost: 10, // Reduced from -1

	DisableCompression: true,

	IdleConnTimeout: 5 * time.Second,

	TLSHandshakeTimeout: 1 * time.Second,

	ExpectContinueTimeout: 1 * time.Second,

	ResponseHeaderTimeout: 2 * time.Second,

	MaxConnsPerHost: 50, // Limit connections per host

}

var sharedClient = &http.Client{

	Timeout: httpTimeout,

	Transport: sharedTransport,

	CheckRedirect: func(req *http.Request, via []*http.Request) error {

		return http.ErrUseLastResponse // Don't follow redirects

	},
}

func NewWebServiceChecker(logger *logger.Logger, conf *config.Config) *WebServiceChecker {
	logger.Success("Starting Web service Checker...")

	// Load existing results to avoid duplicate scanning
	existingServices := make(map[string]struct{})
	if data, err := os.ReadFile("good_web.txt"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if line = strings.TrimSpace(line); line != "" {
				existingServices[line] = struct{}{}
			}
		}
		logger.Info(fmt.Sprintf("Loaded %d existing web services", len(existingServices)))
	}

	// Determine optimal thread count for low memory system
	cpuCount := runtime.NumCPU()
	suggestedThreads := cpuCount * 30 // Reduced from 50 to 30 threads per core for 4GB RAM

	if suggestedThreads > maxThreads {
		suggestedThreads = maxThreads
	}

	// For 4GB RAM, cap at a reasonable number
	if suggestedThreads > 500 {
		suggestedThreads = 500
	}

	// Get thread count from user or config
	var workerThread int
	logger.Info(fmt.Sprintf("Enter threads (recommended: %d, max: %d)", suggestedThreads, maxThreads))
	fmt.Scanln(&workerThread)

	// Validate thread count
	if workerThread <= 0 {
		workerThread = conf.GetThread() // Try to get from config first
		if workerThread <= 0 {
			workerThread = suggestedThreads // Use suggested value
		}
	}
	if workerThread > maxThreads {
		workerThread = maxThreads
	}

	// Load IPs from file
	ips, err := os.ReadFile("ips_2.txt")
	if err != nil {
		logger.Error("Error reading ips.txt file")
		return nil
	}

	// Process IPs
	lines := strings.Split(string(ips), "\n")
	tempServices := make([]string, 0, len(lines))
	for _, line := range lines {
		if line = strings.TrimSpace(line); line != "" {
			tempServices = append(tempServices, line)
		}
	}

	logger.Info(fmt.Sprintf("Loaded %d IPs to scan with %d threads", len(tempServices), workerThread))

	// Set GOMAXPROCS to utilize all available cores
	runtime.GOMAXPROCS(runtime.NumCPU())

	return &WebServiceChecker{
		ips:         tempServices,
		logger:      logger,
		conf:        conf,
		lock:        sync.RWMutex{},
		ip_ports:    existingServices,
		thread:      workerThread,
		buffer:      bytes.NewBuffer(make([]byte, 0, 1024*1024)), // 1MB initial buffer
		portResults: make(chan portScanResult, workerThread*10),  // Buffer for port scan results
	}
}

func (w *WebServiceChecker) containsService(service string) bool {
	w.lock.RLock() // Use read lock for better concurrency
	_, exists := w.ip_ports[service]
	w.lock.RUnlock()
	return exists
}

// Batch save discovered services to reduce lock contention
func (w *WebServiceChecker) saveService(url string) {
	if w.containsService(url) {
		return // Skip if already exists (without acquiring write lock)
	}

	w.lock.Lock()
	defer w.lock.Unlock()

	// Double-check after acquiring lock
	if _, exists := w.ip_ports[url]; !exists {
		w.ip_ports[url] = struct{}{}
		w.buffer.WriteString(url + "\n")

		// Periodically flush to disk when buffer gets large
		if w.buffer.Len() > bufferFlushSize {
			w.flushBuffer()
		}
	}
}

// Flush buffer to disk
func (w *WebServiceChecker) flushBuffer() {
	if w.buffer.Len() == 0 {
		return
	}

	file, err := os.OpenFile("good_web.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		w.logger.Error(fmt.Sprintf("Error opening good_web.txt: %s", err))
		return
	}
	defer file.Close()

	if _, err := file.Write(w.buffer.Bytes()); err != nil {
		w.logger.Error(fmt.Sprintf("Error writing to good_web.txt: %s", err))
	}

	// Reset buffer
	w.buffer.Reset()
}

// Fast port scanner that only checks if port is open
func (w *WebServiceChecker) scanPort(ip string, port int) {
	var addr string
	if strings.Contains(ip, ":") { // IPv6 check
		addr = fmt.Sprintf("[%s]:%d", ip, port)
	} else {
		addr = fmt.Sprintf("%s:%d", ip, port)
	}

	ctx, cancel := context.WithTimeout(context.Background(), portScanTimeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)

	result := portScanResult{
		ip:   ip,
		port: port,
		open: err == nil,
	}

	if err == nil {
		conn.Close()
	}

	w.portResults <- result
}

// Process open ports with HTTP requests
func (w *WebServiceChecker) processOpenPort(ip string, port int) {
	// Determine URL based on port
	var url string
	if port == 443 {
		url = fmt.Sprintf("https://%s:443", ip)
	} else if port == 80 {
		url = fmt.Sprintf("http://%s:80", ip)
	} else if port == 8443 {
		url = fmt.Sprintf("https://%s:8443", ip)
	} else {
		protocol := "http"
		if port == 8443 || port == 443 {
			protocol = "https"
		}
		url = fmt.Sprintf("%s://%s:%d", protocol, ip, port)
	}

	// Skip if already processed
	if w.containsService(url) {
		return
	}

	// Create request with headers
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}

	// Add headers
	for key, value := range HEADERS {
		req.Header.Set(key, value)
	}

	// Send request
	resp, err := sharedClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Save successful connection
	w.saveService(url)
	w.logger.Info(url)
}

func (w *WebServiceChecker) saveToFile() {
	w.lock.Lock()
	defer w.lock.Unlock()

	// Final flush of buffer
	w.flushBuffer()

	w.logger.Success(fmt.Sprintf("Found %d web services", len(w.ip_ports)))
}

func (w *WebServiceChecker) Start() {
	w.logger.Info("Processing IPs to check for web services...")
	startTime := time.Now()

	// Create port scanner workers
	portScanWorkers := w.thread * 2 // More workers for port scanning
	if portScanWorkers > 5000 {
		portScanWorkers = 5000 // Cap at reasonable number
	}

	// Create HTTP workers
	httpWorkers := w.thread

	// Create channels
	ipChan := make(chan string, ipBatchSize)
	resultsChan := make(chan int, w.thread)

	// Start port scanner processor
	var httpWg sync.WaitGroup
	for i := 0; i < httpWorkers; i++ {
		httpWg.Add(1)
		go func() {
			defer httpWg.Done()
			for result := range w.portResults {
				if result.open {
					w.processOpenPort(result.ip, result.port)
				}
			}
		}()
	}

	// Start port scanners
	var scanWg sync.WaitGroup
	for i := 0; i < portScanWorkers; i++ {
		scanWg.Add(1)
		go func() {
			defer scanWg.Done()
			for ip := range ipChan {
				// Process ports in smaller batches to control memory usage
				for i := 0; i < len(PORTS); i += 4 {
					end := i + 4
					if end > len(PORTS) {
						end = len(PORTS)
					}

					// Process this batch of ports
					for _, port := range PORTS[i:end] {
						w.scanPort(ip, port)
					}

					// Small sleep between batches to prevent overwhelming the system
					time.Sleep(10 * time.Millisecond)
				}
				resultsChan <- 1 // Signal IP completion
			}
		}()
	}

	// Start progress tracking
	totalIPs := len(w.ips)
	go func() {
		processed := 0
		ticker := time.NewTicker(progressInterval)
		defer ticker.Stop()

		for {
			select {
			case <-resultsChan:
				processed++
				if processed >= totalIPs {
					return
				}
			case <-ticker.C:
				elapsed := time.Since(startTime)
				if elapsed.Seconds() < 0.1 {
					continue // Avoid division by zero
				}
				ipsPerSecond := float64(processed) / elapsed.Seconds()
				percentComplete := float64(processed) / float64(totalIPs) * 100

				// Get memory stats
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				memoryUsageMB := float64(m.Alloc) / 1024 / 1024

				w.logger.Info(fmt.Sprintf("Progress: %.1f%% (%d/%d IPs, %.1f IPs/sec, Mem: %.1f MB)",
					percentComplete, processed, totalIPs, ipsPerSecond, memoryUsageMB))
			}
		}
	}()

	// Add memory management goroutine
	go func() {
		memTicker := time.NewTicker(memoryCheckInterval)
		defer memTicker.Stop()

		for {
			select {
			case <-memTicker.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				memoryUsageMB := float64(m.Alloc) / 1024 / 1024

				// If memory usage is too high, force garbage collection
				if memoryUsageMB > gcTriggerThreshold {
					w.logger.Info(fmt.Sprintf("Memory usage high (%.1f MB), triggering GC", memoryUsageMB))
					runtime.GC()
				}

				// If still too high after GC, slow down processing temporarily
				runtime.ReadMemStats(&m)
				memoryUsageMB = float64(m.Alloc) / 1024 / 1024
				if memoryUsageMB > maxMemoryUsageMB {
					w.logger.Info("Memory usage critical, pausing briefly")
					time.Sleep(5 * time.Second) // Brief pause to let memory clear
				}
			}
		}
	}()

	// Feed IPs to workers
	for _, ip := range w.ips {
		ipChan <- ip
	}
	close(ipChan)

	// Wait for all port scans to complete
	scanWg.Wait()
	close(w.portResults)

	// Wait for HTTP processing to complete
	httpWg.Wait()
	close(resultsChan)

	// Save results to file
	w.saveToFile()

	// Log completion time
	elapsed := time.Since(startTime)
	w.logger.Success(fmt.Sprintf("Web service discovery completed in %s", elapsed))
}
