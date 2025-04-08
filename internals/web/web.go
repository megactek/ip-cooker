package web

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync/atomic"

	// "strings"
	"bytes"
	"io"
	"sync"
	"time"

	"github.com/megactek/scanner_lite/internals/config"
	"github.com/megactek/scanner_lite/internals/logger"
	"github.com/megactek/scanner_lite/internals/utils"
)

// Common web service ports - prioritized by likelihood
var PORTS = []int{80, 443, 8080, 8443, 8000, 8888, 5000, 9000, 81, 82, 88, 90, 91, 5001, 7001, 8001, 8009, 8081, 8088, 8089, 9001, 9090}

const (
	dialTimeout  = 2 * time.Second
	totalTimeout = 3 * time.Second
	bufferSize   = 1000
)

type WebServiceChecker struct {
	ips      []string
	logger   *logger.Logger
	conf     *config.Config
	lock     sync.Mutex
	ip_ports map[string]struct{}
	thread   int
}

func NewWebServiceChecker(logger *logger.Logger, conf *config.Config) *WebServiceChecker {
	logger.Success("Starting Web service Checker...")

	cpuCount := runtime.NumCPU()

	// Count IPs from file without loading everything into memory
	ipCount, err := countLinesInFile("ips.txt")
	if err != nil {
		logger.Error("Error counting IPs in file: " + err.Error())
		return nil
	}

	logger.Info(fmt.Sprintf("Found %d IPs to scan with %d threads", ipCount, cpuCount))

	// Set GOMAXPROCS to utilize all available cores
	runtime.GOMAXPROCS(runtime.NumCPU())

	return &WebServiceChecker{
		ips:      []string{}, // We'll read incrementally instead of loading all at once
		logger:   logger,
		conf:     conf,
		lock:     sync.Mutex{},
		ip_ports: map[string]struct{}{},
		thread:   cpuCount * 4, // Increase thread count as most time is spent waiting on network
	}
}

// Helper function to count lines in a file
func countLinesInFile(filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	buf := make([]byte, 32*1024)
	count := 0
	lineSep := []byte{'\n'}

	for {
		c, err := file.Read(buf)
		if err != nil && err != io.EOF {
			return count, err
		}

		count += bytes.Count(buf[:c], lineSep)

		if err == io.EOF {
			break
		}
	}

	return count, nil
}
func checkIp(ip string) []string {
	openPorts := []string{}
	// Create channel for timeout
	done := make(chan bool, 1)

	go func() {
		for _, port := range PORTS {
			// Skip if taking too long
			select {
			case <-done:
				return
			default:
				if checkPort, url := utils.ScanWebService(ip, port); checkPort {
					openPorts = append(openPorts, url)
					// Return after first found port to speed up scanning
					done <- true
					return
				}
			}
		}
		done <- true
	}()

	// Implement timeout
	select {
	case <-done:
		return openPorts
	case <-time.After(totalTimeout):
		return openPorts
	}
}

func (w *WebServiceChecker) Start() {
	w.logger.Info("Processing IPs to check for web services...")
	startTime := time.Now()

	// Buffered channels to prevent blocking
	results := make(chan []string, bufferSize)
	ipChan := make(chan string, bufferSize)

	// Create a buffered writer for results
	resultFile, err := os.Create("webs.txt")
	if err != nil {
		w.logger.Error("Failed to create output file: " + err.Error())
		return
	}
	defer resultFile.Close()
	writer := bufio.NewWriter(resultFile)
	defer writer.Flush()

	// Progress tracking
	var processedCount int64
	var foundCount int64
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Start progress reporter
	go func() {
		lastProcessed := int64(0)
		lastTime := time.Now()

		for range ticker.C {
			currentCount := atomic.LoadInt64(&processedCount)
			currentFound := atomic.LoadInt64(&foundCount)
			now := time.Now()

			// Calculate rate over last interval
			interval := now.Sub(lastTime)
			recentProcessed := currentCount - lastProcessed
			ipsPerSecond := float64(recentProcessed) / interval.Seconds()

			w.logger.Info(fmt.Sprintf("Progress: %d IPs processed (%.1f IPs/sec), %d web services found",
				currentCount, ipsPerSecond, currentFound))

			// Update last values
			lastProcessed = currentCount
			lastTime = now
		}
	}()

	// Start IP reader
	go func() {
		file, err := os.Open("ips.txt")
		if err != nil {
			w.logger.Error("Error opening ips.txt file: " + err.Error())
			close(ipChan)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			ip := strings.TrimSpace(scanner.Text())
			if ip != "" {
				ipChan <- ip
			}
		}
		close(ipChan)
	}()

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < w.thread; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for ip := range ipChan {
				res := checkIp(ip)
				atomic.AddInt64(&processedCount, 1)
				if len(res) > 0 {
					results <- res
				}
			}
		}(i)
	}

	// Start result collector
	var wgWriter sync.WaitGroup
	wgWriter.Add(1)
	go func() {
		defer wgWriter.Done()
		for urls := range results {
			for _, url := range urls {
				writer.WriteString(url + "\n")
				atomic.AddInt64(&foundCount, 1)
			}
			if atomic.LoadInt64(&foundCount)%100 == 0 {
				writer.Flush()
			}
		}
	}()

	// Wait for all workers
	go func() {
		wg.Wait()
		close(results)
	}()

	// Wait for writer
	wgWriter.Wait()

	elapsed := time.Since(startTime)
	w.logger.Success(fmt.Sprintf("Web service discovery completed in %s. Found %d web services from %d IPs.",
		elapsed, atomic.LoadInt64(&foundCount), atomic.LoadInt64(&processedCount)))
}
