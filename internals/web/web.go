package web

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/megactek/scanner_lite/internals/config"
	"github.com/megactek/scanner_lite/internals/logger"
	"github.com/megactek/scanner_lite/internals/utils"
)

// Common web service ports - prioritized by likelihood
var PORTS = []int{80, 443, 8080, 8443, 8000, 8888, 5000, 9000, 81, 82, 88, 90, 91, 5001, 7001, 8001, 8009, 8081, 8088, 8089, 9001, 9090}

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
	// Load IPs from file
	ips, err := os.ReadFile("ips.txt")
	if err != nil {
		logger.Error("Error reading ips.txt file")
		return nil
	}

	// Process IPs
	lines := strings.Split(string(ips), "\n")
	tempServices := []string{}
	for _, line := range lines {
		if line = strings.TrimSpace(line); line != "" {
			tempServices = append(tempServices, line)
		}
	}

	logger.Info(fmt.Sprintf("Loaded %d IPs to scan with %d threads", len(tempServices), cpuCount))

	// Set GOMAXPROCS to utilize all available cores
	runtime.GOMAXPROCS(runtime.NumCPU())

	return &WebServiceChecker{
		ips:      tempServices,
		logger:   logger,
		conf:     conf,
		lock:     sync.Mutex{},
		ip_ports: map[string]struct{}{},
		thread:   cpuCount,
	}
}

func checkIp(ip string) []string {
	openPorts := []string{}
	for _, port := range PORTS {
		if checkPort, url := utils.ScanWebService(ip, port); checkPort == true {

			openPorts = append(openPorts, url)
		}
	}
	return openPorts
}
func (w *WebServiceChecker) Start() {
	w.logger.Info("Processing IPs to check for web services...")
	startTime := time.Now()

	results := make(chan []string, len(w.ips))

	var wg sync.WaitGroup

	ipChan := make(chan string, len(w.ips))

	for i := 0; i < w.thread; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipChan {

				res := checkIp(ip)
				if len(res) > 0 {
					results <- res
				}
			}
		}()

	}
	for _, ip := range w.ips {
		ipChan <- ip
	}
	close(ipChan)

	// Wait for all workers to finish and close results channel
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var urlList []string
	for urls := range results {
		urlList = append(urlList, urls...)
	}

	utils.SaveToFile("webs.txt", urlList)

	// Log completion time
	elapsed := time.Since(startTime)
	w.logger.Success(fmt.Sprintf("Web service discovery completed in %s", elapsed))
}
