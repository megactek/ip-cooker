package ips

import (
	"fmt"
	"os"
	"strings"

	"bytes"
	"net"
	"sync"

	"github.com/megactek/scanner_lite/internals/config"
	"github.com/megactek/scanner_lite/internals/logger"
	// "time"
	// "os"
)

type IPService struct {
	cidrs  []string
	logger *logger.Logger
	conf   *config.Config
	lock   sync.Mutex
	ips    map[string]struct{}
}

func NewIPService(logger *logger.Logger, conf *config.Config) (*IPService, error) {
	logger.Success("Starting IP Service...")
	tempCidrs := []string{}
	// load cidrs from file
	cidrs, err := os.ReadFile("cidrs.txt")
	if err != nil {
		// logger.Error(fmt.Sprintf("Error reading cidrs.txt file: %s", err))
		return nil, err
	}
	lines := strings.Split(string(cidrs), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		tempCidrs = append(tempCidrs, line)
	}

	return &IPService{
		cidrs:  tempCidrs,
		logger: logger,
		conf:   conf,
		lock:   sync.Mutex{},
		ips:    make(map[string]struct{}),
	}, nil
}

func (i *IPService) GetCIDRRange(cidr string) ([]byte, []byte, error) {
	i.logger.Info(fmt.Sprintf("Processing CIDR: %s", cidr))
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, err
	}
	ip := ipnet.IP.To4()
	if ip == nil {
		ip = ipnet.IP.To16()
	}
	ipStart := make([]byte, len(ip))
	copy(ipStart, ip)
	mask := ipnet.Mask

	ipEnd := make([]byte, len(ip))
	for i := 0; i < len(ip); i++ {
		ipEnd[i] = ipStart[i] | ^mask[i]
	}
	return ipStart, ipEnd, nil
}

func incrementIP(ip []byte) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

func (i *IPService) containsIp(ip string) bool {
	_, exists := i.ips[ip]
	return exists
}

func (i *IPService) saveIps(ips []string) {
	// Prepare unique IPs to add (avoid duplicates before locking)
	newIps := make([]string, 0, len(ips))

	i.lock.Lock()
	// Find only new IPs that aren't already in our list
	for _, ip := range ips {
		if !i.containsIp(ip) {
			newIps = append(newIps, ip)
			i.ips[ip] = struct{}{}
		}
	}
	i.lock.Unlock()

	// If no new IPs, return early
	if len(newIps) == 0 {
		return
	}

	// Batch write to file (outside the lock for better concurrency)
	file, err := os.OpenFile("ips.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		i.logger.Error(fmt.Sprintf("Error opening ips.txt file: %s", err))
		return
	}
	defer file.Close()

	// Create a buffer for batch writing with pre-allocated capacity
	buffer := bytes.NewBuffer(make([]byte, 0, len(newIps)*16)) // Estimate ~16 bytes per IP
	for _, ip := range newIps {
		buffer.WriteString(ip + "\n")
	}

	// Single write operation for all IPs
	if _, err := file.Write(buffer.Bytes()); err != nil {
		i.logger.Error(fmt.Sprintf("Error writing to ips.txt file: %s", err))
	}
}

func (i *IPService) processCIDR(cidr string) {
	i.logger.Info(fmt.Sprintf("Processing CIDR: %s", cidr))
	ipStart, ipEnd, err := i.GetCIDRRange(cidr)
	if err != nil {
		i.logger.Error(fmt.Sprintf("Error getting CIDR range: %s", err))
		return
	}

	// Pre-allocate IP list with estimated capacity
	_, ipnet, _ := net.ParseCIDR(cidr)
	ones, bits := ipnet.Mask.Size()
	capacity := 1 << uint(bits-ones)

	ips := make([]string, 0, capacity)

	// Generate IP list
	currentIP := make([]byte, len(ipStart))
	copy(currentIP, ipStart)

	for bytes.Compare(currentIP, ipEnd) <= 0 {
		ips = append(ips, net.IP(append([]byte(nil), currentIP...)).String())

		// Increment IP in place
		incrementIP(currentIP)

		// Batch save to avoid memory issues with very large CIDRs
		if len(ips) >= 100000 {
			i.saveIps(ips)
			ips = ips[:0] // Clear slice but keep capacity
		}
	}

	// Save any remaining IPs
	if len(ips) > 0 {
		i.saveIps(ips)
	}
}

func (i *IPService) Start() {
	i.logger.Info("Processing IPs...")
	workerCount := i.conf.GetThread()

	if workerCount <= 0 {
		workerCount = 100
	}

	jobs := make(chan string, len(i.cidrs))

	var wg sync.WaitGroup
	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cidr := range jobs {
				i.processCIDR(cidr)
			}
		}()
	}

	for _, cidr := range i.cidrs {
		jobs <- cidr
	}
	close(jobs)
	wg.Wait()
	i.logger.Success("CIDR to IP conversion completed")
}
