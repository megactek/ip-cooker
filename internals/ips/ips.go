package ips

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"bytes"
	"net"
	"sync"

	"github.com/megactek/scanner_lite/internals/config"
	"github.com/megactek/scanner_lite/internals/logger"
	"github.com/megactek/scanner_lite/internals/utils"
	// "time"
	// "os"
)

type IPService struct {
	cidrs  []string
	logger *logger.Logger
	conf   *config.Config
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

func (i *IPService) processCIDR(cidr string) []string {
	i.logger.Info(fmt.Sprintf("Processing CIDR: %s", cidr))
	ipStart, ipEnd, err := i.GetCIDRRange(cidr)
	if err != nil {
		i.logger.Error(fmt.Sprintf("Error getting CIDR range: %s", err))
		return []string{}
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

		incrementIP(currentIP)

	}
	i.logger.Success(fmt.Sprintf("CIDR processing %s found %v ip(s)", cidr, len(ips)))
	return ips
}

func (i *IPService) Start() {
	i.logger.Info("Processing IPs...")

	// Create a channel to collect results
	results := make(chan []string, len(i.cidrs)) // Buffered channel to prevent blocking

	// Process CIDRs in parallel
	var wg sync.WaitGroup
	for _, cidr := range i.cidrs {
		wg.Add(1)
		go func(cidr string) {
			defer wg.Done()
			// Process the CIDR and send results directly to the channel
			ipList := i.processCIDR(cidr)
			if len(ipList) > 0 {
				results <- ipList
			}
		}(cidr)
	}

	// Start a goroutine to close the results channel after all processing is done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results from the channel
	var ips []string
	for ipList := range results {
		ips = slices.Concat(ips, ipList)
	}

	utils.SaveToFile("ips.txt", ips)
	i.logger.Success(fmt.Sprintf("CIDR to IP conversion completed, ips found: %v", len(ips)))
}
