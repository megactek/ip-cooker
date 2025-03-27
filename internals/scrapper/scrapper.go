package scrapper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/megactek/scanner_lite/internals/config"
	"github.com/megactek/scanner_lite/internals/logger"
)

type CIDRAPIResponse struct {
	Data struct {
		Ipv4Array []struct {
			Ipv4Prefix string `json:"prefix"`
		} `json:"ipv4_prefixes"`
	} `json:"data"`
}
type CIDRScrapper struct {
	keywords []string
	logger   *logger.Logger
	config   *config.Config
	lock     sync.Mutex
	cidrs    map[string]struct{}
}

func NewCIDRScrapper(logger *logger.Logger, config *config.Config) (*CIDRScrapper, error) {
	logger.Info("Loading Cidr Scrapper...")
	// Read and process keywords from file
	content, err := os.ReadFile("keyword.txt")
	if err != nil {
		return nil, fmt.Errorf("create keyword.txt file for scrapper then proceed: %w", err)
	}

	// Split content into lines and process each line
	lines := strings.Split(string(content), "\n")
	keywords := make([]string, 0, len(lines))

	for _, line := range lines {
		// Clean and validate each keyword
		cleaned := cleanKeyword(line)
		if cleaned != "" {
			keywords = append(keywords, cleaned)
		}
	}

	if len(keywords) == 0 {
		logger.Error("No valid keywords found in keyword.txt")
		return nil, fmt.Errorf("keyword.txt contains no valid keywords")
	}

	// Load existing CIDRs to avoid duplicates
	existingCidrs := make(map[string]struct{})
	if cidrData, err := os.ReadFile("cidrs.txt"); err == nil {
		cidrLines := strings.Split(string(cidrData), "\n")
		for _, line := range cidrLines {
			if line = strings.TrimSpace(line); line != "" {
				existingCidrs[line] = struct{}{}
			}
		}
		logger.Info(fmt.Sprintf("Loaded %d existing CIDRs", len(existingCidrs)))
	}

	logger.Info(fmt.Sprintf("Loaded %d keywords", len(keywords)))

	return &CIDRScrapper{
		keywords: keywords,
		logger:   logger,
		config:   config,
		lock:     sync.Mutex{},
		cidrs:    existingCidrs,
	}, nil
}
func getHttpResponse(url string) (*CIDRAPIResponse, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error getting CIDR API response: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading CIDR API response: %w", err)
	}
	var cidrAPIResponse CIDRAPIResponse
	err = json.Unmarshal(body, &cidrAPIResponse)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling CIDR API response: %w", err)
	}
	return &cidrAPIResponse, nil
}
func (s *CIDRScrapper) containsCIDR(cidr string) bool {
	_, exists := s.cidrs[cidr]
	return exists
}
func (s *CIDRScrapper) saveCIDRs(cidrs []string) {
	if len(cidrs) == 0 {
		return
	}

	// Prepare new CIDRs to add
	newCidrs := make([]string, 0, len(cidrs))

	// First acquire the lock
	s.lock.Lock()

	// Find only new CIDRs
	for _, cidr := range cidrs {
		if !s.containsCIDR(cidr) {
			s.cidrs[cidr] = struct{}{}
			newCidrs = append(newCidrs, cidr)
		}
	}

	s.lock.Unlock()

	// If no new CIDRs, return early
	if len(newCidrs) == 0 {
		return
	}

	// Write to cidrs.txt (outside the lock for better concurrency)
	file, err := os.OpenFile("cidrs.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		s.logger.Error(fmt.Sprintf("Error opening cidrs.txt file: %s", err))
		return
	}
	defer file.Close()

	// Create a buffer for batch writing
	buffer := bytes.NewBuffer(make([]byte, 0, len(newCidrs)*20)) // Estimate ~20 bytes per CIDR
	for _, cidr := range newCidrs {
		buffer.WriteString(cidr + "\n")
	}

	// Single write operation for all CIDRs
	if _, err := file.Write(buffer.Bytes()); err != nil {
		s.logger.Error(fmt.Sprintf("Error writing to cidrs.txt file: %s", err))
	}
}

// cleanKeyword removes non-alphanumeric characters and converts to lowercase
func cleanKeyword(keyword string) string {
	// First trim spaces
	keyword = strings.TrimSpace(keyword)

	// Create a new string builder for efficiency
	var result strings.Builder

	// Keep only alphanumeric characters
	for _, r := range strings.ToLower(keyword) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			result.WriteRune(r)
		}
	}

	return result.String()
}
func (s *CIDRScrapper) processKeyword(keyword string) {
	s.logger.Info(fmt.Sprintf("Processing keyword: %s", keyword))
	if keyword == "" {
		s.logger.Error("Keyword is empty")
		return
	}
	for {
		tempCIDRs := []string{}
		cidrAPIResponse, err := getHttpResponse(fmt.Sprintf("https://api.bgpview.io/search?query_term=%s", keyword))
		if err != nil {
			s.logger.Error(fmt.Sprintf("Error getting CIDR API response: %s", err))

			time.Sleep(5 * time.Second)
			continue
		}
		for _, ipv4 := range cidrAPIResponse.Data.Ipv4Array {
			s.logger.Info(fmt.Sprintf("CIDR: %s", ipv4.Ipv4Prefix))
			tempCIDRs = append(tempCIDRs, ipv4.Ipv4Prefix)
		}
		s.saveCIDRs(tempCIDRs)
		time.Sleep(5 * time.Second)
		s.logger.Info(fmt.Sprintf("CIDRs count: %d", len(tempCIDRs)))
		break
	}

}

func (s *CIDRScrapper) Start() {
	s.logger.Info("Starting CIDR Scrapper...")

	// Use a worker pool for concurrent keyword processing
	workerCount := s.config.GetThread()
	if workerCount <= 0 {
		workerCount = 5 // Default to 5 workers for API scraping
	}

	jobs := make(chan string, len(s.keywords))
	var wg sync.WaitGroup

	// Create worker pool
	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for keyword := range jobs {
				s.processKeyword(keyword)
			}
		}()
	}

	// Send jobs to workers
	for _, keyword := range s.keywords {
		jobs <- cleanKeyword(keyword)
	}

	close(jobs)
	wg.Wait()

	s.logger.Info(fmt.Sprintf("CIDR Scrapper finished. Total CIDRs: %d", len(s.cidrs)))
}
