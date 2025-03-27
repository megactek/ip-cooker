package scrapper

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/megactek/scanner_lite/internals/config"
	"github.com/megactek/scanner_lite/internals/logger"
	"github.com/megactek/scanner_lite/internals/utils"
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
	lock     *sync.Mutex
}

func NewCIDRScrapper(logger *logger.Logger, config *config.Config) (*CIDRScrapper, error) {
	logger.Info("Loading Cidr Scrapper...")
	content, err := os.ReadFile("keyword.txt")
	if err != nil {
		return nil, fmt.Errorf("create keyword.txt file for scrapper then proceed: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	keywords := []string{}
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

	logger.Info(fmt.Sprintf("Loaded %d keywords", len(keywords)))

	return &CIDRScrapper{
		keywords: keywords,
		logger:   logger,
		config:   config,
		lock:     &sync.Mutex{},
	}, nil
}
func getHttpResponse(keyword string) ([]string, error) {
	resp, err := http.Get(fmt.Sprintf("https://api.bgpview.io/search?query_term=%s", keyword))
	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("ip block")
	}
	if err != nil {
		return nil, fmt.Errorf("error getting CIDR API response: %w", err)
	}
	body, err := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("error reading CIDR API response: %w", err)
	}

	var cidrAPIResponse CIDRAPIResponse

	if err = json.Unmarshal(body, &cidrAPIResponse); err != nil {
		return nil, fmt.Errorf("error unmarshalling CIDR API response: %w", err)
	}
	var cidrList []string

	for _, cidr := range cidrAPIResponse.Data.Ipv4Array {
		if !slices.Contains(cidrList, cidr.Ipv4Prefix) {
			cidrList = append(cidrList, cidr.Ipv4Prefix)
		}
	}

	return cidrList, nil
}

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
func (s *CIDRScrapper) processKeyword(keyword string) []string {
	s.logger.Info(fmt.Sprintf("Processing keyword: %s", keyword))
	if keyword == "" {
		s.logger.Error("Keyword is empty")
		return []string{}
	}
	for {
		cidrAPIResponse, err := getHttpResponse(keyword)
		if err != nil {
			s.logger.Error(fmt.Sprintf("Error getting CIDR API response: %s", err))

			time.Sleep(2 * time.Second)
			s.logger.Info(fmt.Sprintf("Retrying word: %s", keyword))
			continue
		}
		return cidrAPIResponse

	}

}

func (s *CIDRScrapper) Start() {
	s.logger.Info("Starting CIDR Scrapper...")
	cidrs := []string{}

	for _, word := range s.keywords {
		cidrs = slices.Concat(cidrs, s.processKeyword(word))
	}

	utils.SaveToFile("cidrs.txt", cidrs)

	s.logger.Info(fmt.Sprintf("CIDR Scrapper finished. Total CIDRs: %d", len(cidrs)))
}
