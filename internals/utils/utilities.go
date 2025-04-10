package utils

import (
	"bufio"
	"context"

	// "crypto/tls"
	"fmt"
	"net"

	// "net/http"
	"os"
	"strings"
	"sync"
	"time"
)

func SaveToFile(fileName string, data []string) {

	if len(data) == 0 {
		fmt.Println("No data to save.")
		return
	}
	var lock sync.Mutex
	lock.Lock()

	defer lock.Unlock()

	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)

	if err != nil {
		fmt.Println(fmt.Sprintf("Error opening %s file: %s", fileName, err.Error()))
		return
	}

	defer file.Close()

	bufWriter := bufio.NewWriterSize(file, 8*1024*1024)

	const chunkSize = 1000000

	total := len(data)

	for i := 0; i < total; i += chunkSize {

		end := i + chunkSize

		if end > total {
			end = total
		}

		for j := i; j < end; j++ {
			bufWriter.WriteString(data[j])
			bufWriter.WriteByte('\n')
		}

		if i%(chunkSize*5) == 0 {
			if err := bufWriter.Flush(); err != nil {
				fmt.Println(fmt.Sprintf("Error flushing buffer: %s", err.Error()))
				return
			}
		}
	}

	if err := bufWriter.Flush(); err != nil {
		fmt.Println(fmt.Sprintf("Error flushing buffer: %s", err.Error()))
		return
	}
	fmt.Printf("Successfully wrote %d items to %s\n", total, fileName)
}

func ScanPort(ip string, port int) bool {
	var addr string
	if strings.Contains(ip, ":") { // IPv6 check
		addr = fmt.Sprintf("[%s]:%d", ip, port)
	} else {
		addr = fmt.Sprintf("%s:%d", ip, port)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var d net.Dialer
	_, err := d.DialContext(ctx, "tcp", addr)
	return err == nil

}

const (
	dialTimeout  = 2 * time.Second
	totalTimeout = 3 * time.Second
	bufferSize   = 1000
)

func ScanWebService(ip string, port int) (bool, string) {
	address := fmt.Sprintf("%s:%d", ip, port)

	// Set up dialer with timeout
	dialer := net.Dialer{
		Timeout: dialTimeout,
	}

	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return false, ""
	}
	defer conn.Close()

	// Construct URL
	protocol := "http"
	if port == 443 || port == 8443 {
		protocol = "https"
	}
	url := fmt.Sprintf("%s://%s:%d", protocol, ip, port)

	return true, url
}
