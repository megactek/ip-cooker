# Cloud Nightmare Scanner

A specialized tool for scanning web servers for exposed Laravel `.env` files and extracting sensitive configuration information.

## Features

- Scans IP ranges for exposed Laravel environment files
- Extracts sensitive credentials (database, mail, API keys)
- Supports multiple scanning methods
- Configurable output formats
- IP filtering by keywords/regions

## Installation

```bash
# Clone the repository
git clone https://github.com/megactek/scanner_lite.git

# Navigate to the project directory
cd scanner_lite

# Build the project
go build -o cloud_nightmare cmd/main.go
```

## Usage

```bash
# Basic scan with default settings
./cloud_nightmare 
```

## Configuration

The scanner can be configured using command-line flags:

- `-cidr`: IP range to scan in CIDR notation
- `-v`: Enable verbose output
- `-output`: Directory to save results
- `-keyword-file`: File containing keywords for IP filtering
- `-threads`: Number of concurrent scanning threads

## Output Files

- `result_*/FULL_RESULTS.txt`: Complete scan results with all discovered environment variables
- `Results/gmail.txt`: Extracted Gmail SMTP credentials
- `Results/SMTP_RANDOM.txt`: Other mail server credentials

## Warning

This tool is intended for security research and authorized penetration testing only. Unauthorized scanning of networks you don't own is illegal and unethical.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
