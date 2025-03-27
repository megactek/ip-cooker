package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/megactek/scanner_lite/internals/config"
	"github.com/megactek/scanner_lite/internals/ips"
	"github.com/megactek/scanner_lite/internals/laravel"
	"github.com/megactek/scanner_lite/internals/logger"
	"github.com/megactek/scanner_lite/internals/scrapper"
	"github.com/megactek/scanner_lite/internals/web"
)

const IS_DEBUG = false

func banner() string {
	var banner string
	banner += strings.Repeat("#", 80)
	banner += "\n\n"
	banner += "\n\n"
	banner += "\n\n"
	banner += `
				@@@@@@@  @@@        @@@@@@   @@@  @@@  @@@@@@@      
			@@@@@@@@  @@@       @@@@@@@@  @@@  @@@  @@@@@@@@     
			!@@       @@!       @@!  @@@  @@!  @@@  @@!  @@@     
			!@!       !@!       !@!  @!@  !@!  @!@  !@!  @!@     
			!@!       @!!       @!@  !@!  @!@  !@!  @!@  !@!     
			!!!       !!!       !@!  !!!  !@!  !!!  !@!  !!!     
			:!!       !!:       !!:  !!!  !!:  !!!  !!:  !!!     
			:!:        :!:      :!:  !:!  :!:  !:!  :!:  !:!     
			::: :::   :: ::::  ::::: ::  ::::: ::   :::: ::     
			:: :: :  : :: : :   : :  :    : :  :   :: :  :      
																
																
			@@@  @@@  @@@   @@@@@@   @@@@@@@   @@@@@@@  @@@  @@@ 
			@@@  @@@  @@@  @@@@@@@@  @@@@@@@  @@@@@@@@  @@@  @@@ 
			@@!  @@!  @@!  @@!  @@@    @@!    !@@       @@!  @@@ 
			!@!  !@!  !@!  !@!  @!@    !@!    !@!       !@!  @!@ 
			@!!  !!@  @!@  @!@!@!@!    @!!    !@!       @!@!@!@! 
			!@!  !!!  !@!  !!!@!!!!    !!!    !!!       !!!@!!!! 
			!!:  !!:  !!:  !!:  !!!    !!:    :!!       !!:  !!! 
			:!:  :!:  :!:  :!:  !:!    :!:    :!:       :!:  !:! 
			:::: :: :::   ::   :::     ::     ::: :::  ::   ::: 
			:: :  : :     :   : :     :      :: :: :   :   : : 
	`
	banner += "\n\n"
	banner += "\n\n"
	banner += "// <include stdio.h> >> Welcome to Cloud Nightmare by x-dev TG@t1nidog //\n\n"
	banner += strings.Repeat("-", 80)
	return banner
}

func options() string {
	var options string
	options += "\n\nSelect options (1-4)\n\n\n"
	options += "1. Generate CIDR (needs keywords.txt) \n"
	options += "2. Scan CIDRs for web services \n"
	options += "3. Web Service Checker \n"

	options += "4. Laravel Checker \n"

	options += "5. Exit \n\n"
	return options
}

func main() {
	// Define a string flag for verbose to handle both -verbose and -verbose=true formats
	verboseStr := flag.Bool("verbose", true, "Enable verbose output (true/false)")

	// Parse flags
	flag.Parse()

	// Convert verbose string to boolean
	verbose := false
	if *verboseStr == true {
		verbose = true
	}

	// Create logger
	logger := logger.NewLogger(verbose)

	// Create config with the processed flag values
	conf := config.LoadConfig(verbose, logger)
	fmt.Println(banner())

	for {
		fmt.Println(options())
		var userInput string

		fmt.Scanln(&userInput)
		toInt, err := strconv.Atoi(userInput)
		if err != nil {
			logger.Error("Error: invalid input")
			continue
		}

		switch toInt {
		case 1:
			scrapper, err := scrapper.NewCIDRScrapper(logger, conf)
			if err != nil {
				logger.Error("Failed to create scrapper")
				continue
			}
			scrapper.Start()
			continue
		case 2:
			ips, err := ips.NewIPService(logger, conf)
			if err != nil {
				logger.Error("Failed to create ips service")
				continue
			}
			ips.Start()
			continue
		case 3:
			web_checker := web.NewWebServiceChecker(logger, conf)
			web_checker.Start()
			continue
		case 4:
			laravel_checker, err := laravel.NewLaravelScanner(logger, conf)
			if err != nil {
				logger.Error("Failed to create laravel scanner")
				continue
			}
			laravel_checker.Start()
			continue

		case 5:
			logger.Success("Exiting Cloud Watch...")
			os.Exit(0)

		}

	}
}
