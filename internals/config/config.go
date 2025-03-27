package config

import (
	"github.com/megactek/scanner_lite/internals/logger"
)

type Config struct {
	verbose bool
	logger  *logger.Logger
}

func LoadConfig(verbose bool, logger *logger.Logger) *Config {

	// Create the config with all fields properly set
	config := &Config{
		verbose: verbose,
		logger:  logger,
	}

	return config
}

func (c *Config) SetVerbose(v bool) {
	c.verbose = v
}

func (c *Config) IsVerbose() bool {
	return c.verbose
}
