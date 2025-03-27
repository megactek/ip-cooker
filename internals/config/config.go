package config

import (
	"github.com/megactek/scanner_lite/internals/logger"
)

type Config struct {
	verbose bool
	thread  int
	logger  *logger.Logger
}

func LoadConfig(verbose bool, thread int, logger *logger.Logger) *Config {

	if thread <= 0 {
		thread = 50 // default value
	}

	// Create the config with all fields properly set
	config := &Config{
		verbose: verbose,
		thread:  thread,
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

func (c *Config) SetThread(thread int) {
	c.thread = thread
}

func (c *Config) GetThread() int {
	return c.thread
}
