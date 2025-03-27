package logger

import "fmt"

type Logger struct {
	verbose bool
}

func NewLogger(verbose bool) *Logger {
	return &Logger{
		verbose: verbose,
	}
}

// func log(message string, isError bool) {
// 	if isError {
// 		fmt.Println("[x] " + "❌" + message)
// 	} else {
// 		fmt.Println("[x] " + "✅" + message)

// 	}

// }

func (l *Logger) Success(message string) {
	if l.verbose {
		fmt.Println("[x] " + "✅ " + message)
	}
}

func (l *Logger) Info(message string) {
	if l.verbose {
		fmt.Println("[x] " + "🔍 " + message)
	}
}

func (l *Logger) Error(message string) {
	if l.verbose {
		fmt.Println("[x] " + "❌ " + message)
	}
}
