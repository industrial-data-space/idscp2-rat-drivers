package logger

import (
	"fmt"
	"log"
	"os"
)

const (
	LogOff = iota
	LogCrit
	LogErr
	LogWarn
	LogInfo
	LogDebug
	LogTrace
)

var (
	LogLevel = LogInfo
	Instance = log.New(os.Stderr, "", log.LstdFlags|log.Lshortfile)
)

func Crit(f string, v ...interface{}) {
	if LogLevel >= LogCrit {
		Instance.Output(2, "CRITICAL: "+fmt.Sprintf(f, v...))
	}
}

func Err(f string, v ...interface{}) {
	if LogLevel >= LogErr {
		Instance.Output(2, "ERROR: "+fmt.Sprintf(f, v...))
	}
}

func Warn(f string, v ...interface{}) {
	if LogLevel >= LogWarn {
		Instance.Output(2, "WARNING: "+fmt.Sprintf(f, v...))
	}
}

func Info(f string, v ...interface{}) {
	if LogLevel >= LogInfo {
		Instance.Output(2, "INFO: "+fmt.Sprintf(f, v...))
	}
}

func Debug(f string, v ...interface{}) {
	if LogLevel >= LogDebug {
		Instance.Output(2, "DEBUG: "+fmt.Sprintf(f, v...))
	}
}

func Trace(f string, v ...interface{}) {
	if LogLevel >= LogTrace {
		Instance.Output(2, "TRACE: "+fmt.Sprintf(f, v...))
	}
}

// Log a critical message and terminate the process
func Fatal(f string, v ...interface{}) {
	Crit(f, v...)
	os.Exit(1)
}
