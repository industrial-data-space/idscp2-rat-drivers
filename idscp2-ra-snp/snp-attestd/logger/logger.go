/*-
 * ========================LICENSE_START=================================
 * snp-attestd
 * %%
 * Copyright (C) 2022 Fraunhofer AISEC
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * =========================LICENSE_END==================================
 */
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
