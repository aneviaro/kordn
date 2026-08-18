// Copyright 2026 Kordn AI contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package app contains the deliberately small command surface used while the
// runtime is being built. Keeping argument parsing here gives later runtime
// packages one composition root and avoids a second CLI-specific architecture.
package app

import (
	"fmt"
	"io"
	"os"
	"runtime"
)

const usage = `Usage:
  kordn version
  kordn init
  kordn policy validate [--config PATH]
  kordn identity [--profile NAME]
  kordn audit [--run RUN_ID] [--json]
  kordn run [flags] -- <command> [args...]
`

// Main executes the bootstrap command tree and returns the process exit code.
// Runtime commands intentionally stop at a clear bootstrap error until their
// protected one-process pipeline is implemented in a later task.
func Main(args []string) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(os.Stderr, usage)
		return 2
	}

	switch args[0] {
	case "help", "--help", "-h":
		_, _ = fmt.Fprint(os.Stdout, usage)
		return 0
	case "version", "--version":
		fmt.Printf("kordn bootstrap (go %s)\n", runtime.Version())
		return 0
	case "run":
		return runCommand(args[1:])
	case "init":
		return notReady("init")
	case "identity":
		return notReady("identity")
	case "audit":
		return notReady("audit")
	case "policy":
		if len(args) > 1 && args[1] == "validate" {
			return notReady("policy validate")
		}
	}

	_, _ = fmt.Fprintf(os.Stderr, "kordn: unknown command %q\n\n%s", args[0], usage)
	return 2
}

func runCommand(args []string) int {
	separator := -1
	for i, arg := range args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator < 0 || separator == len(args)-1 {
		_, _ = fmt.Fprintln(os.Stderr, "kordn run: the '--' separator and a child command are required")
		return 2
	}
	// Validate the boundary now. Passing an argv slice directly (rather than
	// invoking a shell) is part of the command contract for the runtime.
	_, _ = fmt.Fprintln(os.Stderr, "kordn run: protected runtime is not available in bootstrap")
	return 78
}

func notReady(command string) int {
	_, _ = fmt.Fprintf(os.Stderr, "kordn %s: command is reserved for the protected runtime\n", command)
	return 78
}

// compile-time assertion documenting that this package's output is ordinary
// io-compatible CLI output and does not require a logging dependency.
var _ io.Writer = os.Stdout
