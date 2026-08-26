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

// Package app contains the command surface and the sole runtime composition
// root. Parsing the child boundary here prevents a second shell-based path.
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

// Main executes the bootstrap command tree. Until the authenticated proxy and
// CA pipeline exists, run intentionally fails closed rather than launching a
// child with only partial protection.
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

	_, _ = fmt.Fprintf(os.Stderr, "kordn: unknown command\n\n%s", usage)
	return 2
}

// RunInvocation is the parsed, direct child argv boundary. The runtime must
// consume Argv as-is; it must never turn it into a shell command.
type RunInvocation struct {
	ConfigPath string
	Quiet      bool
	Verbose    bool
	Argv       []string
}

// ParseRunArgs parses only Kordn flags before the mandatory --. Everything
// after that marker belongs to the child, including values that look like
// flags. Profile and role overrides are deliberately not accepted here: the
// immutable configuration owns the upstream authority ceiling.
func ParseRunArgs(args []string) (RunInvocation, error) {
	separator := -1
	for i, arg := range args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator < 0 {
		return RunInvocation{}, fmt.Errorf("the '--' separator and a child command are required")
	}
	if separator == len(args)-1 || args[separator+1] == "" {
		return RunInvocation{}, fmt.Errorf("a child command is required after '--'")
	}
	var invocation RunInvocation
	for i := 0; i < separator; i++ {
		arg := args[i]
		switch {
		case arg == "--quiet":
			invocation.Quiet = true
		case arg == "--verbose":
			invocation.Verbose = true
		case arg == "--config":
			if i+1 >= separator || args[i+1] == "" {
				return RunInvocation{}, fmt.Errorf("--config requires a path")
			}
			invocation.ConfigPath = args[i+1]
			i++
		case len(arg) > len("--config=") && arg[:len("--config=")] == "--config=":
			invocation.ConfigPath = arg[len("--config="):]
			if invocation.ConfigPath == "" {
				return RunInvocation{}, fmt.Errorf("--config requires a path")
			}
		default:
			// Do not echo arbitrary flag text: callers may accidentally place
			// credential-like material in a malformed option.
			return RunInvocation{}, fmt.Errorf("unsupported run flag")
		}
	}
	invocation.Argv = append([]string(nil), args[separator+1:]...)
	return invocation, nil
}

func runCommand(args []string) int {
	if _, err := ParseRunArgs(args); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "kordn run: %v\n", err)
		return 2
	}
	_, _ = fmt.Fprintln(os.Stderr, "kordn run: protected runtime is not available in bootstrap")
	return 78
}

func notReady(command string) int {
	_, _ = fmt.Fprintf(os.Stderr, "kordn %s: command is reserved for the protected runtime\n", command)
	return 78
}

var _ io.Writer = os.Stdout
