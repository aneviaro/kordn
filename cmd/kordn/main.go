package main

import (
	"fmt"
	"os"

	"github.com/kordn-ai/kordn/internal/app"
	"github.com/kordn-ai/kordn/internal/app/runimpl"
)

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "run" {
		invocation, err := app.ParseRunArgs(args[1:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "kordn run: %v\n", err)
			os.Exit(2)
		}
		os.Exit(runimpl.Run(nil, invocation))
	}
	os.Exit(app.Main(args))
}
