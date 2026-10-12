package main

import (
	"fmt"
	"os"

	"github.com/Mytob/project_j/internal/whitelist"
)

func main() {
	entries, err := whitelist.Validate(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	_, _ = fmt.Print(whitelist.RenderCaddyPolicy(entries))
}
