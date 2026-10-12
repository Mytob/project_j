package main

import (
	"flag"
	"log"

	"github.com/Mytob/project_j/internal/auth"
)

func main() {
	path := flag.String("output", "", "credential file output path")
	password := flag.String("password", "", "test password")
	flag.Parse()
	if *path == "" || *password == "" {
		log.Fatal("--output and --password are required")
	}
	if err := auth.SaveCredential(*path, *password); err != nil {
		log.Fatal(err)
	}
}
