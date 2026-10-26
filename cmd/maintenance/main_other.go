//go:build !linux

package main

import "fmt"

func main() {
	fmt.Println("the restricted host maintenance service is supported only on Linux")
}
