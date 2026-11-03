//go:build !linux || !amd64

package main

import "os"

func main() { os.Exit(1) }
