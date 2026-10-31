//go:build linux && amd64

package main

import "os"

// This entry point has no flags or caller-selectable paths. An isolated wrapper
// supplies /lab/isolation-ok before launching the synthetic lab as root.
func main() {
	if len(os.Args) != 1 {
		fail()
	}
	if err := runStandaloneLab(); err != nil {
		fail()
	}
}
func fail() { _, _ = os.Stderr.WriteString("ssjack-lab: synthetic lab failed\n"); os.Exit(1) }
