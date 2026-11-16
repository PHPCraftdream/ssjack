// Command syntheticconsumer is the in-repository reference consumer of the
// selected-text contract in docs/CONSUMER-CONFORMANCE.md. It is test
// infrastructure that the conformance kit drives; it is never shipped.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

const (
	statusReceived = "received"
	statusWithheld = "withheld"
	statusUnknown  = "unknown"

	operationTimeout = 62 * time.Second
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout))
}

// run requires the fixed leading arguments "--consumer synthetic" so the kit's
// SSJACK_CONSUMER_ARGS plumbing is exercised, then dispatches the subcommand.
// Exactly one status line is printed; only received exits zero.
func run(args []string, stdout io.Writer) int {
	if len(args) < 3 || args[0] != "--consumer" || args[1] != "synthetic" {
		fmt.Fprintln(os.Stderr, "usage: syntheticconsumer --consumer synthetic deploy-text|backup-text FLAGS")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	var status string
	switch args[2] {
	case "deploy-text":
		status = deploy(ctx, args[3:])
	case "backup-text":
		status = backup(ctx, args[3:])
	default:
		fmt.Fprintln(os.Stderr, "unknown subcommand")
		return 2
	}
	fmt.Fprintf(stdout, "{\"status\":%q}\n", status)
	if status == statusReceived {
		return 0
	}
	return 1
}

// parse reads the subcommand flags and reports which were explicitly set.
func parse(flags *flag.FlagSet, args []string) (map[string]bool, bool) {
	flags.SetOutput(io.Discard)
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return nil, false
	}
	set := map[string]bool{}
	flags.Visit(func(f *flag.Flag) { set[f.Name] = true })
	return set, true
}

// settled maps a reported status to one the consumer may forward: only
// received and withheld are trusted; anything else is unknown.
func settled(status string) string {
	switch status {
	case statusReceived, statusWithheld:
		return status
	}
	return statusUnknown
}

// refused maps a status reported where no copy arrived: withheld stays
// withheld, everything else (including received without data) is unknown.
func refused(status string) string {
	if status == statusWithheld {
		return statusWithheld
	}
	return statusUnknown
}
