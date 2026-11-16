// Command syntheticconsumer is the in-repository reference consumer of the
// selected-text contract in docs/CONSUMER-CONFORMANCE.md. It is test
// infrastructure that the conformance kit drives; it is never shipped.
package main

import (
	"os"

	"github.com/PHPCraftdream/ssjack/internal/syntheticconsumer"
)

func main() {
	os.Exit(syntheticconsumer.Run(os.Args[1:], os.Stdout))
}
