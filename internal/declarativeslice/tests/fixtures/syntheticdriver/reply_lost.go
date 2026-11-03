//go:build task231_lostreply && linux && amd64

package main

import (
	"os"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/driverframe"
)

func writeReply(r *request, payload []byte) error {
	if r != nil && r.Action == "apply" {
		time.Sleep(6 * time.Second)
	}
	return driverframe.Write(os.Stdout, payload)
}
