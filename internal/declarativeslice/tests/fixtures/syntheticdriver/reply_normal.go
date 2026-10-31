//go:build !task231_lostreply && linux && amd64

package main

import (
	"os"

	"github.com/PHPCraftdream/ssjack/internal/driverframe"
)

func writeReply(_ *request, payload []byte) error { return driverframe.Write(os.Stdout, payload) }
