//go:build linux && amd64

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const admissionCoord = "/var/lib/ssjack/synthetic/concurrent"

var admissionProbe = "off"

func admissionBarrier(r request) bool {
	if admissionProbe != "on" || r.Action != "apply" || r.ExpectedRevision == nil {
		return true
	}
	deadline := time.UnixMilli(r.DeadlineUnixMS)
	if !time.Now().Before(deadline) {
		return false
	}
	payload, err := json.Marshal(struct{ ExpectedRevision string }{*r.ExpectedRevision})
	if err != nil || len(payload) > 256 {
		return false
	}
	waiting := filepath.Join(admissionCoord, "driver.waiting")
	if err := os.WriteFile(waiting, payload, 0600); err != nil {
		return false
	}
	for time.Now().Before(deadline) {
		info, err := os.Stat(filepath.Join(admissionCoord, "driver.release"))
		if err == nil && info.Mode().IsRegular() {
			return true
		}
		if err != nil && !os.IsNotExist(err) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
