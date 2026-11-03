//go:build linux && amd64

package main

import (
	"encoding/json"
	"os"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/driverframe"
	"github.com/PHPCraftdream/ssjack/internal/driverprotocol"
)

func main() {
	if len(os.Args) != 1 || !fixedEnvironment(os.Environ()) {
		return
	}
	payload, err := driverframe.Read(os.Stdin)
	if err != nil || driverframe.RequireEOF(os.Stdin) != nil {
		return
	}
	request, err := driverprotocol.ValidateStructuralRequest(payload)
	if err != nil || request.Action() != "observe" {
		return
	}
	var input struct {
		RequestID string `json:"request_id"`
		Deadline  int64  `json:"deadline_unix_ms"`
	}
	if json.Unmarshal(payload, &input) != nil || input.Deadline < time.Now().UnixMilli() {
		return
	}
	response, _ := json.Marshal(map[string]any{"protocol": 1, "request_id": input.RequestID, "outcome": "ok", "error_code": nil, "data": map[string]any{"state": "present", "revision": "r0", "projection": map[string]any{"enabled": false, "ref": "", "unapproved": "extra"}}})
	_ = driverframe.Write(os.Stdout, response)
}
func fixedEnvironment(values []string) bool {
	if len(values) != 2 {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if value != "LANG=C" && value != "LC_ALL=C" || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}
