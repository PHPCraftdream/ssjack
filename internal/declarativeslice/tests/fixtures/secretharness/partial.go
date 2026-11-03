package main

import (
	"encoding/json"
	"os"

	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
	"github.com/PHPCraftdream/ssjack/internal/declarativeslice"
)

// verifyTargetState confirms the apply changed target metadata, without reading
// or exposing any confidential payload.
func verifyTargetState(result declarativeslice.ApplyResult, priorRevision string) {
	b, err := os.ReadFile(declarativeauthority.StatePath + "/state.json")
	must(err == nil)
	var state struct {
		OperationID string `json:"operation_id"`
		Revision    string `json:"revision"`
	}
	must(json.Unmarshal(b, &state) == nil)
	must(state.OperationID == result.OperationID && state.Revision != "" && state.Revision != priorRevision)
}
