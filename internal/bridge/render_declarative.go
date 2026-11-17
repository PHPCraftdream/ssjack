package bridge

import (
	"fmt"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/declarativeslice"
)

// Text contract of the declarative tools (see docs/declarative/protocol.md).
// Both results are flat, so no nesting is rendered. A plan is:
//
//	Plan <plan_id> created
//	Digest: <digest> · Expires: <expires_at>
//	Precondition: <revision>        (none when absent)
//	Effects: <n>                    (none when empty)
//	- <class>: <summary_id> [(destructive)]
//	Next: apply it with plan_apply plan_id=<plan_id> and a new request_id.
//
// An apply is:
//
//	Operation <operation_id>: <state>
//	Delivery: <delivery>            (only when the keeper reports one)

const noPrecondition = "none"

// renderPlan is the result of resource_plan.
func renderPlan(plan declarativeslice.PlanResult) string {
	precondition := noPrecondition
	if plan.Precondition != nil {
		precondition = oneLine(*plan.Precondition)
	}
	lines := []string{
		fmt.Sprintf("Plan %s created", plan.PlanID),
		fmt.Sprintf("Digest: %s%sExpires: %s", plan.Digest, fieldSep, plan.ExpiresAt),
		"Precondition: " + precondition,
	}
	if len(plan.Effects) == 0 {
		lines = append(lines, "Effects: none")
	} else {
		lines = append(lines, fmt.Sprintf("Effects: %d", len(plan.Effects)))
		for _, effect := range plan.Effects {
			line := fmt.Sprintf("- %s: %s", effect.Class, effect.SummaryID)
			if effect.Destructive {
				line += " (destructive)"
			}
			lines = append(lines, line)
		}
	}
	lines = append(lines, fmt.Sprintf("Next: apply it with plan_apply plan_id=%s and a new request_id.", plan.PlanID))
	return strings.Join(lines, "\n")
}

// renderApply is the result of plan_apply.
func renderApply(result declarativeslice.ApplyResult) string {
	headline := "Operation: " + result.State
	if result.OperationID != "" {
		headline = fmt.Sprintf("Operation %s: %s", result.OperationID, result.State)
	}
	lines := []string{headline}
	if result.Delivery != "" {
		lines = append(lines, "Delivery: "+result.Delivery)
	}
	return strings.Join(lines, "\n")
}
