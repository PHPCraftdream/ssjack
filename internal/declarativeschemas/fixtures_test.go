package declarativeschemas_test

type fixture struct {
	name   string
	input  string
	output string
}

var fixtures = []fixture{
	{
		"driver_list",
		`{"$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{},"required":[],"type":"object"}`,
		`{"$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"drivers":{"items":{"additionalProperties":false,"properties":{"capabilities":{"items":{"enum":["observe","plan","apply","conditional_write","exclusive_owner","cancel","reconcile","verify_adoption"]},"maxItems":8,"minItems":1,"type":"array"},"driver_id":{"maxLength":64,"type":"string"},"kinds":{"items":{"maxLength":64,"type":"string"},"maxItems":128,"minItems":0,"type":"array"},"limits":{"additionalProperties":false,"properties":{"cancellation_reserve_bytes":{"maximum":4096,"minimum":4096,"type":"integer"},"emergency_cancellations":{"maximum":16,"minimum":1,"type":"integer"},"global_operations":{"maximum":64,"minimum":1,"type":"integer"},"process_slots":{"maximum":4,"minimum":1,"type":"integer"},"records":{"maximum":256,"minimum":1,"type":"integer"},"session_operations":{"maximum":32,"minimum":1,"type":"integer"},"storage_bytes":{"maximum":16777216,"minimum":1,"type":"integer"}},"required":["cancellation_reserve_bytes","emergency_cancellations","global_operations","process_slots","records","session_operations","storage_bytes"],"type":"object"},"protocol":{"maximum":1,"minimum":1,"type":"integer"}},"required":["capabilities","driver_id","kinds","limits","protocol"],"type":"object"},"maxItems":128,"minItems":0,"type":"array"}},"required":["drivers"],"type":"object"}`,
	},
	{
		"resource_status",
		`{"$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"driver_id":{"maxLength":64,"type":"string"},"kind":{"maxLength":64,"type":"string"},"resource_id":{"maxLength":128,"type":"string"},"schema_id":{"maxLength":64,"type":"string"},"target":{"maxLength":64,"type":"string"}},"required":["driver_id","kind","resource_id","schema_id","target"],"type":"object"}`,
		`{"$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"observed_at":{"maxLength":24,"type":"string"},"projection":{"additionalProperties":true,"maxProperties":128,"type":"object"},"revision":{"maxLength":128,"type":["string","null"]},"state":{"enum":["present","absent","unknown"]}},"required":["observed_at","projection","revision","state"],"type":"object"}`,
	},
	{
		"resource_plan",
		`{"$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"desired":{"additionalProperties":true,"maxProperties":128,"type":"object"},"driver_id":{"maxLength":64,"type":"string"},"kind":{"maxLength":64,"type":"string"},"request_id":{"maxLength":22,"type":"string"},"resource_id":{"maxLength":128,"type":"string"},"schema_id":{"maxLength":64,"type":"string"},"target":{"maxLength":64,"type":"string"}},"required":["desired","driver_id","kind","request_id","resource_id","schema_id","target"],"type":"object"}`,
		`{"$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"digest":{"maxLength":64,"type":"string"},"effects":{"items":{"additionalProperties":false,"properties":{"class":{"maxLength":64,"type":"string"},"destructive":{"type":"boolean"},"summary_id":{"maxLength":64,"type":"string"}},"required":["class","destructive","summary_id"],"type":"object"},"maxItems":256,"minItems":0,"type":"array"},"expires_at":{"maxLength":24,"type":"string"},"plan_id":{"maxLength":22,"type":"string"},"precondition":{"maxLength":128,"type":["string","null"]}},"required":["digest","effects","expires_at","plan_id","precondition"],"type":"object"}`,
	},
	{
		"plan_apply",
		`{"$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"plan_id":{"maxLength":22,"type":"string"},"request_id":{"maxLength":22,"type":"string"}},"required":["plan_id","request_id"],"type":"object"}`,
		`{"$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"operation_id":{"maxLength":22,"type":"string"},"state":{"enum":["RESERVED","RUNNING","SUCCEEDED","FAILED","CANCELLED","UNKNOWN"]}},"required":["operation_id","state"],"type":"object"}`,
	},
	{
		"operation_read",
		`{"$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"operation_id":{"maxLength":22,"type":"string"}},"required":["operation_id"],"type":"object"}`,
		`{"$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"error":{"additionalProperties":false,"properties":{"code":{"maxLength":64,"type":"string"},"message":{"maxLength":256,"type":"string"},"operation_id":{"maxLength":22,"type":["string","null"]},"retryable":{"type":"boolean"}},"required":["code","message","operation_id","retryable"],"type":["object","null"]},"operation_id":{"maxLength":22,"type":"string"},"phase":{"enum":["queued","observing","planning","applying","verifying","reconciling","cancelling","complete"]},"progress":{"maximum":100,"minimum":0,"type":["integer","null"]},"result":{"additionalProperties":false,"properties":{"projection":{"additionalProperties":true,"maxProperties":128,"type":"object"},"verified":{"type":"boolean"}},"required":["projection","verified"],"type":["object","null"]},"revisions":{"additionalProperties":false,"properties":{"adopted":{"maxLength":128,"type":["string","null"]},"applied":{"maxLength":128,"type":["string","null"]},"delivered":{"maxLength":128,"type":["string","null"]},"observed":{"maxLength":128,"type":["string","null"]}},"required":["adopted","applied","delivered","observed"],"type":"object"},"state":{"enum":["RESERVED","RUNNING","SUCCEEDED","FAILED","CANCELLED","UNKNOWN"]},"updated_at":{"maxLength":24,"type":"string"}},"required":["error","operation_id","phase","progress","result","revisions","state","updated_at"],"type":"object"}`,
	},
	{
		"operation_cancel",
		`{"$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"operation_id":{"maxLength":22,"type":"string"},"request_id":{"maxLength":22,"type":"string"}},"required":["operation_id","request_id"],"type":"object"}`,
		`{"$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"cancellation":{"enum":["confirmed","unsupported","pending"]},"operation_id":{"maxLength":22,"type":"string"},"state":{"enum":["RESERVED","RUNNING","SUCCEEDED","FAILED","CANCELLED","UNKNOWN"]}},"required":["cancellation","operation_id","state"],"type":"object"}`,
	},
}
