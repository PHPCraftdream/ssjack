package engine

// Exported solely for the external chunk tests (package engine_test, same
// directory): the exact diskFree injection seam and the verbatim message and
// retry constants they assert.
var DiskFree = &diskFree

const (
	MsgDiskShort      = msgDiskShort
	MsgLocalDiskShort = msgLocalDiskShort
	StatSourceTries   = statSourceTries
)
