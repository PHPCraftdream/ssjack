package core

import (
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// LinkFailure returns the error of a command session that ended without a
// remote exit status (connection reset, EOF, dial or handshake failure): a
// drop in the terms of docs/FILE-TRANSFER.md. A remote command that exited
// non-zero, a cancel and every local failure are never link failures.
func LinkFailure() *transfercore.Error {
	return Classed(transfercore.ClassRemoteFailed, MsgTransport, -1)
}

// IsLinkFailure reports whether err is a LinkFailure.
func IsLinkFailure(err error) bool {
	var e *transfercore.Error
	return errors.As(err, &e) && e.Class == transfercore.ClassRemoteFailed && e.ExitCode == -1 && e.Message == MsgTransport
}
