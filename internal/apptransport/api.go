package apptransport

import (
	"context"

	"github.com/PHPCraftdream/ssjack/internal/remote"

	server "github.com/PHPCraftdream/ssjack/internal/apptransport/internal/server"
)

const (
	EnvEndpoint = server.EnvEndpoint
	EnvToken    = server.EnvToken
	EnvPin      = server.EnvPin
	Protocol    = server.Protocol
)

const (
	ChunkSize             = server.ChunkSize
	TextStreamFormat      = server.TextStreamFormat
	TextStreamPreparePath = server.TextStreamPreparePath
	TextStreamExecutePath = server.TextStreamExecutePath
	TextStreamReversePath = server.TextStreamReversePath
)

// TextReverseResponseLimit bounds the complete encoded reverse-text response.
const TextReverseResponseLimit = server.TextReverseResponseLimit

type (
	Bootstrap               = server.Bootstrap
	InfoOutput              = server.InfoOutput
	Server                  = server.Server
	TextHydrator            = server.TextHydrator
	TextReverseCopier       = server.TextReverseCopier
	TextStreamHydrator      = server.TextStreamHydrator
	TextStreamReverseCopier = server.TextStreamReverseCopier
	TextStreamHeader        = server.TextStreamHeader
	TextStreamReply         = server.TextStreamReply
	TextReverseCopyInput    = server.TextReverseCopyInput
	TextReverseCopyOutput   = server.TextReverseCopyOutput
	TextHydrateInput        = server.TextHydrateInput
	TextHydrateOutput       = server.TextHydrateOutput
	StartInput              = server.StartInput
	StartOutput             = server.StartOutput
	InputInput              = server.InputInput
	InputOutput             = server.InputOutput
	JobInput                = server.JobInput
	ReadOutput              = server.ReadOutput
	CancelOutput            = server.CancelOutput
)

func Listen(parent context.Context, profile string, runner remote.StreamRunner) (*Server, error) {
	return server.Listen(parent, profile, runner)
}

func ListenWithTextAdapter(parent context.Context, profile string, runner remote.StreamRunner, adapter TextHydrator) (*Server, error) {
	return server.ListenWithTextAdapter(parent, profile, runner, adapter)
}

func ListenWithReverseTextAdapter(parent context.Context, profile string, runner remote.StreamRunner, adapter TextReverseCopier) (*Server, error) {
	return server.ListenWithReverseTextAdapter(parent, profile, runner, adapter)
}

func ListenWithTextStreamAdapter(parent context.Context, profile string, runner remote.StreamRunner, adapter TextStreamHydrator) (*Server, error) {
	return server.ListenWithTextStreamAdapter(parent, profile, runner, adapter)
}

func ListenWithReverseTextStreamAdapter(parent context.Context, profile string, runner remote.StreamRunner, adapter TextStreamReverseCopier) (*Server, error) {
	return server.ListenWithReverseTextStreamAdapter(parent, profile, runner, adapter)
}

func Environment(base []string, bootstrap Bootstrap) []string {
	return server.Environment(base, bootstrap)
}

func IsEnvironmentName(name string) bool {
	return server.IsEnvironmentName(name)
}
