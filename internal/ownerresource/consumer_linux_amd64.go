//go:build linux && amd64

package ownerresource

import (
	"context"
	"io"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/apptransport"
)

func serveText(ctx context.Context, r *Resources, request TextRequest) (*apptransport.Server, io.Closer, error) {
	var adapter io.Closer
	var server *apptransport.Server
	var err error
	switch request.Mode {
	case "hydrate-v1", "reverse-copy-v1":
		base, createErr := appstorecrypto.NewBorrowedTextAdapter(ctx, r.installation, r.store, r.directory, request.GrantID, request.Profile, request.CredentialDigest, request.Runner, request.Mode)
		if createErr != nil {
			return nil, nil, createErr
		}
		adapter = base
		if request.Mode == "hydrate-v1" {
			server, err = apptransport.ListenWithTextAdapter(ctx, request.Profile, request.Runner, base)
		} else {
			server, err = apptransport.ListenWithReverseTextAdapter(ctx, request.Profile, request.Runner, base)
		}
	case "hydrate-stream-v2", "reverse-copy-stream-v2":
		stream, createErr := appstorecrypto.NewBorrowedTextStreamAdapter(ctx, r.installation, r.store, r.directory, request.GrantID, request.Profile, request.CredentialDigest, request.Runner, request.Mode)
		if createErr != nil {
			return nil, nil, createErr
		}
		adapter = stream
		if request.Mode == "hydrate-stream-v2" {
			server, err = apptransport.ListenWithTextStreamAdapter(ctx, request.Profile, request.Runner, stream)
		} else {
			server, err = apptransport.ListenWithReverseTextStreamAdapter(ctx, request.Profile, request.Runner, stream)
		}
	default:
		return nil, nil, ErrConsumer
	}
	if err != nil {
		_ = adapter.Close()
		return nil, nil, err
	}
	return server, adapter, nil
}
