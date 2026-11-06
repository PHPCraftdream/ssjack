//go:build !linux || !amd64

package ownerresource

import (
	"context"
	"io"

	"github.com/PHPCraftdream/ssjack/internal/apptransport"
)

func serveText(context.Context, *Resources, TextRequest) (*apptransport.Server, io.Closer, error) {
	return nil, nil, ErrConsumer
}
