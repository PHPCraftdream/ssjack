//go:build !linux

package immutableexec

import (
	"context"

	"github.com/PHPCraftdream/ssjack/internal/driverprotocol"
)

func Bind(string, [32]byte, ...string) (*Runner, error) { return nil, ErrUnsupported }

type Runner struct{}

func (*Runner) Run(context.Context, []string, string) error { return ErrUnsupported }
func (*Runner) Observe(context.Context, []string, string, []byte) (driverprotocol.StructuralResponse, error) {
	return driverprotocol.StructuralResponse{}, ErrUnsupported
}
func (*Runner) Close() error { return nil }
