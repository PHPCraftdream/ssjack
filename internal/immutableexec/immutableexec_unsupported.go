//go:build !linux

package immutableexec

import "context"

func Bind(string, [32]byte, ...string) (*Runner, error) { return nil, ErrUnsupported }

type Runner struct{}

func (*Runner) Run(context.Context, []string, string) error { return ErrUnsupported }
func (*Runner) Close() error                                { return nil }
