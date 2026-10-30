//go:build !linux

package appstoresink

import (
	"context"

	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
)

type consumerState struct{}
type deliveryState struct{}

func newConsumer(Config) (*Consumer, error)                    { return nil, ErrUnsupported }
func consumerBinding(*Consumer) Binding                        { return Binding{} }
func checkConsumer(*Consumer, appstoreref.Ref, [32]byte) error { return ErrUnsupported }
func closeConsumer(*Consumer) error                            { return nil }
func beginDelivery(*Consumer, context.Context, appstoreref.Ref, [32]byte, uint64) (*Delivery, error) {
	return nil, ErrUnsupported
}
func writeDelivery(*Delivery, []byte) (int, error) { return 0, ErrUnsupported }
func finishDelivery(*Delivery) (Result, error)     { return Result{}, ErrUnsupported }
func closeDelivery(*Delivery) error                { return nil }
