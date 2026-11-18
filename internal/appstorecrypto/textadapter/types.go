// Package textadapter hydrates and reverse-copies text through approved consumer runners.
package textadapter

import "github.com/PHPCraftdream/ssjack/internal/appstorecrypto/delivery"

type ReverseTextOutcome struct {
	Status delivery.DeliveryStatus
	Text   []byte
}

type TextStreamPreparation struct {
	Ticket string
	Bytes  uint64
}
