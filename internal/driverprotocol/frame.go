package driverprotocol

import (
	"io"

	"github.com/PHPCraftdream/ssjack/internal/driverframe"
)

func ReadStructuralRequest(r io.Reader) (StructuralRequest, error) {
	b, e := driverframe.Read(r)
	if e != nil {
		return StructuralRequest{}, e
	}
	if e = driverframe.RequireEOF(r); e != nil {
		return StructuralRequest{}, e
	}
	return ValidateStructuralRequest(b)
}
func ReadStructuralResponse(q StructuralRequest, r io.Reader) (StructuralResponse, error) {
	b, e := driverframe.Read(r)
	if e != nil {
		return StructuralResponse{}, e
	}
	if e = driverframe.RequireEOF(r); e != nil {
		return StructuralResponse{}, e
	}
	return ValidateStructuralResponse(q, b)
}

// WriteStructuralFrame checks only bounded JSON syntax; it does not structurally validate a request or response.
func WriteStructuralFrame(w io.Writer, payload []byte) error {
	if _, e := ParseJSON(payload); e != nil {
		return ErrInvalid
	}
	return driverframe.Write(w, payload)
}
