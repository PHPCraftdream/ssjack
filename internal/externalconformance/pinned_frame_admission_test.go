package externalconformance

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/driverframe"
	"github.com/PHPCraftdream/ssjack/internal/driverprotocol"
)

func TestPinnedAdmissionParserFrameDistinctions(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		want        error
	}{
		{"null_exact", `null` + strings.Repeat(" ", 65532), nil},
		{"null_over", `null` + strings.Repeat(" ", 65533), driverprotocol.ErrInvalid},
		{"zero", `0`, nil},
		{"negative_zero", `-0`, driverprotocol.ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := driverprotocol.ParseJSON([]byte(tc.value)); !errors.Is(err, tc.want) {
				t.Errorf("parse: %v, want %v", err, tc.want)
			}
			var out bytes.Buffer
			if err := driverprotocol.WriteStructuralFrame(&out, []byte(tc.value)); !errors.Is(err, tc.want) {
				t.Errorf("write: %v, want %v", err, tc.want)
			}
			if tc.want != nil && out.Len() != 0 {
				t.Errorf("invalid write produced %d bytes", out.Len())
			}
		})
	}
	if driverframe.MaxPayload != 65536 {
		t.Fatal("frame payload limit changed")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], 65537)
	if _, err := driverprotocol.ReadStructuralRequest(bytes.NewReader(header[:])); !errors.Is(err, driverframe.ErrLength) {
		t.Errorf("oversize header: %v, want ErrLength", err)
	}
}

func TestPinnedAdmissionStructuralRequestDistinctions(t *testing.T) {
	const observe = `{"protocol":1,"request_id":"AAAAAAAAAAAAAAAAAAAAAA","action":"observe","target":"target","kind":"kind","schema_id":"cache.desired","resource_id":"r","desired":null,"expected_revision":null,"plan_digest":null,"allowed_effects":[],"deadline_unix_ms":1,"max_response_bytes":1000,"operation_id":null}`
	for _, tc := range []struct {
		size       int
		structWant error
		frameWant  error
	}{
		{65536, nil, nil},
		{65537, driverprotocol.ErrInvalid, driverframe.ErrLength},
	} {
		t.Run(fmt.Sprintf("observe_%d", tc.size), func(t *testing.T) {
			payload := []byte(observe + strings.Repeat(" ", tc.size-len(observe)))
			if _, err := driverprotocol.ValidateStructuralRequest(payload); !errors.Is(err, tc.structWant) {
				t.Errorf("structural: %v, want %v", err, tc.structWant)
			}
			var frame bytes.Buffer
			var header [4]byte
			binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
			frame.Write(header[:])
			frame.Write(payload)
			if _, err := driverprotocol.ReadStructuralRequest(&frame); !errors.Is(err, tc.frameWant) {
				t.Errorf("read: %v, want %v", err, tc.frameWant)
			}
		})
	}
	const schema = prefix + `"additionalProperties":false,"properties":{"x":{"const":0,"type":"integer"}},"required":["x"],"type":"object"}`
	digest := admissionSchema(t, schema)
	for _, tc := range []struct {
		name, value string
		want        error
	}{{"zero", `0`, nil}, {"negative_zero", `-0`, driverprotocol.ErrInvalid}} {
		t.Run(tc.name, func(t *testing.T) {
			plan := `{"protocol":1,"request_id":"AAAAAAAAAAAAAAAAAAAAAA","action":"plan","target":"target","kind":"kind","schema_id":"cache.desired","resource_id":"r","desired":{"x":` + tc.value + `},"expected_revision":null,"plan_digest":null,"allowed_effects":[],"deadline_unix_ms":1,"max_response_bytes":1000,"operation_id":null}`
			if _, err := driverprotocol.ValidateStructuralRequest([]byte(plan)); !errors.Is(err, tc.want) {
				t.Errorf("structural: %v, want %v", err, tc.want)
			}
			if _, err := driverprotocol.ValidatePinnedRequest([]byte(plan), []byte(schema), "cache.desired", digest, "target", "kind"); !errors.Is(err, tc.want) {
				t.Errorf("pinned: %v, want %v", err, tc.want)
			}
		})
	}
}
