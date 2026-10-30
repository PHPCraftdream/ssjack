package appstoreanchorledger

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorcore"
)

const headerSize int64 = 64
const recordSize int64 = 676

func header(store [16]byte, capacity int) [64]byte {
	var b [64]byte
	copy(b[:8], "SSASLOG1")
	copy(b[8:24], store[:])
	binary.BigEndian.PutUint16(b[24:26], 1)
	binary.BigEndian.PutUint32(b[26:30], uint32(capacity))
	return b
}
func digest(domain string, parts ...[]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(domain))
	for _, p := range parts {
		h.Write(p)
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}
func encodeRecord(s *backendState, item record) ([676]byte, [32]byte, error) {
	var b [676]byte
	if !item.request.Valid() || item.request.Kind() == appstoreanchorcore.Read || item.grant.Role() != appstoreanchorcore.Writer {
		return b, [32]byte{}, ErrInvalid
	}
	reply, err := item.result.Unsigned()
	if err != nil {
		return b, [32]byte{}, ErrInvalid
	}
	raw := item.request.Bytes()
	credential := item.grant.CredentialID()
	copy(b[:8], "SSASREC1")
	binary.BigEndian.PutUint64(b[8:16], uint64(len(s.records)))
	copy(b[16:48], credential[:])
	b[48] = byte(item.grant.Role())
	binary.BigEndian.PutUint16(b[50:52], uint16(len(raw)))
	copy(b[52:356], raw)
	copy(b[356:644], reply[:])
	head := digest("SSAPP-ANCHOR-LEDGER-RECORD-v1", s.store[:], s.head[:], b[:644])
	copy(b[644:676], head[:])
	return b, head, nil
}

func recoverRecords(s *backendState, size int64) error {
	if size < headerSize || (size-headerSize)%recordSize != 0 || (size-headerSize)/recordSize > int64(s.limit) {
		return ErrInvalid
	}
	if _, err := s.log.Seek(0, io.SeekStart); err != nil {
		return ErrUnavailable
	}
	var actual [64]byte
	if _, err := io.ReadFull(s.log, actual[:]); err != nil {
		return ErrUnavailable
	}
	expected := header(s.store, s.limit)
	if actual != expected {
		return ErrInvalid
	}
	s.head = digest("SSAPP-ANCHOR-LEDGER-GENESIS-v1", actual[:])
	for index := int64(0); index < (size-headerSize)/recordSize; index++ {
		var raw [676]byte
		if _, err := io.ReadFull(s.log, raw[:]); err != nil {
			return ErrUnavailable
		}
		if err := recoverRecord(s, raw); err != nil {
			return err
		}
	}
	return nil
}

func recoverRecord(s *backendState, b [676]byte) error {
	length := int(binary.BigEndian.Uint16(b[50:52]))
	if string(b[:8]) != "SSASREC1" || binary.BigEndian.Uint64(b[8:16]) != uint64(len(s.records)) || b[48] != byte(appstoreanchorcore.Writer) || b[49] != 0 || (length != 272 && length != 304) {
		return ErrInvalid
	}
	if !bytes.Equal(b[52+length:356], make([]byte, 304-length)) {
		return ErrInvalid
	}
	head := digest("SSAPP-ANCHOR-LEDGER-RECORD-v1", s.store[:], s.head[:], b[:644])
	if head != [32]byte(b[644:676]) {
		return ErrInvalid
	}
	request, err := appstoreanchorcore.Parse(b[52:52+length], s.store)
	if err != nil {
		return ErrInvalid
	}
	grant, err := appstoreanchorcore.NewGrant(s.store, [32]byte(b[16:48]), appstoreanchorcore.Writer)
	if err != nil {
		return ErrInvalid
	}
	requestKey, mutationKey := keys(request, grant)
	if _, ok := s.requests[requestKey]; ok {
		return ErrInvalid
	}
	if _, ok := s.mutations[mutationKey]; ok {
		return ErrInvalid
	}
	result, err := appstoreanchorcore.Evaluate(request, grant, s.current)
	if err != nil {
		return ErrInvalid
	}
	reply, err := result.Unsigned()
	if err != nil || !bytes.Equal(reply[:], b[356:644]) {
		return ErrInvalid
	}
	remember(s, record{request: request, grant: grant, result: result}, head)
	return nil
}
