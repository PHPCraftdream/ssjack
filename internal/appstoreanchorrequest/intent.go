package appstoreanchorrequest

import "github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"

const IntentSize = 312

type Intent struct {
	raw     [IntentSize]byte
	request Request
	parsed  bool
}

// NewIntent creates bytes only, never a durable record or replay permission.
func NewIntent(commit Request) (Intent, error) {
	if !commit.Valid() || commit.kind != commitKind {
		return Intent{}, ErrInvalid
	}
	var raw [IntentSize]byte
	copy(raw[:8], "SSAPCMT1")
	transaction := commit.state.CommittedTransactionID()
	copy(raw[8:24], transaction[:])
	copy(raw[24:56], commit.raw[48:80])
	stateBytes := commit.state.Bytes()
	copy(raw[56:248], stateBytes[:])
	copy(raw[248:280], commit.raw[272:304])
	candidate := commit.state.CommittedFileHash()
	copy(raw[280:312], candidate[:])
	return ParseIntent(raw[:], commit.StoreID())
}

// ParseIntent checks encoding and reconstructs bytes, not candidate/intent provenance.
func ParseIntent(raw []byte, expectedStore [16]byte) (Intent, error) {
	if len(raw) != IntentSize || expectedStore == ([16]byte{}) {
		return Intent{}, ErrInvalid
	}
	var b [IntentSize]byte
	copy(b[:], raw)
	if string(b[:8]) != "SSAPCMT1" {
		return Intent{}, ErrInvalid
	}
	transaction := [16]byte(b[8:24])
	expected := [32]byte(b[24:56])
	key := [32]byte(b[248:280])
	candidate := [32]byte(b[280:312])
	state, err := appstoreanchorstate.Parse(b[56:248], expectedStore)
	if err != nil || state.Sequence() == 0 || transaction == ([16]byte{}) || candidate == ([32]byte{}) || expected == ([32]byte{}) || expected == state.Hash() || transaction != state.CommittedTransactionID() || candidate != state.CommittedFileHash() {
		return Intent{}, ErrInvalid
	}
	want := sum("SSAPP-COMMIT-v1", expectedStore[:], transaction[:], candidate[:])
	if key != want {
		return Intent{}, ErrInvalid
	}
	request, err := mutation(commitKind, state, expected, key, "SSAPP-COMMIT-REQUEST-ID-v1")
	if err != nil {
		return Intent{}, ErrInvalid
	}
	return Intent{raw: b, request: request, parsed: true}, nil
}

// Valid reports byte admission only, not durability or authority to replay.
func (i Intent) Valid() bool              { return i.parsed }
func (i Intent) Bytes() [IntentSize]byte  { return i.raw }
func (i Intent) Request() (Request, bool) { return i.request, i.parsed }
