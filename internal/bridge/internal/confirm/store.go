// Package confirm implements the MCP elicitation confirmation seam: eligible
// tool calls answer an input_required result carrying one form elicitation and
// an opaque one-use state token, and the retry is dispatched only when the
// echoed state, tool name and canonicalized argument digest all match. The
// state lives in RAM only and is never persisted.
package confirm

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"reflect"
	"sync"
	"time"
)

const (
	// RequestKey is the single input request id of the elicitation.
	RequestKey = "ssjack-confirm-v1"

	// reviewMessage is the fixed dialog text of this slice: a placeholder
	// without paths, names or secrets. The real text is a later slice.
	reviewMessage = "Review this operation before it starts."

	// activeTTL is how long a pending confirmation stays usable.
	activeTTL = 5 * time.Minute
	// tombstoneTTL is how long an expired confirmation is remembered so the
	// retry can be told apart from an unknown token.
	tombstoneTTL = 2 * time.Minute

	pendingCap   = 128
	tombstoneCap = 128

	nonceLen   = 32
	stateLimit = 1024
)

// The fixed outcome texts of a refused retry. None of them carries argument
// contents.
const (
	Declined  = "operation was not started: declined"
	Cancelled = "operation was not started: cancelled"
	TimedOut  = "operation was not started: confirmation timed out"
	Invalid   = "operation was not started: confirmation could not be validated"
)

// Kind is the class of operation a confirmation dialog describes.
type Kind string

// KindTransfer marks the upload and download tools.
const KindTransfer Kind = "transfer"

// DialogBuilder supplies the elicitation message.
type DialogBuilder interface {
	ReviewMessage(kind Kind) string
}

// fixedDialog is the placeholder dialog of this slice.
type fixedDialog struct{}

func (fixedDialog) ReviewMessage(Kind) string { return reviewMessage }

// Classify decides whether an app_exec is non-observational. It is a seam:
// no side-effect-free classification exists in this tree (see
// internal/application), so the wiring leaves it nil and app_exec is never
// elicited.
type Classify interface {
	IsNonObservational(tool string, canonicalArgs []byte) (bool, error)
}

// tombstone holds the facts an expired confirmation must keep so the retry
// can be classified: its expiry, and the session that created it (the same
// stable identity as entry.session). RAM only, no raw data.
type tombstone struct {
	expiry  time.Time
	session any
}

// entry holds only the confirmation facts, never the raw arguments. session
// is the stable identity of the originating MCP session (its transport
// session id when available, else the *mcp.ServerSession pointer, else ""),
// binding the continuation state to the connection that requested it.
type entry struct {
	tool    string
	digest  string
	session any
	created time.Time
	expiry  time.Time
}

// Manager tracks the pending confirmations of one server.
type Manager struct {
	mu         sync.Mutex
	enabled    bool
	now        func() time.Time
	pending    map[string]*entry
	tombstones map[string]tombstone
	rand       io.Reader
	dialog     DialogBuilder
	classify   Classify
	debug      func(format string, args ...any)
}

// NewManager builds an enabled manager. now and rand replace the real clock
// and crypto/rand (nil is the real one), for the tests.
func NewManager(now func() time.Time, random io.Reader) *Manager {
	m := &Manager{
		enabled:    true,
		pending:    map[string]*entry{},
		tombstones: map[string]tombstone{},
		dialog:     fixedDialog{},
	}
	if now == nil {
		now = time.Now
	}
	m.now = now
	if random == nil {
		random = rand.Reader
	}
	m.rand = random
	return m
}

// NewManagerOff builds a manager wired exactly like NewManager but with the
// confirmation feature disabled. It exists so tests can hold a wired-but-
// disabled manager and assert that the disabled path is byte-identical on the
// wire to a server with no confirm wiring at all.
func NewManagerOff(now func() time.Time, random io.Reader) *Manager {
	m := NewManager(now, random)
	m.enabled = false
	return m
}

// Enabled reports whether the middleware is installed at all.
func (m *Manager) Enabled() bool { return m.enabled }

// SetClassify installs the app_exec classification seam. An untyped nil clears
// it; a typed-nil pointer is refused as an enabling classifier. No
// side-effect-free classification exists in this tree (see
// internal/application), so the wiring leaves it nil and app_exec is never
// elicited.
func (m *Manager) SetClassify(classify Classify) {
	if classify == nil {
		// An untyped nil clears the seam: app_exec is never elicited.
		m.classify = nil
		return
	}
	if value := reflect.ValueOf(classify); value.Kind() == reflect.Pointer && value.IsNil() {
		return
	}
	m.classify = classify
}

// SetDebug installs a failure-only diagnostic hook. The hook never receives
// argument contents.
func (m *Manager) SetDebug(debug func(format string, args ...any)) { m.debug = debug }

func (m *Manager) debugf(format string, args ...any) {
	if m.debug != nil {
		m.debug(format, args...)
	}
}

// Digest is the hex SHA-256 of the canonicalized argument bytes.
func Digest(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// create mints one state token for tool. It fails closed when the pending
// cap is reached: the caller answers the generic confirmation error instead
// of starting the operation.
func (m *Manager) create(tool, digest string, kind Kind, session any) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for token, e := range m.pending {
		if !now.Before(e.expiry) {
			delete(m.pending, token)
			if now.Sub(e.expiry) < tombstoneTTL {
				m.addTombstone(token, e.expiry, e.session)
			}
		}
	}
	if len(m.pending) >= pendingCap {
		m.debugf("confirm: pending capacity reached")
		return "", false
	}
	var nonce [nonceLen]byte
	if _, err := io.ReadFull(m.rand, nonce[:]); err != nil {
		m.debugf("confirm: nonce read failed: %v", err)
		return "", false
	}
	token := base64.RawURLEncoding.EncodeToString(nonce[:])
	if len(token) > stateLimit {
		m.debugf("confirm: state over the size cap")
		return "", false
	}
	m.pending[token] = &entry{tool: tool, digest: digest, session: session, created: now, expiry: now.Add(activeTTL)}
	return token, true
}

// outcome is the verdict of one retry validation.
type outcome int

const (
	outcomeAccepted outcome = iota
	outcomeDeclined
	outcomeCancelled
	outcomeTimedOut
	outcomeInvalid
)

// validate checks one retry against the pending state and consumes it. Every
// branch runs under the mutex, so a concurrent duplicate cannot also pass.
func (m *Manager) validate(token, tool, digest, action string, session any) outcome {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	e, ok := m.pending[token]
	if !ok {
		if tomb, tom := m.tombstones[token]; tom {
			if now.Sub(tomb.expiry) >= tombstoneTTL {
				delete(m.tombstones, token)
				m.debugf("confirm: expired state past the tombstone window")
				return outcomeInvalid
			}
			if tomb.session != session {
				// A foreign session retrying an expired token gets the generic
				// error: the timeout is not disclosed outside the originating
				// session, which alone gets TimedOut.
				m.debugf("confirm: expired state, foreign session (%s)", shortSession(session))
				return outcomeInvalid
			}
			m.debugf("confirm: expired state")
			return outcomeTimedOut
		}
		m.debugf("confirm: unknown or already used state")
		return outcomeInvalid
	}
	if !now.Before(e.expiry) {
		delete(m.pending, token)
		if now.Sub(e.expiry) >= tombstoneTTL {
			// Past the tombstone window the state is simply forgotten.
			m.debugf("confirm: state expired past the window")
			return outcomeInvalid
		}
		m.addTombstone(token, e.expiry, e.session)
		m.debugf("confirm: state expired")
		return outcomeTimedOut
	}
	if e.tool != tool || e.digest != digest {
		m.debugf("confirm: retry does not match the confirmed call")
		return outcomeInvalid
	}
	if e.session != session {
		// Wrong originating session: report exactly like an unknown token but
		// do NOT consume the record — the rightful session may still answer.
		m.debugf("confirm: retry session mismatch (%s)", shortSession(session))
		return outcomeInvalid
	}
	switch action {
	case "accept":
	case "decline":
	case "cancel":
	default:
		m.debugf("confirm: invalid action")
		return outcomeInvalid
	}
	delete(m.pending, token)
	switch action {
	case "accept":
		return outcomeAccepted
	case "decline":
		return outcomeDeclined
	default:
		return outcomeCancelled
	}
}

// addTombstone remembers an expired confirmation, evicting the oldest one
// first when the cap is reached. Capacity eviction of a tombstone only
// downgrades its retry to the generic error, which fails closed.
func (m *Manager) addTombstone(token string, expiry time.Time, session any) {
	if len(m.tombstones) >= tombstoneCap {
		oldest, oldestExpiry := "", time.Time{}
		for key, tomb := range m.tombstones {
			if oldest == "" || tomb.expiry.Before(oldestExpiry) {
				oldest, oldestExpiry = key, tomb.expiry
			}
		}
		delete(m.tombstones, oldest)
	}
	m.tombstones[token] = tombstone{expiry: expiry, session: session}
}
