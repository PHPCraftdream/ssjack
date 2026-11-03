package appstorecrypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchortls"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
)

const MaxOwnerObjects = 128

var ErrOwnerChanged = errors.New("application-store changed; reload owner state before editing")

// OwnerObject describes private editor state without exposing its value.
type OwnerObject struct {
	ObjectID  [16]byte
	Reference appstoreref.Ref
	MediaType string
	Length    uint64
	Pending   bool
}

type ownerObject struct {
	value     []byte
	media     string
	reference appstoreref.Ref
	pending   bool
}

// OwnerEditor borrows the unlocked installation and directory. It is never an
// MCP capability. Close it before releasing those borrowed owner resources.
type OwnerEditor struct {
	mu        sync.Mutex
	writer    *SnapshotWriter
	transport *appstoreanchortls.Writer
	base      appstoreanchorstate.State
	objects   map[[16]byte]ownerObject
	dirty     bool
	closed    bool
	blocked   bool
}

func NewOwnerEditor(ctx context.Context, installation *Installation, directory *appstorefile.Directory) (*OwnerEditor, error) {
	if ctx == nil || installation == nil {
		return nil, ErrInstallation
	}
	opctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	writer, transport, err := installation.Writer(directory)
	if err != nil {
		return nil, err
	}
	owner := &OwnerEditor{writer: writer, transport: transport, objects: make(map[[16]byte]ownerObject)}
	if err := owner.load(opctx); err != nil {
		owner.Close()
		return nil, err
	}
	return owner, nil
}

func (o *OwnerEditor) Objects() []OwnerObject {
	o.mu.Lock()
	defer o.mu.Unlock()
	result := make([]OwnerObject, 0, len(o.objects))
	for id, object := range o.objects {
		result = append(result, OwnerObject{ObjectID: id, Reference: object.reference, MediaType: object.media, Length: uint64(len(object.value)), Pending: object.pending})
	}
	sort.Slice(result, func(i, j int) bool { return bytes.Compare(result[i].ObjectID[:], result[j].ObjectID[:]) < 0 })
	return result
}

func (o *OwnerEditor) Add(media string, value []byte) ([16]byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	var id [16]byte
	if o.closed || o.blocked || o.objects == nil || !o.base.Valid() || len(o.objects) >= MaxOwnerObjects || !validMedia(media) || len(value) > maxRAMSecretSize {
		return id, ErrRecord
	}
	if _, err := rand.Read(id[:]); err != nil {
		return [16]byte{}, err
	}
	if _, exists := o.objects[id]; exists || id == ([16]byte{}) {
		return [16]byte{}, ErrRecord
	}
	o.objects[id] = ownerObject{value: append([]byte{}, value...), media: media, pending: true}
	o.dirty = true
	return id, nil
}

func (o *OwnerEditor) Update(id [16]byte, value []byte) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	object, exists := o.objects[id]
	if o.closed || o.blocked || !exists || len(value) > maxRAMSecretSize {
		return ErrRecord
	}
	owned := append([]byte{}, value...)
	clear(object.value)
	object.value, object.pending = owned, true
	o.objects[id] = object
	o.dirty = true
	return nil
}

// Remove changes owner RAM only; the UI must confirm destructive owner actions.
func (o *OwnerEditor) Remove(id [16]byte) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	object, exists := o.objects[id]
	if o.closed || o.blocked || !exists {
		return ErrRecord
	}
	clear(object.value)
	delete(o.objects, id)
	o.dirty = true
	return nil
}

// Commit returns metadata only. Errors block retries until explicit inspection
// and a fresh owner session; they never imply that a mutation was withheld.
func (o *OwnerEditor) Commit(ctx context.Context) (SnapshotCommit, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if ctx == nil || o.closed || o.blocked || o.writer == nil || !o.base.Valid() {
		return SnapshotCommit{}, ErrWriterPending
	}
	if err := ctx.Err(); err != nil {
		return SnapshotCommit{}, err
	}
	if !o.dirty {
		refs := make([]appstoreref.Ref, 0, len(o.objects))
		for _, object := range o.objects {
			refs = append(refs, object.reference)
		}
		return SnapshotCommit{State: o.base, Refs: refs, EncodedHash: o.base.CommittedFileHash()}, nil
	}
	opctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	objects := make([]SnapshotObject, 0, len(o.objects))
	var closeObjects []func()
	defer func() {
		for _, closeObject := range closeObjects {
			closeObject()
		}
	}()
	for id, object := range o.objects {
		selected, closeObject, err := NewSecretObject(id, object.media, object.value)
		if err != nil {
			return SnapshotCommit{}, err
		}
		objects = append(objects, selected)
		closeObjects = append(closeObjects, closeObject)
	}
	o.blocked = true
	commit, err := o.writer.WriteFrom(opctx, o.base, objects)
	if err != nil {
		return SnapshotCommit{}, err
	}
	if !commit.State.Valid() || commit.State.StoreID() != o.base.StoreID() || commit.EncodedHash != commit.State.CommittedFileHash() || len(commit.Refs) != len(o.objects) {
		return SnapshotCommit{}, ErrRecord
	}
	seen := make(map[[16]byte]bool)
	for _, reference := range commit.Refs {
		id := reference.ObjectID()
		if _, exists := o.objects[id]; !exists || !reference.Valid() || seen[id] || reference.StoreID() != commit.State.StoreID() || reference.SnapshotID() != commit.State.CommittedSnapshotID() {
			return SnapshotCommit{}, ErrRecord
		}
		seen[id] = true
	}
	for _, reference := range commit.Refs {
		object := o.objects[reference.ObjectID()]
		object.reference, object.pending = reference, false
		o.objects[reference.ObjectID()] = object
	}
	o.base, o.dirty, o.blocked = commit.State, false, false
	return commit, nil
}

func (o *OwnerEditor) Close() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil
	}
	for id, object := range o.objects {
		clear(object.value)
		delete(o.objects, id)
	}
	o.closed = true
	if o.transport != nil {
		return o.transport.Close()
	}
	return nil
}

// WriteFrom adds optimistic concurrency, not authority, to an existing writer.
func (w *SnapshotWriter) WriteFrom(ctx context.Context, expected appstoreanchorstate.State, objects []SnapshotObject) (SnapshotCommit, error) {
	return w.write(ctx, objects, false, &expected)
}
