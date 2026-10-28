package recoveryjournal

import (
	"context"
	"encoding/json"
	"github.com/PHPCraftdream/ssjack/internal/recovery"
)

func (j *Journal) publishDocument(d document) error {
	fail := func() error { j.poisoned = true; return ErrUnavailable }
	if !validDoc(d) {
		return fail()
	}
	d.Digest = digest(d)
	b, e := json.Marshal(d)
	if e != nil || len(b) > maxJournal {
		return fail()
	}
	marker, e := j.io.create(j.pendingPath())
	if e != nil {
		return fail()
	}
	if e = j.io.write(marker, []byte("pending")); e == nil {
		e = j.io.sync(marker)
	}
	closeErr := j.io.close(marker)
	if e == nil {
		e = closeErr
	}
	if e != nil || j.io.syncDir(j.root) != nil {
		return fail()
	}
	f, e := j.io.create(j.newPath())
	if e != nil {
		return fail()
	}
	if e = j.io.write(f, b); e == nil {
		e = j.io.sync(f)
	}
	closeErr = j.io.close(f)
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return fail()
	}
	if j.io.rename(j.newPath(), j.path()) != nil || j.io.syncDir(j.root) != nil {
		return fail()
	}
	if j.io.remove(j.pendingPath()) != nil || j.io.syncDir(j.root) != nil {
		return fail()
	}
	j.last = d
	return nil
}

func (j *Journal) pendingPath() string { return j.path() + ".pending" }
func (j *Journal) newPath() string     { return j.path() + ".new" }

func (j *Journal) Quarantine(ctx context.Context, b recovery.Binding) error {
	return j.quarantine(ctx, b, b)
}
func (j *Journal) QuarantineConflict(ctx context.Context, a, b recovery.Binding) error {
	return j.quarantine(ctx, a, b)
}
func (j *Journal) quarantine(ctx context.Context, a, b recovery.Binding) error {
	return j.mutate(ctx, func(d *document) error {
		if !recovery.ValidBinding(a) || !recovery.ValidBinding(b) {
			return ErrUnavailable
		}

		// Find originals by their full binding. Invocation-only matching could
		// quarantine a different resource and overwrite its durable evidence.
		indices := make([]int, 0, 2)
		for n := range d.Records {
			r := &d.Records[n]
			if r.Intent.Binding == a || r.Intent.Binding == b {
				indices = append(indices, n)
			}
		}
		if len(indices) == 0 && a == b {
			if len(d.Records) >= maxEntries {
				return ErrUnavailable
			}
			d.Records = append(d.Records, record{Intent: recovery.Intent{Binding: a, Phase: recovery.Quarantined}, Blocked: []recovery.Binding{a}})
			return nil
		}
		if len(indices) == 0 {
			return ErrUnavailable
		}
		foundA, foundB := false, false
		for _, n := range indices {
			binding := d.Records[n].Intent.Binding
			foundA = foundA || binding == a
			foundB = foundB || binding == b
		}
		if !foundA {
			// A conflict involving a new invocation/resource still needs a
			// durable fence. Keep the original stored binding as the record.
			return ErrUnavailable
		}
		if !foundB && a != b {
			for n := range d.Records {
				r := &d.Records[n]
				if r.Intent.Binding == a {
					continue
				}
				if r.Intent.Binding.Invocation == b.Invocation || r.Intent.Binding.Resource == b.Resource || conflicts(*r, b) {
					return recovery.ErrConflict
				}
			}
			// The requested binding has no stored intent; attach its fence to
			// the stored record rather than inventing an intent record.
			for n := range d.Records {
				r := &d.Records[n]
				if r.Intent.Binding == a {
					addBlock(&r.Blocked, a)
					addBlock(&r.Blocked, b)
					r.Intent.Phase = recovery.Quarantined
					return nil
				}
			}
		}
		for n := range d.Records {
			r := &d.Records[n]
			if r.Intent.Binding != a && r.Intent.Binding != b {
				if conflicts(*r, a) || conflicts(*r, b) || r.Intent.Binding.Invocation == a.Invocation || r.Intent.Binding.Resource == a.Resource || r.Intent.Binding.Invocation == b.Invocation || r.Intent.Binding.Resource == b.Resource {
					return recovery.ErrConflict
				}
				continue
			}
			addBlock(&r.Blocked, r.Intent.Binding)
			r.Intent.Phase = recovery.Quarantined
		}
		return nil
	})
}
func addBlock(bs *[]recovery.Binding, b recovery.Binding) {
	for _, x := range *bs {
		if x == b {
			return
		}
	}
	*bs = append(*bs, b)
}
