package transferlink

import (
	"reflect"
	"testing"
)

func listed(name string, off, length, size int64) Listed {
	return Listed{Name: name, Range: Range{Off: off, Len: length}, Size: size}
}

func TestAcceptListedBuildsTheCoverage(t *testing.T) {
	entries := []Listed{
		listed("part-100-100", 100, 100, 100),
		listed("part-0-100", 0, 100, 100),
		listed("part-0-50", 0, 50, 50),     // shorter at an accepted offset: overlaps
		listed("part-150-50", 150, 50, 50), // starts inside an accepted part
		listed("part-200-100", 200, 100, 99),
		listed("part-300-100", 300, 100, 100),
		listed("part-900-300", 900, 300, 300), // ends past the file
		listed("part-2000-10", 2000, 10, 10),  // starts past the file
	}
	accepted, rejected := AcceptListed(1000, entries)
	wantAccepted := []Range{{Off: 0, Len: 100}, {Off: 100, Len: 100}, {Off: 300, Len: 100}}
	if !reflect.DeepEqual(accepted, wantAccepted) {
		t.Fatalf("accepted = %v, want %v", accepted, wantAccepted)
	}
	wantRejected := []string{"part-0-50", "part-150-50", "part-200-100", "part-900-300", "part-2000-10"}
	if !reflect.DeepEqual(rejected, wantRejected) {
		t.Fatalf("rejected = %v, want %v", rejected, wantRejected)
	}
}

func TestAcceptListedLongerFirstAndWrongSizeDoesNotShadow(t *testing.T) {
	accepted, rejected := AcceptListed(1000, []Listed{
		listed("part-0-50", 0, 50, 50),
		listed("part-0-100", 0, 100, 99), // lying size, tried first, rejected
	})
	if !reflect.DeepEqual(accepted, []Range{{Off: 0, Len: 50}}) || !reflect.DeepEqual(rejected, []string{"part-0-100"}) {
		t.Fatalf("accepted = %v, rejected = %v", accepted, rejected)
	}
}

func TestAcceptListedEmptyAndNegativeSize(t *testing.T) {
	if accepted, rejected := AcceptListed(10, nil); accepted != nil || rejected != nil {
		t.Fatalf("empty input gave %v, %v", accepted, rejected)
	}
	accepted, rejected := AcceptListed(-5, []Listed{listed("part-0-1", 0, 1, 1)})
	if accepted != nil || !reflect.DeepEqual(rejected, []string{"part-0-1"}) {
		t.Fatalf("negative size gave %v, %v", accepted, rejected)
	}
}

func TestAcceptListedDoesNotModifyItsInput(t *testing.T) {
	in := []Listed{listed("part-100-100", 100, 100, 100), listed("part-0-100", 0, 100, 100)}
	before := append([]Listed(nil), in...)
	AcceptListed(1000, in)
	if !reflect.DeepEqual(in, before) {
		t.Fatalf("input modified: %v", in)
	}
}
