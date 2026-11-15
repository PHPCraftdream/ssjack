package transferlocal

import (
	"sort"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// treeItem is one manifest entry in archive order.
type treeItem struct {
	path  string
	parts []string
	dir   bool
	file  transfercore.Entry
}

// orderedTree lists the manifest depth first: a directory comes right before
// its whole subtree. A tar reader that sets a directory's time once the
// stream leaves it (GNU tar does) then keeps the time, whereas directories
// first and files after would see a later child change the parent again.
func orderedTree(m transfercore.Manifest) []treeItem {
	items := make([]treeItem, 0, len(m.Dirs)+len(m.Files))
	for _, d := range m.Dirs {
		items = append(items, treeItem{path: d, parts: strings.Split(d, "/"), dir: true})
	}
	for _, f := range m.Files {
		items = append(items, treeItem{path: f.Path, parts: strings.Split(f.Path, "/"), file: f})
	}
	sort.SliceStable(items, func(i, j int) bool {
		return compareParts(items[i].parts, items[j].parts) < 0
	})
	return items
}

// compareParts orders paths component by component, a parent before its
// children; comparing whole strings would put "a-b" between "a" and "a/x".
func compareParts(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := strings.Compare(a[i], b[i]); c != 0 {
			return c
		}
	}
	return len(a) - len(b)
}
