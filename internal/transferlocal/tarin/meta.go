package tarin

import (
	"os"
	"sort"
	"strings"
	"time"
)

// Directory transfers carry modification times: BuildTar records each
// entry's mtime in whole seconds and ExtractTar restores it. A time before
// 1980 (an unset header reads as the 1970 epoch) or after 2100 is not
// restored, so a hostile or empty header cannot plant an absurd date, and a
// failure to set a time never fails a transfer: it is metadata, and the
// verified content has already been written.
var (
	minRestoredTime = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	maxRestoredTime = time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
)

// applyModTime restores one modification time, best effort.
func applyModTime(path string, modTime time.Time) {
	if modTime.Before(minRestoredTime) || !modTime.Before(maxRestoredTime) {
		return
	}
	_ = os.Chtimes(path, modTime, modTime)
}

// dirTime is one staged directory and the time its archive entry carried.
type dirTime struct {
	rel     string
	modTime time.Time
}

// applyDirTimes restores directory times deepest first and only after every
// entry was written, because creating a child changes its parent's time.
func applyDirTimes(root string, times []dirTime) {
	sort.SliceStable(times, func(i, j int) bool {
		return strings.Count(times[i].rel, "/") > strings.Count(times[j].rel, "/")
	})
	for _, d := range times {
		applyModTime(joinOSPath(root, d.rel), d.modTime)
	}
}
