package approvals

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/application/discovery"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

type Status uint8

const (
	StatusCandidate Status = iota
	StatusApproved
	StatusRejected
	StatusChanged
	StatusUnsafe
)

type Entry struct {
	Status                           Status
	Name, DisplayPath                string
	PathSafe, NameSafe               bool
	HashPrefix                       string
	Reason                           string
	ApprovedHashPrefix               string
	DisplayHash, DisplayApprovedHash string
	OutsideWorkdir                   bool
	Record                           vault.Approval
	candidate                        *discovery.Candidate
}

func fingerprintPrefix(c *discovery.Candidate) string {
	if c == nil {
		return ""
	}
	h := hex.EncodeToString(c.Fingerprint[:])
	return h[:12]
}
func List(root string, records []vault.Approval) []Entry {
	scan := discovery.Scan(root)
	entries := make([]Entry, 0, len(scan.Candidates)+len(scan.Diagnostics)+len(records)+1)
	matched := make(map[int]bool)
	if scan.Overflow {
		entries = append(entries, Entry{Status: StatusUnsafe, Reason: scan.OverflowReason})
	} else {
		for i := range scan.Candidates {
			candidate := &scan.Candidates[i]
			entry := Entry{Status: StatusCandidate, candidate: candidate, HashPrefix: fingerprintPrefix(candidate)}
			entry.Name, entry.NameSafe = display(candidate.Name)
			entry.DisplayPath, entry.PathSafe = display(candidate.Path)
			entry.DisplayHash, _ = display(entry.HashPrefix)
			for j, record := range records {
				if filepath.Clean(record.Path) != filepath.Clean(candidate.CanonicalPath) {
					continue
				}
				matched[j] = true
				entry.Record = record
				entry.ApprovedHashPrefix = prefixHash(record.Hash)
				entry.DisplayApprovedHash, _ = display(entry.ApprovedHashPrefix)
				if record.Hash == hex.EncodeToString(candidate.Fingerprint[:]) {
					entry.Status = StatusApproved
				} else {
					entry.Status = StatusChanged
				}
				break
			}
			if !entry.NameSafe {
				entry.Reason = "name_unprintable"
			}
			if !entry.PathSafe {
				entry.Reason = "path_unprintable"
			}
			entries = append(entries, entry)
		}
		for _, diagnostic := range scan.Diagnostics {
			path, safe := display(diagnostic.Path)
			entry := Entry{Status: StatusUnsafe, Reason: diagnostic.Reason, DisplayPath: path, PathSafe: safe}
			if !safe {
				entry.Reason = "path_unprintable"
			}
			entries = append(entries, entry)
		}
	}
	diagnosticReasons := make(map[string]string, len(scan.Diagnostics))
	for _, d := range scan.Diagnostics {
		diagnosticReasons[filepath.Clean(filepath.FromSlash(d.Path))] = d.Reason
	}
	for i, record := range records {
		if matched[i] {
			continue
		}
		rel, relErr := filepath.Rel(root, record.Path)
		outside := relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
		displayPath, pathSafe := "", true
		if !outside {
			displayPath, pathSafe = display(rel)
		}
		reason := "not_scanned"
		if outside {
			reason = "outside_workdir"
		} else if diagnosticReason, ok := diagnosticReasons[filepath.Clean(rel)]; ok {
			reason = diagnosticReason
		} else if _, err := os.Stat(record.Path); os.IsNotExist(err) {
			reason = "descriptor_missing"
		}
		if !outside && !pathSafe {
			reason = "path_unprintable"
		}
		entry := Entry{Status: StatusChanged, Record: record, ApprovedHashPrefix: prefixHash(record.Hash), DisplayPath: displayPath, PathSafe: pathSafe, OutsideWorkdir: outside, Reason: reason}
		entry.Name, entry.NameSafe = display(record.Name)
		entry.DisplayHash, _ = display(prefixHash(record.Hash))
		entry.DisplayApprovedHash = entry.DisplayHash
		if !entry.NameSafe && entry.Reason == "not_scanned" {
			entry.Reason = "name_unprintable"
		}
		if entry.DisplayHash == "" && prefixHash(record.Hash) != "" && entry.Reason == "not_scanned" {
			entry.Reason = "hash_unprintable"
		}
		entries = append(entries, entry)
	}
	return entries
}
func prefixHash(hash string) string {
	if len(hash) < 12 {
		return ""
	}
	return hash[:12]
}
