package discover

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/PHPCraftdream/ssjack/internal/application"
	"github.com/PHPCraftdream/ssjack/internal/application/discovery"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

// Status is one post-unlock owner-facing status line for one validated name.
type Status struct {
	Kind string
	Name string
	Path string
}

// Approved registers approved discovered applications after validating conflicts.
func Approved(result discovery.Result, approvals []vault.Approval, explicit []application.App) ([]application.App, []Status, error) {
	if result.Overflow {
		return nil, []Status{{Kind: "overflow"}}, nil
	}
	records := make(map[string]vault.Approval, len(approvals))
	for _, record := range approvals {
		records[record.Name] = record
	}
	statuses := make([]Status, 0, len(result.Candidates)+len(approvals))
	type approvedCandidate struct {
		app       application.App
		candidate discovery.Candidate
	}
	tentative := make([]approvedCandidate, 0, len(result.Candidates))
	matched := make(map[string]bool, len(result.Candidates))
	for _, candidate := range result.Candidates {
		record, ok := records[candidate.Name]
		if ok {
			matched[candidate.Name] = true
		}
		if !ok {
			continue
		}
		if record.Path != candidate.CanonicalPath || record.Hash != hex.EncodeToString(candidate.Fingerprint[:]) {
			statuses = append(statuses, Status{Kind: "changed", Name: candidate.Name})
			continue
		}
		current, err := os.Lstat(candidate.CanonicalPath)
		if err != nil || !current.IsDir() || !os.SameFile(candidate.Identity, current) {
			statuses = append(statuses, Status{Kind: "changed", Name: candidate.Name})
			continue
		}
		app, err := application.ParseDescriptorBuffer(candidate.Buffer, candidate.CanonicalPath)
		if err != nil {
			statuses = append(statuses, Status{Kind: "changed", Name: candidate.Name})
			continue
		}
		tentative = append(tentative, approvedCandidate{app: app, candidate: candidate})
	}
	for _, record := range approvals {
		if !matched[record.Name] {
			statuses = append(statuses, Status{Kind: "absent", Name: record.Name})
		}
	}

	nameCounts := make(map[string]int, len(tentative))
	for _, item := range tentative {
		nameCounts[item.app.Name]++
	}
	collisionStatuses := make([]Status, 0)
	collided := make(map[string]bool)
	for _, item := range tentative {
		if nameCounts[item.app.Name] > 1 {
			collisionStatuses = append(collisionStatuses, Status{Kind: "collision_refused", Name: item.app.Name})
			collided[item.app.Name] = true
		}
	}
	statuses = append(statuses, collisionStatuses...)

	combined := append([]application.App(nil), explicit...)
	seenDirs := make(map[string]string, len(explicit)+len(tentative))
	seenNames := make(map[string]string, len(explicit)+len(tentative))
	for _, app := range explicit {
		dir := filepath.Clean(app.Directory)
		if previous, ok := seenNames[app.Name]; ok && previous != dir {
			return nil, nil, fmt.Errorf("application name '%s' is enabled from more than one directory", app.Name)
		}
		if previous, ok := seenDirs[dir]; ok && previous != app.Name {
			return nil, nil, fmt.Errorf("application directory enabled under more than one name")
		}
		seenDirs[dir], seenNames[app.Name] = app.Name, dir
	}
	registered := make([]application.App, 0, len(tentative))
	pendingEnabled := make([]Status, 0, len(tentative))
	for _, item := range tentative {
		app, candidate := item.app, item.candidate
		if collided[app.Name] {
			continue
		}
		dir := filepath.Clean(app.Directory)
		if previous, ok := seenNames[app.Name]; ok && previous != dir {
			statuses = append(statuses, Status{Kind: "collision_refused", Name: app.Name})
			continue
		}
		if previous, ok := seenDirs[dir]; ok {
			if previous != app.Name {
				statuses = append(statuses, Status{Kind: "collision_refused", Name: app.Name})
				continue
			}
			pendingEnabled = append(pendingEnabled, Status{Kind: "enabled", Name: candidate.Name, Path: displayPath(candidate.Path)})
			continue
		}
		seenDirs[dir], seenNames[app.Name] = app.Name, dir
		combined = append(combined, app)
		registered = append(registered, app)
		pendingEnabled = append(pendingEnabled, Status{Kind: "enabled", Name: candidate.Name, Path: displayPath(candidate.Path)})
	}
	if len(combined) > application.MaxApplications {
		return nil, append(statuses, Status{Kind: "cap_overflow_refused"}), nil
	}
	statuses = append(statuses, pendingEnabled...)
	return registered, statuses, nil
}
