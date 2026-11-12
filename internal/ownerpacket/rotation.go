package ownerpacket

import (
	"bytes"
	"encoding/hex"
	"strings"
)

// Rotation is a closed owner-confirmed request. PlanID and ID bind actions to
// this journal independently of import plans.
type Rotation struct {
	Action   string `json:"action"`
	ID       string `json:"id,omitempty"`
	PlanID   uint64 `json:"plan_id,omitempty"`
	ServerID string `json:"server_id,omitempty"`
	Account  string `json:"account,omitempty"`
}

type RotationMetadata struct {
	ID             string   `json:"id"`
	Phase          string   `json:"phase"`
	ServerID       string   `json:"server_id"`
	Account        string   `json:"account"`
	Profile        string   `json:"profile"`
	PlanID         uint64   `json:"plan_id"`
	BaseRevision   uint64   `json:"base_revision"`
	CommitRevision uint64   `json:"commit_revision"`
	Address        string   `json:"address,omitempty"`
	User           string   `json:"user,omitempty"`
	Usage          string   `json:"usage,omitempty"`
	CommitDigest   string   `json:"commit_digest"`
	RecoveryPath   string   `json:"recovery_path,omitempty"`
	RecoveryDigest string   `json:"recovery_digest,omitempty"`
	OldPublic      []byte   `json:"old_public,omitempty"`
	NewPublic      []byte   `json:"new_public,omitempty"`
	HostKeys       []string `json:"host_keys,omitempty"`
}

func validCode(code string) bool {
	switch code {
	case "", "invalid", "busy", "stale", "unsupported", "authentication", "archive", "uncertain", "rotation-uncertain", "operation", "pending":
		return true
	default:
		return false
	}
}

func validRotationCommand(rotation *Rotation) bool {
	if rotation == nil || len(rotation.ID) > 32 || len(rotation.ServerID) > 32 || len(rotation.Account) > 64 {
		return false
	}
	switch rotation.Action {
	case "prepare":
		id, err := hex.DecodeString(rotation.ServerID)
		return err == nil && rotation.ID == "" && rotation.PlanID == 0 && len(id) == 16 && hex.EncodeToString(id) == rotation.ServerID && !bytes.Equal(id, make([]byte, 16)) && rotation.Account != "" && len(rotation.Account) <= 64
	case "install", "verify", "commit", "cancel", "recover", "archive":
		if rotation.ServerID != "" || rotation.Account != "" || len(rotation.ID) != 32 || rotation.PlanID == 0 {
			return false
		}
		id, err := hex.DecodeString(rotation.ID)
		return err == nil && hex.EncodeToString(id) == rotation.ID && !bytes.Equal(id, make([]byte, 16))
	default:
		return false
	}
}

func validRotationMetadata(rotation *RotationMetadata) bool {
	if rotation == nil {
		return true
	}
	if len(rotation.ID) != 32 || len(rotation.Phase) > 16 || len(rotation.ServerID) != 32 || len(rotation.Account) > 64 || len(rotation.Profile) > 64 || len(rotation.Address) > 4096 || len(rotation.User) > 256 || len(rotation.Usage) > 64 || len(rotation.CommitDigest) > 64 || len(rotation.RecoveryPath) > 4096 || len(rotation.RecoveryDigest) > 64 || len(rotation.OldPublic) > 16384 || len(rotation.NewPublic) > 16384 || len(rotation.HostKeys) > 16 || rotation.PlanID == 0 || rotation.CommitRevision != 0 && rotation.CommitDigest == "" {
		return false
	}
	id, err := hex.DecodeString(rotation.ID)
	if err != nil || hex.EncodeToString(id) != rotation.ID || bytes.Equal(id, make([]byte, 16)) {
		return false
	}
	server, err := hex.DecodeString(rotation.ServerID)
	if err != nil || len(server) != 16 || hex.EncodeToString(server) != rotation.ServerID || bytes.Equal(server, make([]byte, 16)) {
		return false
	}
	for _, hostKey := range rotation.HostKeys {
		if len(hostKey) == 0 || len(hostKey) > 16384 {
			return false
		}
	}
	switch rotation.Phase {
	case "prepared", "attempting", "unknown", "added", "verified", "committed":
		return rotation.RecoveryPath == "" && rotation.RecoveryDigest == "" && rotation.Account != "" && rotation.Profile != "" && len(rotation.OldPublic) > 0 && len(rotation.NewPublic) > 0 && rotation.CommitRevision == 0 && rotation.CommitDigest == ""
	case "complete":
		if rotation.RecoveryPath != "" || rotation.RecoveryDigest != "" || rotation.Account == "" || rotation.Profile == "" || len(rotation.OldPublic) == 0 || len(rotation.NewPublic) == 0 || len(rotation.CommitDigest) != 64 {
			return false
		}
		proof, err := hex.DecodeString(rotation.CommitDigest)
		return err == nil && len(proof) == 32 && !bytes.Equal(proof, make([]byte, 32)) && hex.EncodeToString(proof) == rotation.CommitDigest
	case "cancelled":
		return rotation.RecoveryPath == "" && rotation.RecoveryDigest == "" && rotation.Account != "" && rotation.Profile != "" && rotation.Address == "" && rotation.User == "" && rotation.Usage == "" && len(rotation.HostKeys) == 0 && (len(rotation.OldPublic) == 0 && len(rotation.NewPublic) == 0 || len(rotation.OldPublic) > 0 && len(rotation.NewPublic) > 0) && rotation.CommitRevision == 0 && rotation.CommitDigest == ""
	case "archived":
		if rotation.Account == "" || rotation.Profile == "" || rotation.Address != "" || rotation.User != "" || rotation.Usage != "" || len(rotation.OldPublic) != 0 || len(rotation.NewPublic) != 0 || len(rotation.HostKeys) != 0 || rotation.RecoveryPath == "" || strings.ContainsAny(rotation.RecoveryPath, "\x00\r\n\x1b") || len(rotation.RecoveryDigest) != 64 || len(rotation.CommitDigest) != 64 {
			return false
		}
		commit, commitErr := hex.DecodeString(rotation.CommitDigest)
		recovery, recoveryErr := hex.DecodeString(rotation.RecoveryDigest)
		return commitErr == nil && len(commit) == 32 && !bytes.Equal(commit, make([]byte, 32)) && hex.EncodeToString(commit) == rotation.CommitDigest && recoveryErr == nil && len(recovery) == 32 && !bytes.Equal(recovery, make([]byte, 32)) && hex.EncodeToString(recovery) == rotation.RecoveryDigest && len(rotation.RecoveryPath) <= 4096
	default:
		return false
	}
}
