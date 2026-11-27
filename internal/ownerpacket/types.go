// Package ownerpacket authenticates the private human-owner channel.
package ownerpacket

import (
	"bytes"
	"encoding/hex"
	"errors"
	"path"
	"strings"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
	"github.com/PHPCraftdream/ssjack/internal/sshstatus"
)

const (
	MaxWire      = 256 << 10
	MaxMessages  = 4096
	MaxApprovals = 32 // Mirrors vault.MaxApplicationApprovals.
	Lease        = 10 * time.Minute
)

var (
	ErrAuthentication = errors.New("owner channel authentication failed")
	ErrProtocol       = errors.New("invalid owner channel message")
	ErrExpired        = errors.New("owner channel expired")
	ErrUncertain      = errors.New("owner operation outcome unknown; inspect state before retrying")
	ErrReviewStale    = errors.New("reviewed application changed; re-open the approvals menu")
)

type DirectoryChange struct {
	Action   string   `json:"action"`
	ServerID string   `json:"server_id"`
	Account  string   `json:"account"`
	Fields   [][]byte `json:"fields"`
}
type SecretChange struct {
	Action            string `json:"action"`
	AliasID           string `json:"alias_id"`
	Name              string `json:"name"`
	ServerID          string `json:"server_id"`
	ObjectID          string `json:"object_id"`
	PreviousReference string `json:"previous_ref"`
	MediaType         string `json:"media_type"`
	Value             []byte `json:"value"`
}
type Export struct {
	Servers      map[string][]string    `json:"servers"`
	RemoteMCP    []mcpdirectory.Binding `json:"remote_mcp,omitempty"`
	Global       bool                   `json:"global"`
	Destination  string                 `json:"destination"`
	Confirmation string                 `json:"confirmation"`
}
type Link struct {
	Directory string `json:"directory"`
	Master    []byte `json:"master"`
}
type Inspect struct {
	Path     string `json:"path"`
	Password []byte `json:"password"`
}

type ApprovalChange struct {
	ApplicationName string `json:"application_name"`
	ApplicationPath string `json:"application_path,omitempty"`
	ReviewedHash    string `json:"reviewed_hash"`
	ReplacesHash    string `json:"replaces_hash,omitempty"`
}

// Command is a closed operation union; it cannot ask for a credential getter.
type Command struct {
	Operation string           `json:"operation"`
	Revision  *uint64          `json:"revision,omitempty"`
	Plan      uint64           `json:"plan,omitempty"`
	Directory *DirectoryChange `json:"directory,omitempty"`
	Secret    *SecretChange    `json:"secret,omitempty"`
	Export    *Export          `json:"export,omitempty"`
	Link      *Link            `json:"link,omitempty"`
	Inspect   *Inspect         `json:"inspect,omitempty"`
	Approval  *ApprovalChange  `json:"approval,omitempty"`
	Recovery  string           `json:"recovery,omitempty"`
	Rotation  *Rotation        `json:"rotation,omitempty"`
}

func (c *Command) Clear() {
	if c == nil {
		return
	}
	if c.Directory != nil {
		for _, field := range c.Directory.Fields {
			clear(field)
		}
	}
	if c.Secret != nil {
		clear(c.Secret.Value)
	}
	if c.Link != nil {
		clear(c.Link.Master)
	}
	if c.Inspect != nil {
		clear(c.Inspect.Password)
	}
}

type Account struct {
	Name, Profile, User, Authentication, Usage string
}
type ServerMetadata struct {
	ID, Name, Address string
	Fingerprints      []string
	Accounts          []Account
	Proxy             sshproxy.Metadata
}
type Binding struct{ Name, ServerID, Ref string }
type Store struct{ Directory, StoreID, PendingID, PendingPhase string }
type ApprovalRecord struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Hash string `json:"hash"`
}
type Metadata struct {
	Servers    []ServerMetadata
	Secrets    map[string]Binding
	OwnerStore *Store
	RemoteMCP  mcpdirectory.Metadata
	Approvals  []ApprovalRecord
}
type Status struct {
	Revision, SavedRevision                       uint64
	Saving, DatabaseFailed, Busy, Pending, Failed bool
	CipherDigest                                  [32]byte
	SSH                                           *sshstatus.Status `json:"ssh,omitempty"`
}
type Conflict struct{ Kind, Subject string }
type ImportSecret struct {
	AliasID, Name, ServerID, ServerName string
	Length                              int
}
type Preview struct {
	Encrypted bool
	Servers   []ServerMetadata
	Secrets   []ImportSecret
	RemoteMCP mcpdirectory.Metadata
	Conflicts []Conflict
}
type ImportStatus struct {
	PlanID           uint64
	Phase            string
	Preview          Preview
	Conflicts        []Conflict
	Published, Total int
	DirectoryApplied bool
	ErrorCode        string
}

// Reply contains metadata and persistence evidence only, never stored values.
type Reply struct {
	ErrorCode string            `json:"error"`
	Metadata  Metadata          `json:"metadata"`
	Status    Status            `json:"status"`
	Import    ImportStatus      `json:"import"`
	Rotation  *RotationMetadata `json:"rotation,omitempty"`
}

func (c Command) valid() bool {
	importDecision := c.Operation == "confirm-import" || (c.Operation == "recovery" && (c.Recovery == "resume-import" || c.Recovery == "abort-import"))
	if c.Operation == "rotation" {
		return c.Revision != nil && c.Plan == 0 && !importDecision && c.Directory == nil && c.Secret == nil && c.Export == nil && c.Link == nil && c.Inspect == nil && c.Approval == nil && c.Recovery == "" && validRotationCommand(c.Rotation)
	}
	if c.Rotation != nil || importDecision != (c.Plan != 0) {
		return false
	}
	bodies := 0
	for _, present := range []bool{c.Directory != nil, c.Secret != nil, c.Export != nil, c.Link != nil, c.Inspect != nil, c.Approval != nil, c.Recovery != ""} {
		if present {
			bodies++
		}
	}
	if c.Operation == "snapshot" || c.Operation == "flush" {
		return c.Revision == nil && bodies == 0
	}
	if c.Revision == nil {
		return false
	}
	switch c.Operation {
	case "approve_application":
		return bodies == 1 && c.Approval != nil && validApproval(c.Approval, true)
	case "revoke_application":
		return bodies == 1 && c.Approval != nil && validApproval(c.Approval, false)
	case "confirm-import":
		return bodies == 0
	case "directory":
		if bodies != 1 || c.Directory == nil {
			return false
		}
		counts := map[string]int{
			"add-server": 8, "rename-server": 1, "edit-server": 2, "add-account": 5, "edit-account": 5, "edit-proxy": 4,
			"add-mcp-server": 2, "edit-mcp-server": 3, "remove-mcp-server": 1,
			"add-mcp-account": 6, "edit-mcp-account": 6, "rename-mcp-account": 1, "remove-mcp-account": 1, "edit-mcp-header": 3,
		}
		count, ok := counts[c.Directory.Action]
		if !ok || len(c.Directory.Fields) != count || len(c.Directory.ServerID) > 32 || len(c.Directory.Account) > 64 {
			return false
		}
		for _, field := range c.Directory.Fields {
			if len(field) > 16384 {
				return false
			}
		}
		return true
	case "secret":
		if bodies != 1 || c.Secret == nil || len(c.Secret.Value) > 16384 {
			return false
		}
		return c.Secret.Action == "add" || c.Secret.Action == "update" || c.Secret.Action == "remove"
	case "export":
		if bodies != 1 || c.Export == nil || len(c.Export.Servers) > 64 || len(c.Export.RemoteMCP) > mcpdirectory.MaxAccounts || c.Export.Destination == "" || len(c.Export.Destination) > 4096 {
			return false
		}
		if c.Export.Confirmation != "" && c.Export.Confirmation != "EXPORT PLAINTEXT" {
			return false
		}
		accounts := 0
		for server, selected := range c.Export.Servers {
			if len(server) != 32 || len(selected) == 0 {
				return false
			}
			accounts += len(selected)
			for _, name := range selected {
				if len(name) == 0 || len(name) > 64 {
					return false
				}
			}
		}
		if accounts > 64 {
			return false
		}
		mcpAccounts, mcpServers, seen := map[string]bool{}, map[string]bool{}, map[string]bool{}
		for _, binding := range c.Export.RemoteMCP {
			serverID, serverErr := hex.DecodeString(binding.ServerID)
			accountID, accountErr := hex.DecodeString(binding.AccountID)
			if serverErr != nil || accountErr != nil || len(serverID) != 16 || len(accountID) != 16 || hex.EncodeToString(serverID) != binding.ServerID || hex.EncodeToString(accountID) != binding.AccountID || bytes.Equal(serverID, make([]byte, 16)) || bytes.Equal(accountID, make([]byte, 16)) || binding.ServerRevision == 0 || binding.AccountRevision == 0 || seen[binding.AccountID] {
				return false
			}
			seen[binding.AccountID], mcpServers[binding.ServerID] = true, true
			mcpAccounts[binding.AccountID] = true
		}
		if len(mcpServers) > mcpdirectory.MaxServers || (len(mcpAccounts) == 0 && accounts == 0 && !c.Export.Global) {
			return false
		}
		return len(mcpAccounts) <= 64
	case "link":
		return bodies == 1 && c.Link != nil && len(c.Link.Directory) > 0 && len(c.Link.Directory) <= 4096 && len(c.Link.Master) > 0 && len(c.Link.Master) <= 16384
	case "inspect-import":
		return bodies == 1 && c.Inspect != nil && len(c.Inspect.Path) > 0 && len(c.Inspect.Path) <= 4096 && len(c.Inspect.Password) <= 16384
	case "recovery":
		if bodies != 1 {
			return false
		}
		switch c.Recovery {
		case "retry-db", "reconcile", "resume-draft", "cancel-draft", "resume-import", "abort-import":
			return true
		}
	}
	return false
}

func (r Reply) valid() bool {
	if !validCode(r.ErrorCode) || !validCode(r.Import.ErrorCode) || !validRotationMetadata(r.Rotation) || len(r.Metadata.Servers) > 64 || len(r.Metadata.Secrets) > 128 || !validApprovalRecords(r.Metadata.Approvals) || len(r.Import.Preview.Servers) > 64 || len(r.Import.Preview.Secrets) > 128 || len(r.Import.Conflicts) > 512 || len(r.Import.Preview.Conflicts) > 512 {
		return false
	}
	switch r.Import.Phase {
	case "", "inspecting", "staged", "applying", "partial", "complete":
	default:
		return false
	}
	if r.Import.Published < 0 || r.Import.Total < 0 || r.Import.Total > 128 || r.Import.Published > r.Import.Total {
		return false
	}
	for _, servers := range [][]ServerMetadata{r.Metadata.Servers, r.Import.Preview.Servers} {
		accounts := 0
		for _, server := range servers {
			accounts += len(server.Accounts)
		}
		if accounts > 64 {
			return false
		}
	}
	for _, preview := range []mcpdirectory.Metadata{r.Metadata.RemoteMCP, r.Import.Preview.RemoteMCP} {
		if len(preview.Servers) > mcpdirectory.MaxServers || len(preview.Accounts) > mcpdirectory.MaxAccounts || len(preview.Last) > 64 {
			return false
		}
		for _, account := range preview.Accounts {
			if len(account.HeaderNames) > 4 {
				return false
			}
		}
		for _, selected := range preview.Last {
			if len(selected) > mcpdirectory.MaxSelections {
				return false
			}
		}
	}
	if r.Status.SavedRevision > r.Status.Revision {
		return false
	}
	if status := r.Status.SSH; status != nil {
		if len(status.Profile) > 64 || (status.AdoptedKnown && (!status.DeliveredKnown || status.AdoptedRevision > status.DeliveredRevision)) || (status.DeliveredKnown && (!status.DesiredKnown || status.DeliveredRevision > status.DesiredRevision)) {
			return false
		}
	}
	return true
}

func (c Command) Valid() bool { return c.valid() }

func (c ApprovalChange) Valid() bool {
	revision := uint64(0)
	return (Command{Operation: "approve_application", Revision: &revision, Approval: &c}).valid()
}

func validApprovalRecords(records []ApprovalRecord) bool {
	if len(records) > MaxApprovals {
		return false
	}
	seen := make(map[string]bool, len(records))
	for _, record := range records {
		if len(record.Name) == 0 || len(record.Name) > 32 || record.Name[0] < 'a' || record.Name[0] > 'z' || seen[record.Name] || len(record.Path) == 0 || len(record.Path) > 512 || len(record.Hash) != 64 {
			return false
		}
		seen[record.Name] = true
		for i := 1; i < len(record.Name); i++ {
			c := record.Name[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
		for i := 0; i < len(record.Path); i++ {
			if record.Path[i] < 0x20 || record.Path[i] == 0x7f {
				return false
			}
		}
		normalized := bytes.ReplaceAll([]byte(record.Path), []byte{'\\'}, []byte{'/'})
		cleaned := string(normalized)
		absolute := strings.HasPrefix(cleaned, "/") || len(cleaned) >= 3 && cleaned[1] == ':' && cleaned[2] == '/' && ((cleaned[0] >= 'A' && cleaned[0] <= 'Z') || (cleaned[0] >= 'a' && cleaned[0] <= 'z'))
		if !absolute || path.Clean(cleaned) != cleaned {
			return false
		}
		for i := 0; i < len(record.Hash); i++ {
			c := record.Hash[i]
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return true
}

func validApproval(change *ApprovalChange, approve bool) bool {
	if len(change.ApplicationName) == 0 || len(change.ApplicationName) > 64 {
		return false
	}
	// The all-zero digest is rejected to match the repository's existing digest rule (internal/vault/internal/core/ownerstore.go).
	hash := func(value string) bool {
		if len(value) != 64 {
			return false
		}
		decoded, err := hex.DecodeString(value)
		return err == nil && hex.EncodeToString(decoded) == value && !bytes.Equal(decoded, make([]byte, 32))
	}
	if !hash(change.ReviewedHash) {
		return false
	}
	if approve {
		return validApprovalPath(change.ApplicationPath) && (change.ReplacesHash == "" || hash(change.ReplacesHash))
	}
	return change.ApplicationPath == "" && hash(change.ReplacesHash)
}

func validApprovalPath(value string) bool {
	if len(value) == 0 || len(value) > 512 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] == 0x7f {
			return false
		}
	}
	normalized := bytes.ReplaceAll([]byte(value), []byte{'\\'}, []byte{'/'})
	cleaned := string(normalized)
	absolute := strings.HasPrefix(cleaned, "/") || len(cleaned) >= 3 && cleaned[1] == ':' && cleaned[2] == '/' && ((cleaned[0] >= 'A' && cleaned[0] <= 'Z') || (cleaned[0] >= 'a' && cleaned[0] <= 'z'))
	return absolute && path.Clean(cleaned) == cleaned
}

func (c DirectoryChange) Valid() bool {
	revision := uint64(0)
	return (Command{Operation: "directory", Revision: &revision, Directory: &c}).valid()
}
