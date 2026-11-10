// Package ownerpacket authenticates the private human-owner channel.
package ownerpacket

import (
	"bytes"
	"encoding/hex"
	"errors"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
	"github.com/PHPCraftdream/ssjack/internal/sshstatus"
)

const (
	MaxWire     = 256 << 10
	MaxMessages = 4096
	Lease       = 10 * time.Minute
)

var (
	ErrAuthentication = errors.New("owner channel authentication failed")
	ErrProtocol       = errors.New("invalid owner channel message")
	ErrExpired        = errors.New("owner channel expired")
	ErrUncertain      = errors.New("owner operation outcome unknown; inspect state before retrying")
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
	Recovery  string           `json:"recovery,omitempty"`
}

func (c *Command) Clear() {
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
type Metadata struct {
	Servers    []ServerMetadata
	Secrets    map[string]Binding
	OwnerStore *Store
	RemoteMCP  mcpdirectory.Metadata
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
	ErrorCode string       `json:"error"`
	Metadata  Metadata     `json:"metadata"`
	Status    Status       `json:"status"`
	Import    ImportStatus `json:"import"`
}

func (c Command) valid() bool {
	importDecision := c.Operation == "confirm-import" || (c.Operation == "recovery" && (c.Recovery == "resume-import" || c.Recovery == "abort-import"))
	if importDecision != (c.Plan != 0) {
		return false
	}
	bodies := 0
	for _, present := range []bool{c.Directory != nil, c.Secret != nil, c.Export != nil, c.Link != nil, c.Inspect != nil, c.Recovery != ""} {
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

func validCode(code string) bool {
	switch code {
	case "", "invalid", "busy", "stale", "unsupported", "authentication", "archive", "uncertain", "operation", "pending":
		return true
	}
	return false
}

func (r Reply) valid() bool {
	if !validCode(r.ErrorCode) || !validCode(r.Import.ErrorCode) || len(r.Metadata.Servers) > 64 || len(r.Metadata.Secrets) > 128 || len(r.Import.Preview.Servers) > 64 || len(r.Import.Preview.Secrets) > 128 || len(r.Import.Conflicts) > 512 || len(r.Import.Preview.Conflicts) > 512 {
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
	if status := r.Status.SSH; status != nil {
		if len(status.Profile) > 64 || (status.AdoptedKnown && (!status.DeliveredKnown || status.AdoptedRevision > status.DeliveredRevision)) || (status.DeliveredKnown && (!status.DesiredKnown || status.DeliveredRevision > status.DesiredRevision)) {
			return false
		}
	}
	return r.Status.SavedRevision <= r.Status.Revision
}

func (c Command) Valid() bool { return c.valid() }

func (c DirectoryChange) Valid() bool {
	revision := uint64(0)
	return (Command{Operation: "directory", Revision: &revision, Directory: &c}).valid()
}
