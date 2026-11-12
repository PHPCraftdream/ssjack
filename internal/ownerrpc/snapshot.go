// Package ownerrpc composes the private owner channel; it is not an MCP API.
package ownerrpc

import (
	"context"
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownerrotation"
	"github.com/PHPCraftdream/ssjack/internal/sshstatus"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

// Execute returns one authenticated atomic snapshot and a fixed operation error.
func (c *Client) Execute(ctx context.Context, command ownerpacket.Command) (ownerdb.Snapshot, error) {
	reply, err := c.Call(ctx, command)
	if err != nil {
		return ownerdb.Snapshot{}, err
	}
	return decodeSnapshot(reply)
}

var errOperation = errors.New("owner operation failed; inspect state before retrying")
var errDatabase = errors.New("owner database persistence failed")

func errorCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, vault.ErrOwnerRevision):
		return "stale"
	case errors.Is(err, ownerdb.ErrPending):
		return "pending"
	case errors.Is(err, ownerpacket.ErrUncertain):
		return "uncertain"
	case errors.Is(err, ownerrotation.ErrUncertain):
		return "rotation-uncertain"
	case errors.Is(err, ownerpacket.ErrAuthentication), errors.Is(err, ownerpacket.ErrExpired):
		return "authentication"
	case errors.Is(err, ownerpacket.ErrProtocol):
		return "invalid"
	default:
		return "operation"
	}
}

func codeError(code string) error {
	switch code {
	case "":
		return nil
	case "stale":
		return vault.ErrOwnerRevision
	case "pending", "busy":
		return ownerdb.ErrPending
	case "uncertain":
		return ownerpacket.ErrUncertain
	case "rotation-uncertain":
		return ownerrotation.ErrUncertain
	case "authentication":
		return ownerpacket.ErrAuthentication
	case "invalid":
		return ownerpacket.ErrProtocol
	case "operation", "archive", "unsupported":
		return errOperation
	default:
		return ownerpacket.ErrProtocol
	}
}

func cloneMCP(m mcpdirectory.Metadata) mcpdirectory.Metadata {
	out := mcpdirectory.Metadata{}
	if m.Servers != nil {
		out.Servers = append([]mcpdirectory.ServerMetadata{}, m.Servers...)
	}
	if m.Accounts != nil {
		out.Accounts = append([]mcpdirectory.AccountMetadata{}, m.Accounts...)
		for i := range out.Accounts {
			if m.Accounts[i].HeaderNames != nil {
				out.Accounts[i].HeaderNames = append([]string{}, m.Accounts[i].HeaderNames...)
			}
		}
	}
	if m.Last != nil {
		out.Last = make(map[string][]mcpdirectory.Binding, len(m.Last))
		for id, selected := range m.Last {
			if selected == nil {
				out.Last[id] = nil
			} else {
				out.Last[id] = append([]mcpdirectory.Binding{}, selected...)
			}
		}
	}
	return out
}

func cloneSSH(status *sshstatus.Status) *sshstatus.Status {
	if status == nil {
		return nil
	}
	cloned := *status
	return &cloned
}

func encodeRotation(info vault.RotationInfo) *ownerpacket.RotationMetadata {
	return &ownerpacket.RotationMetadata{
		ID: info.ID, Phase: info.Phase, ServerID: info.ServerID, Account: info.Account,
		Profile: info.Profile, PlanID: info.PlanID, BaseRevision: info.BaseRevision,
		CommitRevision: info.CommitRevision, Address: info.Address, User: info.User,
		Usage: info.Usage, CommitDigest: info.CommitDigest,
		RecoveryPath: info.RecoveryPath, RecoveryDigest: info.RecoveryDigest,
		OldPublic: append([]byte(nil), info.OldPublic...), NewPublic: append([]byte(nil), info.NewPublic...),
		HostKeys: cloneStrings(info.HostKeys),
	}
}

func decodeRotation(info ownerpacket.RotationMetadata) vault.RotationInfo {
	return vault.RotationInfo{
		ID: info.ID, Phase: info.Phase, ServerID: info.ServerID, Account: info.Account,
		Profile: info.Profile, PlanID: info.PlanID, BaseRevision: info.BaseRevision,
		CommitRevision: info.CommitRevision, Address: info.Address, User: info.User,
		Usage: info.Usage, CommitDigest: info.CommitDigest,
		RecoveryPath: info.RecoveryPath, RecoveryDigest: info.RecoveryDigest,
		OldPublic: append([]byte(nil), info.OldPublic...), NewPublic: append([]byte(nil), info.NewPublic...),
		HostKeys: cloneStrings(info.HostKeys),
	}
}

// SnapshotReply copies caller-owned metadata into a closed reply, never a getter.
func SnapshotReply(s ownerdb.Snapshot, err error) ownerpacket.Reply { return encodeSnapshot(s, err) }

func encodeSnapshot(s ownerdb.Snapshot, err error) ownerpacket.Reply {
	r := ownerpacket.Reply{ErrorCode: errorCode(err)}
	r.Status = ownerpacket.Status{
		Revision: s.Status.Database.Revision, SavedRevision: s.Status.Database.SavedRevision,
		Saving: s.Status.Database.Pending, DatabaseFailed: s.Status.Database.Err != nil,
		Busy: s.Status.Busy, Pending: s.Status.Pending, Failed: s.Status.Err != nil, CipherDigest: s.CipherDigest,
		SSH: cloneSSH(s.Status.Database.SSH),
	}
	r.Metadata.RemoteMCP = cloneMCP(s.Directory.RemoteMCP)
	if s.Directory.Secrets != nil {
		r.Metadata.Secrets = make(map[string]ownerpacket.Binding, len(s.Directory.Secrets))
		for id, binding := range s.Directory.Secrets {
			r.Metadata.Secrets[id] = ownerpacket.Binding(binding)
		}
	}
	if s.Directory.OwnerStore != nil {
		store := ownerpacket.Store(*s.Directory.OwnerStore)
		r.Metadata.OwnerStore = &store
	}
	if s.Directory.Servers != nil {
		r.Metadata.Servers = make([]ownerpacket.ServerMetadata, 0, len(s.Directory.Servers))
	}
	for _, server := range s.Directory.Servers {
		out := ownerpacket.ServerMetadata{ID: server.ID, Name: server.Name, Address: server.Address, Proxy: server.Proxy, Fingerprints: cloneStrings(server.Fingerprints)}
		if server.Accounts != nil {
			out.Accounts = make([]ownerpacket.Account, 0, len(server.Accounts))
		}
		for _, account := range server.Accounts {
			out.Accounts = append(out.Accounts, ownerpacket.Account(account))
		}
		r.Metadata.Servers = append(r.Metadata.Servers, out)
	}
	r.Import = encodeImport(s.Import)
	if s.Rotation != nil {
		r.Rotation = encodeRotation(*s.Rotation)
	}
	return r
}

func decodeSnapshot(r ownerpacket.Reply) (ownerdb.Snapshot, error) {
	s := ownerdb.Snapshot{CipherDigest: r.Status.CipherDigest}
	s.Status = ownerdb.Status{Database: vault.SessionStatus{Revision: r.Status.Revision, SavedRevision: r.Status.SavedRevision, Pending: r.Status.Saving, SSH: cloneSSH(r.Status.SSH)}, Busy: r.Status.Busy, Pending: r.Status.Pending}
	if r.Status.DatabaseFailed {
		s.Status.Database.Err = errDatabase
	}
	if r.Status.Failed {
		s.Status.Err = errOperation
	}
	s.Directory.RemoteMCP = cloneMCP(r.Metadata.RemoteMCP)
	if r.Metadata.Secrets != nil {
		s.Directory.Secrets = make(map[string]vault.SecretBinding, len(r.Metadata.Secrets))
		for id, binding := range r.Metadata.Secrets {
			s.Directory.Secrets[id] = vault.SecretBinding(binding)
		}
	}
	if r.Metadata.OwnerStore != nil {
		store := vault.OwnerStoreMetadata(*r.Metadata.OwnerStore)
		s.Directory.OwnerStore = &store
	}
	if r.Metadata.Servers != nil {
		s.Directory.Servers = make([]vault.ServerMetadata, 0, len(r.Metadata.Servers))
	}
	for _, server := range r.Metadata.Servers {
		out := vault.ServerMetadata{ID: server.ID, Name: server.Name, Address: server.Address, Proxy: server.Proxy, Fingerprints: cloneStrings(server.Fingerprints)}
		if server.Accounts != nil {
			out.Accounts = make([]vault.AccountMetadata, 0, len(server.Accounts))
		}
		for _, account := range server.Accounts {
			out.Accounts = append(out.Accounts, vault.AccountMetadata(account))
		}
		s.Directory.Servers = append(s.Directory.Servers, out)
	}
	s.Import = decodeImport(r.Import)
	if r.Rotation != nil {
		rotation := decodeRotation(*r.Rotation)
		s.Rotation = &rotation
	}
	return s, codeError(r.ErrorCode)
}

func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	return append([]string{}, in...)
}
