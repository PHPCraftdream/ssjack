package ownerrpc

import (
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func encodeConflicts(in []vault.ImportConflict) []ownerpacket.Conflict {
	if in == nil {
		return nil
	}
	out := make([]ownerpacket.Conflict, 0, len(in))
	for _, conflict := range in {
		out = append(out, ownerpacket.Conflict(conflict))
	}
	return out
}

func decodeConflicts(in []ownerpacket.Conflict) []vault.ImportConflict {
	if in == nil {
		return nil
	}
	out := make([]vault.ImportConflict, 0, len(in))
	for _, conflict := range in {
		out = append(out, vault.ImportConflict(conflict))
	}
	return out
}

func encodeImport(in ownerdb.ImportStatus) ownerpacket.ImportStatus {
	out := ownerpacket.ImportStatus{
		Phase: string(in.Phase), PlanID: in.PlanID, Conflicts: encodeConflicts(in.Conflicts), Published: in.Published,
		Total: in.Total, DirectoryApplied: in.DirectoryApplied, ErrorCode: errorCode(in.Err),
	}
	out.Preview.Encrypted, out.Preview.Conflicts = in.Preview.Encrypted, encodeConflicts(in.Preview.Conflicts)
	out.Preview.RemoteMCP = cloneMCP(in.Preview.RemoteMCP)
	if in.Preview.Servers != nil {
		out.Preview.Servers = make([]ownerpacket.ServerMetadata, 0, len(in.Preview.Servers))
	}
	for _, server := range in.Preview.Servers {
		s := ownerpacket.ServerMetadata{ID: server.ID, Name: server.Name, Address: server.Address, Proxy: server.Proxy, Fingerprints: cloneStrings(server.Fingerprints)}
		if server.Accounts != nil {
			s.Accounts = make([]ownerpacket.Account, 0, len(server.Accounts))
		}
		for _, account := range server.Accounts {
			s.Accounts = append(s.Accounts, ownerpacket.Account{Name: account.Name, User: account.User, Authentication: account.Authentication, Usage: account.Usage})
		}
		out.Preview.Servers = append(out.Preview.Servers, s)
	}
	if in.Preview.Secrets != nil {
		out.Preview.Secrets = make([]ownerpacket.ImportSecret, 0, len(in.Preview.Secrets))
	}
	for _, secret := range in.Preview.Secrets {
		out.Preview.Secrets = append(out.Preview.Secrets, ownerpacket.ImportSecret(secret))
	}
	return out
}

func decodeImport(in ownerpacket.ImportStatus) ownerdb.ImportStatus {
	out := ownerdb.ImportStatus{
		Phase: ownerdb.ImportPhase(in.Phase), PlanID: in.PlanID, Conflicts: decodeConflicts(in.Conflicts), Published: in.Published,
		Total: in.Total, DirectoryApplied: in.DirectoryApplied, Err: codeError(in.ErrorCode),
	}
	out.Preview.Encrypted, out.Preview.Conflicts = in.Preview.Encrypted, decodeConflicts(in.Preview.Conflicts)
	out.Preview.RemoteMCP = cloneMCP(in.Preview.RemoteMCP)
	if in.Preview.Servers != nil {
		out.Preview.Servers = make([]vault.ImportServer, 0, len(in.Preview.Servers))
	}
	for _, server := range in.Preview.Servers {
		s := vault.ImportServer{ID: server.ID, Name: server.Name, Address: server.Address, Proxy: server.Proxy, Fingerprints: cloneStrings(server.Fingerprints)}
		if server.Accounts != nil {
			s.Accounts = make([]vault.ImportAccount, 0, len(server.Accounts))
		}
		for _, account := range server.Accounts {
			s.Accounts = append(s.Accounts, vault.ImportAccount{Name: account.Name, User: account.User, Authentication: account.Authentication, Usage: account.Usage})
		}
		out.Preview.Servers = append(out.Preview.Servers, s)
	}
	if in.Preview.Secrets != nil {
		out.Preview.Secrets = make([]vault.ImportSecret, 0, len(in.Preview.Secrets))
	}
	for _, secret := range in.Preview.Secrets {
		out.Preview.Secrets = append(out.Preview.Secrets, vault.ImportSecret(secret))
	}
	return out
}
