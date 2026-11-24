// Package vault is the public API of the encrypted credential database. The
// implementation lives in internal packages so secret-bearing types and their
// state are reachable only through this surface.
package vault

import (
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/approval"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/core"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/record"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/recovery"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/session"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/store"
)

type (
	Target          = record.Target
	SSHPolicy       = record.SSHPolicy
	Approval        = approval.Record
	Server          = record.Server
	SecretBinding   = record.SecretBinding
	Vault           = core.Vault
	OwnerStore      = core.OwnerStore
	OwnerIntent     = core.OwnerIntent
	OwnerChange     = core.OwnerChange
	RotationJournal = core.RotationJournal
	RestorePlan     = recovery.RestorePlan
	UpgradePlan     = recovery.UpgradePlan

	Session            = session.Session
	SessionStatus      = session.SessionStatus
	RotationInfo       = session.RotationInfo
	AccountMetadata    = session.AccountMetadata
	ServerMetadata     = session.ServerMetadata
	OwnerStoreMetadata = session.OwnerStoreMetadata
	DirectoryMetadata  = session.DirectoryMetadata
	ExportSelection    = session.ExportSelection
	OwnerExportPlan    = session.OwnerExportPlan
	ImportAccount      = session.ImportAccount
	ImportServer       = session.ImportServer
	ImportSecret       = session.ImportSecret
	ImportPreview      = session.ImportPreview
	OwnerImport        = session.OwnerImport
	ImportConflict     = session.ImportConflict
	OwnerUnlock        = session.OwnerUnlock
)

var (
	ErrWriterRole     = store.ErrWriterRole
	ErrOwnerRevision  = session.ErrOwnerRevision
	ErrImportInvalid  = session.ErrImportInvalid
	ErrImportConflict = session.ErrImportConflict
	ErrImportChanged  = session.ErrImportChanged
)

const (
	ConflictServerID         = session.ConflictServerID
	ConflictServerName       = session.ConflictServerName
	ConflictAccountID        = session.ConflictAccountID
	ConflictSecretID         = session.ConflictSecretID
	ConflictSecretName       = session.ConflictSecretName
	ConflictServerLimit      = session.ConflictServerLimit
	ConflictAccountLimit     = session.ConflictAccountLimit
	ConflictSecretLimit      = session.ConflictSecretLimit
	ConflictPendingIntent    = session.ConflictPendingIntent
	ConflictDirectoryVersion = session.ConflictDirectoryVersion
	ConflictUnlinkedStore    = session.ConflictUnlinkedStore
	ConflictValueUnsupported = session.ConflictValueUnsupported
	ConflictMCPServerID      = session.ConflictMCPServerID
	ConflictMCPServerName    = session.ConflictMCPServerName
	ConflictMCPServerURL     = session.ConflictMCPServerURL
	ConflictMCPServerLimit   = session.ConflictMCPServerLimit
	ConflictMCPAccountID     = session.ConflictMCPAccountID
	ConflictMCPAccountName   = session.ConflictMCPAccountName
	ConflictMCPAccountLimit  = session.ConflictMCPAccountLimit
	ConflictMCPLast          = session.ConflictMCPLast
	ConflictMCPLastLimit     = session.ConflictMCPLastLimit
)

const (
	RotationPrepared   = core.RotationPrepared
	RotationAttempting = core.RotationAttempting
	RotationUnknown    = core.RotationUnknown
	RotationAdded      = core.RotationAdded
	RotationVerified   = core.RotationVerified
	RotationCommitted  = core.RotationCommitted
	RotationComplete   = core.RotationComplete
	RotationCancelled  = core.RotationCancelled
	RotationArchived   = core.RotationArchived
)
