package main

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

type commandHelp struct {
	Name     string
	Usage    string
	Summary  string
	Details  string
	Examples []string
}

var commands = []commandHelp{
	{"appstore", "ssjack appstore setup DIR | put DIR | inspect DIR | unlock HARNESS [ARGS...]", "Store encrypted application secrets and issue exact references.", "setup installs a locally encrypted binding using preprovisioned anchor details; it never enrolls or contacts the service. The store and writer role/genesis must already be provisioned. put is first-entry only and emits the exact reference plus safe sequence and journal revision. inspect reports trusted anchor state; unlock verifies a separate root-installed finite delivery grant, confirms the canonical reference, prompts for the hidden master secret, then launches the fixed synthetic consumer.", []string{"ssjack appstore setup ~/.local/share/ssjack/appstore", "ssjack appstore put ~/.local/share/ssjack/appstore", "ssjack appstore inspect ~/.local/share/ssjack/appstore", "ssjack appstore unlock claude -c"}},
	{"declarative", "ssjack declarative setup | register | revoke | register-delivery | revoke-delivery | run HARNESS [ARGUMENTS...]", "Manage or run the restricted Linux synthetic metadata slice.", "Linux/amd64 only. setup/register/revoke and delivery grant changes require root and independent interactive scope confirmation outside a model session. register-delivery installs a separate finite secret-delivery grant; it is not the metadata grant. run exposes only resource_plan and plan_apply for synthetic cache metadata and never releases secrets or hydrates placeholders into native application configuration. appstore unlock follows a separate confidential delivery route through the fixed native consumer. Model tools expose no arbitrary executable, path, or network access. A receipt is not adoption; adoption status is unknown and there is no safe retry after an uncertain receipt. Public acceptance is authored, not execution evidence.", []string{"ssjack declarative setup", "ssjack declarative register", "ssjack declarative register-delivery", "ssjack declarative revoke-delivery", "ssjack declarative run claude -c"}},
	{"declarative register-delivery", "ssjack declarative register-delivery", "Install a finite root-approved synthetic delivery grant.", "Requires trusted interactive confirmation and independently verified reference, store identity, installation/snapshot digests, fixed driver and consumer, recipient UID, and expiry. A prior metadata grant cannot release secrets.", []string{"ssjack declarative register-delivery"}},
	{"declarative revoke-delivery", "ssjack declarative revoke-delivery", "Revoke a synthetic delivery grant by exact reference.", "Requires root and explicit reference and revocation confirmation outside a model session.", []string{"ssjack declarative revoke-delivery"}},
	{"appstore setup", "ssjack appstore setup DIR", "Create an encrypted application-store installation.", "Requires a protected existing directory and independently reconfirmed HTTPS endpoint, certificate material, and signing key. Private keys are entered as hidden DER base64, never read from a credential file. Setup does not enroll or contact a service.", []string{"ssjack appstore setup ~/.local/share/ssjack/appstore"}},
	{"appstore put", "ssjack appstore put DIR", "Write the first hidden secret and print its exact reference.", "First-entry only: authenticates the installation and confirms the authoritative store is empty before the hidden secret prompt. A second authoritative check prevents overwriting data committed after the prompt. Emits the exact placeholder plus safe sequence and journal revision; does not replay or release stored credentials.", []string{"ssjack appstore put ~/.local/share/ssjack/appstore"}},

	{"appstore inspect", "ssjack appstore inspect DIR", "Inspect trusted application-store anchor state.", "Non-root trusted terminal only; prompts for the hidden installation master secret. Does not deliver a secret.", []string{"ssjack appstore inspect ~/.local/share/ssjack/appstore"}},
	{"appstore unlock", "ssjack appstore unlock HARNESS [ARGS...]", "Unlock one explicitly granted synthetic secret for the fixed consumer.", "Non-root trusted terminal only. Confirms the canonical reference, requires a separate active root-installed finite delivery grant, checks the independently registered store/installation binding, and prompts without echo for the master secret. Receipts do not prove application adoption; outcome may be unknown and must not be blindly retried. No arbitrary executable, path, or network access is exposed to model tools.", []string{"ssjack appstore unlock claude -c"}},
	{"ssh", "ssjack [--vault FILE] [-p PROFILE] ssh", "Open an interactive SSH session with named credentials.", "Requests the vault secret, verifies the stored server pins, then opens a PTY. No external SSH executable or agent is used. Human usage must be permitted by the record.", []string{"ssjack ssh", "ssjack --vault .ssh/work.ssjack.ktav -p work ssh"}},
	{"run", "ssjack [options] run HARNESS [ARGUMENTS...]", "Launch a coding harness with access to one credential record.", "Requests the vault secret once. The MCP bridge receives a single-use capability, not the private key or vault secret. Everything after HARNESS belongs to that program, including --help. Agent usage must be permitted by the record.", []string{"ssjack run claude -c", "ssjack -p work --bootstrap-timeout 5m run claude -c"}},
	{"list", "ssjack [--vault FILE] list", "List credential names without exposing private keys.", "Requires interactive vault authorization. Labels are printed in sorted order.", []string{"ssjack list"}},
	{"show", "ssjack [--vault FILE] [-p PROFILE] show", "Show connection metadata, usage, and server fingerprints.", "Intentionally displays decrypted metadata, never private key bytes. Consider terminal recording and redirected output.", []string{"ssjack show"}},
	{"add", "ssjack [--vault FILE] [-p PROFILE] add [--generate-key]", "Create a named credential record interactively.", "Prompts for address, SSH user, verified server public key, and intended usage. By default imports a key file. --generate-key derives Ed25519 locally from the unlocked heavy-profile master and fresh parameters, saves private bytes only in the vault, then prints the public key and a restrict,pty installation command. No remote account or standalone key file is created.", []string{"ssjack add", "ssjack -p work add --generate-key"}},
	{"edit", "ssjack [--vault FILE] [-p PROFILE] edit", "Edit a record without a plaintext editor or temporary file.", "Hidden field input; Enter keeps the current value. Key and pin replacement are explicit. An invalid edit does not commit the record.", []string{"ssjack edit"}},
	{"remove", "ssjack [--vault FILE] [-p PROFILE] remove", "Remove a credential record after confirmation.", "Requires the vault secret and typing the record name. Backups and remote authorized_keys are not modified; removal is not secure erasure of older copies.", []string{"ssjack remove"}},
	{"check", "ssjack [--vault FILE] [-p PROFILE] check", "Verify SSH reachability, server pins, and authentication.", "Opens and closes an SSH session without running a remote command or requesting a PTY. Requires the vault secret; does not accept unknown host keys.", []string{"ssjack check"}},
	{"doctor", "ssjack [--vault FILE] doctor", "Inspect local credentials, permissions, MCP, and UI readiness.", "Requires the vault secret for full validation. Reports findings without changing settings, installing plugins, opening SSH connections, or launching a harness.", []string{"ssjack doctor", "ssjack --vault .ssh/work.ssjack.ktav doctor"}},
	{"rotate", "ssjack [--vault FILE] [-p PROFILE] rotate", "Stage a new key, verify its remote login, then switch the record.", "For a POSIX account using ~/.ssh/authorized_keys. Saves encrypted recovery files first and requires explicit confirmation before adding the new public key. Old remote keys are never removed automatically. A failed verification never switches the vault record.", []string{"ssjack rotate"}},
	{"key", "ssjack [--vault FILE] key COMMAND", "Import, export, or display a record's SSH key.", "Private exports are encrypted OpenSSH files with a distinct passphrase. No private key is printed or exposed through MCP.", []string{"ssjack key public", "ssjack help key export"}},
	{"key public", "ssjack [--vault FILE] [-p PROFILE] key public", "Print only the client's OpenSSH public key.", "Requires interactive vault authorization. Safe to redirect the public output; the secret prompt is written to stderr.", []string{"ssjack key public", "ssjack key public > home.pub"}},
	{"key import", "ssjack [--vault FILE] [-p PROFILE] key import FILE", "Replace a record's private key from an OpenSSH, PEM, or ssjack file.", "Preserves address, user, usage, and server pins. Source files are never rewritten or deleted. A plaintext source remains plaintext outside the vault. Install the new public key on the server separately if identity changes.", []string{"ssjack key import existing-key.pem"}},
	{"key export", "ssjack [--vault FILE] [-p PROFILE] key export FILE", "Create a new encrypted OpenSSH private-key file.", "Requires a confirmed, nonempty passphrase different from the vault secret. Existing output paths are refused. Standard OpenSSH protection is not the custom Argon2id/1000-layer profile; use vault backup for disaster recovery.", []string{"ssjack key export home.openssh"}},
	{"policy", "ssjack [-p PROFILE] policy show|edit", "Inspect or edit encrypted SSH algorithm preferences.", "Values are never persisted in plaintext configuration or passed in argv. Only safe SupportedAlgorithms entries from the pinned SSH library are accepted; this does not change container encryption.", []string{"ssjack policy show", "ssjack -p work policy edit"}},
	{"policy show", "ssjack [-p PROFILE] policy show", "Display this profile's SSH preferences after authorization.", "Empty preferences mean safe compiled defaults. This intentionally displays metadata to the authorized terminal.", []string{"ssjack policy show"}},
	{"policy edit", "ssjack [-p PROFILE] policy edit", "Edit host-key, key-exchange, cipher, and MAC lists without echo.", "Enter keeps the value, default resets it, comma-separated safe identifiers set preferences. Duplicates/unsupported/insecure choices fail before save; profile-name confirmation is required.", []string{"ssjack -p work policy edit"}},
	{"hostkey", "ssjack [--vault FILE] hostkey COMMAND", "Inspect or explicitly replace trusted server keys.", "These are server identity pins, not the client's login public key. No network scan or automatic trust acceptance is performed.", []string{"ssjack hostkey show", "ssjack help hostkey replace"}},
	{"hostkey show", "ssjack [--vault FILE] [-p PROFILE] hostkey show", "Display the trusted server-key fingerprints.", "Reads only the encrypted database after vault authorization; does not connect to the server.", []string{"ssjack hostkey show"}},
	{"hostkey replace", "ssjack [--vault FILE] [-p PROFILE] hostkey replace FILE", "Replace server pins with an independently verified public key.", "FILE must contain one bare OpenSSH server public key. Shows old and new fingerprints and requires typing the new fingerprint before committing. Never use this to bypass an unexplained key mismatch.", []string{"ssjack hostkey replace verified-server-key.pub"}},
	{"vault", "ssjack [--vault FILE] vault COMMAND", "Manage the encrypted database as a whole.", "Record commands are top-level: list, show, add, edit, remove. Backups remain encrypted and include the parameters needed to recover stored keys.", []string{"ssjack vault init", "ssjack help vault restore"}},
	{"vault migrate", "ssjack [-p PROFILE] [--vault FILE] vault migrate LEGACY_FILE", "Import one legacy connection into the encrypted profile database.", "Requests terminal authorization, imports private key bytes and only server pins already trusted for the exact address, preserves originals, refuses profile overwrite, and snapshots an existing database. Normal startup never reads this file.", []string{"ssjack vault migrate .ssh/ssjack.ktav", "ssjack -p work vault migrate legacy-work.ktav"}},
	{"vault init", "ssjack [--vault FILE] [-p PROFILE] vault init [--generate-key]", "Create a new encrypted database with a confirmed secret.", "The parent directory must exist. Prompts for a complete initial profile, named main unless -p selects another. --generate-key creates Ed25519 in memory using the new database master instead of importing a key file; public-key instructions appear only after encrypted save. No invalid empty profile is saved; existing files and symlinks are not overwritten.", []string{"ssjack vault init", "ssjack -p work vault init --generate-key"}},
	{"vault upgrade", "ssjack [--vault FILE] vault upgrade", "Explicitly upgrade a v1 database to opaque v2.", "Authenticates the original and verifies the new encrypted payload before UPGRADE confirmation. Preserves exact encrypted v1 bytes before revision-checked replacement. Already-v2 databases are authenticated and left unchanged. Ordinary edits retain the loaded format; backups are never silently upgraded. Older binaries need the preserved v1 copy.", []string{"ssjack vault upgrade", "ssjack --vault .ssh/work.ssjack.ktav vault upgrade"}},
	{"vault passwd", "ssjack [--vault FILE] vault passwd", "Re-encrypt the database with a new confirmed secret.", "Requires the current secret, then a confirmed new secret. Uses fresh public parameters. Existing backups retain their old secret and protection.", []string{"ssjack vault passwd"}},
	{"vault backup", "ssjack [--vault FILE] vault backup FILE", "Verify and copy the complete encrypted database to a new file.", "Checks authentication and schema before copying ciphertext. Refuses overwrite. No private data is written as plaintext.", []string{"ssjack vault backup backups/home.ssjack.ktav"}},
	{"vault check", "ssjack vault check FILE", "Authenticate and validate an encrypted database or backup.", "Requests the backup's secret, validates every record, and makes no changes or network connections. This is not a password-only recovery operation.", []string{"ssjack vault check backups/home.ssjack.ktav"}},
	{"vault restore", "ssjack [--vault FILE] vault restore FILE", "Verify a backup and restore it with a recoverable previous copy.", "Requests backup and current secrets as needed, saves encrypted recovery snapshots, and requires explicit confirmation. Rejects revision conflicts. Source backups and the last working copy are never deleted to make replacement succeed.", []string{"ssjack vault restore backups/home.ssjack.ktav"}},
	{"--licenses", "ssjack --licenses", "Print the project license choices and third-party notices.", "Works without opening the vault or prompting for a secret. Project-owned code is MIT OR Apache-2.0; third-party components retain their own terms. Notices are embedded in the executable for redistribution.", []string{"ssjack --licenses"}},
	{"--version", "ssjack --version", "Print build version, commit, and platform without unlocking secrets.", "Development builds identify themselves as dev/unknown unless CI embeds an exact commit. This does not change vault formats or dependency versions.", []string{"ssjack --version"}},
	{"--generate-key", "ssjack --generate-key FILE", "Derive an Ed25519 key from hidden manual input and fresh parameters.", "Confirms the secret, writes a new ssjack container and FILE.pub, and never overwrites either. Same secret with different public parameters gives a different key; retain the container. Uses four Argon2id operations and 1000 data layers.", []string{"ssjack --generate-key .ssh/derived.ssjack.ktav"}},
	{"--protect-key", "ssjack --protect-key FILE [--key-output NEW_FILE]", "Import a private-key file into a new ssjack encrypted container.", "Supports standard OpenSSH/PEM and ssjack sources. Requests source authorization when encrypted and confirms the new secret. Source files and credential records remain unchanged.", []string{"ssjack --protect-key existing-key --key-output .ssh/protected.ssjack.ktav"}},
	{"mcp", "ssjack mcp", "Run the internal authenticated MCP stdio bridge.", "Started by the selected harness, not a standalone way to unlock credentials. Requires the keeper's memory-only single-use environment capability and pinned TLS parameters and accepts no credential or password arguments.", []string{"ssjack run claude -c"}},
	{"install-hooks", "ssjack install-hooks", "Install legacy display hooks for compatibility only.", "Not required for normal startup: the UI plugin is installed automatically. Do not combine legacy display notices with the normal card workflow.", []string{"ssjack install-hooks"}},
	{"hook", "ssjack hook pre|post|failure", "Handle one legacy hook event from stdin.", "Internal compatibility endpoint for installed legacy display hooks; it does not execute remote commands or unlock SSH keys.", []string{"ssjack hook pre < hook-event.json"}},
	{"help", "ssjack help [COMMAND [SUBCOMMAND]]", "Show command descriptions, safety notes, and examples.", "Help never opens the database or asks for a secret. For harness help, keep --help after the harness name in run.", []string{"ssjack help", "ssjack help vault restore", "ssjack help key export"}},
}

func findHelp(name string) *commandHelp {
	for i := range commands {
		if commands[i].Name == name {
			return &commands[i]
		}
	}
	return nil
}

func printRootHelp(w io.Writer) {
	fmt.Fprint(w, "Usage: ssjack [options] COMMAND [arguments...]\n\nNamed encrypted profiles (default main), native SSH sessions, and scoped coding-agent access.\n")
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "Commands:")
	for _, entry := range commands {
		if !strings.Contains(entry.Name, " ") && !strings.HasPrefix(entry.Name, "--") && entry.Name != "hook" && entry.Name != "install-hooks" {
			fmt.Fprintf(table, "  %s\t%s\n", entry.Name, entry.Summary)
		}
	}
	table.Flush()
	fmt.Fprintln(w, "\nOptions:\n  --vault FILE              Encrypted database (default .ssh/credentials.ssjack.ktav)\n  --bootstrap-timeout TIME  Initial agent MCP attachment deadline (default 2m; maximum 10m)\n  --clawwright-directory DIR Register a trusted Clawwright deployment for app_* MCP tools\n  --clawwright-entry FILE    Checked dist/entry/bin.js (default installed package on PATH)\n  --clawwright-container NAME Fixed Incus route through the selected SSH host\n  --clawwright-user USER     Explicit guest user for the Incus route\n  -p, --profile NAME        Encrypted profile (default main)\n  --version                 Print build identity\n  --licenses                Print licenses and third-party notices\n  --generate-key FILE       Create a secret-derived Ed25519 key container\n  --protect-key FILE        Protect a key without changing its source\n  --key-output FILE         Output for --protect-key\n  --help                    Show this help")
	fmt.Fprintln(w, "\nExamples:\n  ssjack ssh\n  ssjack run claude -c\n  ssjack add\n  ssjack vault backup backups/home.ssjack.ktav\n  ssjack help key export\n\nUse 'ssjack help COMMAND' for arguments, safety notes, and examples.")
}

func printCommandHelp(w io.Writer, entry *commandHelp) {
	fmt.Fprintf(w, "Usage: %s\n\n%s\n\n%s\n", entry.Usage, entry.Summary, entry.Details)
	for _, child := range commands {
		if strings.HasPrefix(child.Name, entry.Name+" ") {
			fmt.Fprintf(w, "\n  %-22s %s", child.Name, child.Summary)
		}
	}
	fmt.Fprintln(w, "\n\nExamples:")
	for _, example := range entry.Examples {
		fmt.Fprintln(w, "  "+example)
	}
}

func handleHelp(args []string, w io.Writer) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	if args[0] == "help" {
		if len(args) == 1 {
			printRootHelp(w)
			return true, nil
		}
		entry := findHelp(strings.Join(args[1:], " "))
		if entry == nil {
			return true, fmt.Errorf("unknown help topic %q; use ssjack help", strings.Join(args[1:], " "))
		}
		printCommandHelp(w, entry)
		return true, nil
	}
	if args[len(args)-1] != "--help" && args[len(args)-1] != "-h" {
		return false, nil
	}
	if args[0] == "run" && len(args) > 2 {
		return false, nil
	}
	for size := len(args) - 1; size > 0; size-- {
		if entry := findHelp(strings.Join(args[:size], " ")); entry != nil {
			printCommandHelp(w, entry)
			return true, nil
		}
	}
	return false, nil
}
