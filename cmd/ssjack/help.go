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
	{"ssh", "ssjack [--vault FILE] ssh NAME", "Open an interactive SSH session with named credentials.", "Requests the vault secret, verifies the stored server pins, then opens a PTY. No external SSH executable or agent is used. Human usage must be permitted by the record.", []string{"ssjack ssh home", "ssjack --vault .ssh/work.ssjack.ktav ssh work"}},
	{"run", "ssjack [options] run NAME HARNESS [ARGUMENTS...]", "Launch a coding harness with access to one credential record.", "Requests the vault secret once. The MCP bridge receives a single-use capability, not the private key or vault secret. Everything after HARNESS belongs to that program, including --help. Agent usage must be permitted by the record.", []string{"ssjack run home claude -c", "ssjack --bootstrap-timeout 5m run work claude -c"}},
	{"list", "ssjack [--vault FILE] list", "List credential names without exposing private keys.", "Requires interactive vault authorization. Labels are printed in sorted order.", []string{"ssjack list"}},
	{"show", "ssjack [--vault FILE] show NAME", "Show connection metadata, usage, and server fingerprints.", "Intentionally displays decrypted metadata, never private key bytes. Consider terminal recording and redirected output.", []string{"ssjack show home"}},
	{"add", "ssjack [--vault FILE] add NAME", "Create a named credential record interactively.", "Prompts for address, SSH user, key source, verified server public key, and intended usage. Imports the key into encrypted storage; source files remain unchanged.", []string{"ssjack add home"}},
	{"edit", "ssjack [--vault FILE] edit NAME", "Edit a record without a plaintext editor or temporary file.", "Hidden field input; Enter keeps the current value. Key and pin replacement are explicit. An invalid edit does not commit the record.", []string{"ssjack edit home"}},
	{"remove", "ssjack [--vault FILE] remove NAME", "Remove a credential record after confirmation.", "Requires the vault secret and typing the record name. Backups and remote authorized_keys are not modified; removal is not secure erasure of older copies.", []string{"ssjack remove home"}},
	{"check", "ssjack [--vault FILE] check NAME", "Verify SSH reachability, server pins, and authentication.", "Opens and closes an SSH session without running a remote command or requesting a PTY. Requires the vault secret; does not accept unknown host keys.", []string{"ssjack check home"}},
	{"doctor", "ssjack [--vault FILE] doctor", "Inspect local credentials, permissions, MCP, and UI readiness.", "Requires the vault secret for full validation. Reports findings without changing settings, installing plugins, opening SSH connections, or launching a harness.", []string{"ssjack doctor", "ssjack --vault .ssh/work.ssjack.ktav doctor"}},
	{"rotate", "ssjack [--vault FILE] rotate NAME", "Stage a new key, verify its remote login, then switch the record.", "For a POSIX account using ~/.ssh/authorized_keys. Saves encrypted recovery files first and requires explicit confirmation before adding the new public key. Old remote keys are never removed automatically. A failed verification never switches the vault record.", []string{"ssjack rotate home"}},
	{"key", "ssjack [--vault FILE] key COMMAND", "Import, export, or display a record's SSH key.", "Private exports are encrypted OpenSSH files with a distinct passphrase. No private key is printed or exposed through MCP.", []string{"ssjack key public home", "ssjack help key export"}},
	{"key public", "ssjack [--vault FILE] key public NAME", "Print only the client's OpenSSH public key.", "Requires interactive vault authorization. Safe to redirect the public output; the secret prompt is written to stderr.", []string{"ssjack key public home", "ssjack key public home > home.pub"}},
	{"key import", "ssjack [--vault FILE] key import NAME FILE", "Replace a record's private key from an OpenSSH, PEM, or ssjack file.", "Preserves address, user, usage, and server pins. Source files are never rewritten or deleted. A plaintext source remains plaintext outside the vault. Install the new public key on the server separately if identity changes.", []string{"ssjack key import home existing-key.pem"}},
	{"key export", "ssjack [--vault FILE] key export NAME FILE", "Create a new encrypted OpenSSH private-key file.", "Requires a confirmed, nonempty passphrase different from the vault secret. Existing output paths are refused. Standard OpenSSH protection is not the custom Argon2id/1000-layer profile; use vault backup for disaster recovery.", []string{"ssjack key export home home.openssh"}},
	{"hostkey", "ssjack [--vault FILE] hostkey COMMAND", "Inspect or explicitly replace trusted server keys.", "These are server identity pins, not the client's login public key. No network scan or automatic trust acceptance is performed.", []string{"ssjack hostkey show home", "ssjack help hostkey replace"}},
	{"hostkey show", "ssjack [--vault FILE] hostkey show NAME", "Display the trusted server-key fingerprints.", "Reads only the encrypted database after vault authorization; does not connect to the server.", []string{"ssjack hostkey show home"}},
	{"hostkey replace", "ssjack [--vault FILE] hostkey replace NAME FILE", "Replace server pins with an independently verified public key.", "FILE must contain one bare OpenSSH server public key. Shows old and new fingerprints and requires typing the new fingerprint before committing. Never use this to bypass an unexplained key mismatch.", []string{"ssjack hostkey replace home verified-server-key.pub"}},
	{"vault", "ssjack [--vault FILE] vault COMMAND", "Manage the encrypted database as a whole.", "Record commands are top-level: list, show, add, edit, remove. Backups remain encrypted and include the parameters needed to recover stored keys.", []string{"ssjack vault init", "ssjack help vault restore"}},
	{"vault init", "ssjack [--vault FILE] vault init", "Create a new encrypted database with a confirmed secret.", "The parent directory must exist. Existing files and symlinks are not overwritten. Every later invocation asks for the secret again.", []string{"ssjack vault init", "ssjack --vault .ssh/work.ssjack.ktav vault init"}},
	{"vault passwd", "ssjack [--vault FILE] vault passwd", "Re-encrypt the database with a new confirmed secret.", "Requires the current secret, then a confirmed new secret. Uses fresh public parameters. Existing backups retain their old secret and protection.", []string{"ssjack vault passwd"}},
	{"vault backup", "ssjack [--vault FILE] vault backup FILE", "Verify and copy the complete encrypted database to a new file.", "Checks authentication and schema before copying ciphertext. Refuses overwrite. No private data is written as plaintext.", []string{"ssjack vault backup backups/home.ssjack.ktav"}},
	{"vault check", "ssjack vault check FILE", "Authenticate and validate an encrypted database or backup.", "Requests the backup's secret, validates every record, and makes no changes or network connections. This is not a password-only recovery operation.", []string{"ssjack vault check backups/home.ssjack.ktav"}},
	{"vault restore", "ssjack [--vault FILE] vault restore FILE", "Verify a backup and restore it with a recoverable previous copy.", "Requests backup and current secrets as needed, saves encrypted recovery snapshots, and requires explicit confirmation. Rejects revision conflicts. Source backups and the last working copy are never deleted to make replacement succeed.", []string{"ssjack vault restore backups/home.ssjack.ktav"}},
	{"--version", "ssjack --version", "Print build version, commit, and platform without unlocking secrets.", "Development builds identify themselves as dev/unknown unless CI embeds an exact commit. This does not change vault formats or dependency versions.", []string{"ssjack --version"}},
	{"--generate-key", "ssjack --generate-key FILE", "Derive an Ed25519 key from hidden manual input and fresh parameters.", "Confirms the secret, writes a new ssjack container and FILE.pub, and never overwrites either. Same secret with different public parameters gives a different key; retain the container. Uses four Argon2id operations and 1000 data layers.", []string{"ssjack --generate-key .ssh/derived.ssjack.ktav"}},
	{"--protect-key", "ssjack --protect-key FILE [--key-output NEW_FILE]", "Import a private-key file into a new ssjack encrypted container.", "Supports standard OpenSSH/PEM and ssjack sources. Requests source authorization when encrypted and confirms the new secret. Source files and credential records remain unchanged.", []string{"ssjack --protect-key existing-key --key-output .ssh/protected.ssjack.ktav"}},
	{"mcp", "ssjack mcp", "Run the internal authenticated MCP stdio bridge.", "Started by the selected harness, not a standalone way to unlock credentials. Requires the keeper's single-use environment/file capabilities and accepts no credential or password arguments.", []string{"ssjack run home claude -c"}},
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
	fmt.Fprint(w, "Usage: ssjack [options] COMMAND [arguments...]\n\nNamed SSH credentials, native SSH sessions, and scoped coding-agent access.\n")
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "Commands:")
	for _, entry := range commands {
		if !strings.Contains(entry.Name, " ") && !strings.HasPrefix(entry.Name, "--") && entry.Name != "hook" && entry.Name != "install-hooks" {
			fmt.Fprintf(table, "  %s\t%s\n", entry.Name, entry.Summary)
		}
	}
	table.Flush()
	fmt.Fprintln(w, "\nOptions:\n  --vault FILE              Encrypted database (default .ssh/credentials.ssjack.ktav)\n  --bootstrap-timeout TIME  Initial agent MCP attachment deadline (default 2m; maximum 10m)\n  --config FILE             Explicit legacy plaintext target metadata; not used by named run/ssh\n  --version                 Print build identity\n  --generate-key FILE       Create a secret-derived Ed25519 key container\n  --protect-key FILE        Protect a key without changing its source\n  --key-output FILE         Output for --protect-key\n  --help                    Show this help")
	fmt.Fprintln(w, "\nExamples:\n  ssjack ssh home\n  ssjack run home claude -c\n  ssjack add home\n  ssjack vault backup backups/home.ssjack.ktav\n  ssjack help key export\n\nUse 'ssjack help COMMAND' for arguments, safety notes, and examples.")
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
	if args[0] == "run" && len(args) > 3 {
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
