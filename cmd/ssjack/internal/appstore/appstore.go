// Package appstore implements the ssjack appstore subcommands (setup, put,
// inspect, unlock). Run is the CLI entry point exported to the root command.
package appstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/terminal"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
	"github.com/PHPCraftdream/ssjack/internal/declarativeslice"
	"github.com/PHPCraftdream/ssjack/internal/launch"
)

// Run dispatches the appstore subcommands for the root CLI.
func Run(ctx context.Context, args []string) (int, error) {
	return runAppstore(ctx, args)
}

var appstoreReadInput = terminal.TerminalInput

// ReadInput forwards the canonical appstore input reader for text adapters.
func ReadInput(prompt string, allowEmpty bool) ([]byte, error) {
	return appstoreReadInput(prompt, allowEmpty)
}

// ErrSetup is the canonical application-store setup failure. Other chunks
// (e.g. the text adapter) should reference this instead of duplicating the
// sentinel so refusal classification keeps a single error identity.
var ErrSetup = errors.New("application-store setup failed")

func readTerminalInput(prompt string, allowEmpty bool) ([]byte, error) {
	return terminal.TerminalInput(prompt, allowEmpty)
}

func readVisibleInput(prompt string, allowEmpty bool) ([]byte, error) {
	return terminal.VisibleInput(prompt, allowEmpty)
}

func confirmVisibleValue(prompt, expected string) error {
	return terminal.ConfirmVisibleValue(prompt, expected)
}

func runAppstore(ctx context.Context, args []string) (int, error) {
	if len(args) == 0 {
		return 1, errors.New("usage: ssjack appstore setup DIR | put DIR | inspect DIR | unlock [--text-mode hydrate|reverse --text-fd FD] HARNESS [ARGS...]")
	}
	switch args[0] {
	case "setup":
		if len(args) != 2 {
			return 1, errors.New("usage: ssjack appstore setup DIR")
		}
		return runAppstoreSetup(ctx, args[1])
	case "put":
		if len(args) != 2 {
			return 1, errors.New("usage: ssjack appstore put DIR")
		}
		return runAppstorePut(ctx, args[1])
	case "inspect":
		if len(args) != 2 {
			return 1, errors.New("usage: ssjack appstore inspect DIR")
		}
		return runAppstoreInspect(ctx, args[1])
	case "unlock":
		if len(args) < 2 {
			return 1, errors.New("usage: ssjack appstore unlock [--text-mode hydrate|reverse --text-fd FD] HARNESS [ARGS...]")
		}
		return runAppstoreUnlock(ctx, args[1:])
	default:
		return 1, fmt.Errorf("usage: ssjack appstore setup DIR | put DIR | inspect DIR | unlock [--text-mode hydrate|reverse --text-fd FD] HARNESS [ARGS...]")
	}
}

func runAppstorePut(ctx context.Context, dir string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	if !appstoreentry.Supported() {
		return 1, appstoreentry.ErrUnsupported
	}
	store, err := appstoreentry.Open(dir)
	if err != nil {
		return 1, errAppstore
	}
	defer store.Close()
	encoded, digest, err := store.Load()
	if err != nil {
		return 1, errAppstore
	}
	defer clear(encoded)
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	master, err := appstoreReadInput("Application-store master secret: ", false)
	if err != nil {
		clear(master)
		return 1, errAppstore
	}
	defer clear(master)
	installation, err := appstorecrypto.UnlockInstallation(ctx, encoded, master)
	if err != nil {
		return 1, errAppstore
	}
	defer installation.Close()
	dev, ino, err := store.Identity()
	if err != nil || !installation.DirectoryMatches(dev, ino) {
		return 1, errAppstore
	}
	if store.VerifyUnchanged(digest) != nil {
		return 1, errAppstore
	}
	root, err := store.Root()
	if err != nil {
		return 1, errAppstore
	}
	defer root.Close()
	directory, err := appstorefile.Open(root, installation.Header().StoreID())
	if err != nil {
		return 1, errAppstore
	}
	defer directory.Close()
	writer, transport, err := installation.Writer(directory)
	if err != nil {
		return 1, errAppstore
	}
	defer transport.Close()
	opctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := opctx.Err(); err != nil {
		return 1, err
	}
	reply, err := transport.Read(opctx)
	if err != nil {
		return 1, errors.New("application-store read failed")
	}
	if reply.Operation() != appstoreanchorreply.Read || reply.Outcome() != appstoreanchorreply.ReadState {
		return 1, errors.New("application-store authority read was not successful")
	}
	state, present := reply.State()
	if !present || !state.Valid() || state.StoreID() != installation.Header().StoreID() {
		return 1, errAppstore
	}
	if state.Sequence() != 0 || state.CommittedSnapshotID() != ([16]byte{}) {
		return 1, errors.New("application-store already has committed data; put is first-entry only")
	}
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	if store.VerifyUnchanged(digest) != nil {
		return 1, errors.New("installation authority changed; no mutation sent")
	}
	secret, err := appstoreReadInput("Secret (max 16 KiB): ", false)
	if err != nil {
		clear(secret)
		return 1, errAppstore
	}
	if err = ctx.Err(); err != nil {
		clear(secret)
		return 1, err
	}
	var objectID [16]byte
	if _, err = rand.Read(objectID[:]); err != nil {
		clear(secret)
		return 1, errAppstore
	}
	object, closeObject, err := appstorecrypto.NewSecretObject(objectID, "text/plain", secret)
	clear(secret)
	if err != nil {
		return 1, errAppstore
	}
	defer closeObject()
	if err = ctx.Err(); err != nil {
		return 1, err
	}
	if store.VerifyUnchanged(digest) != nil {
		return 1, errors.New("installation authority changed; no mutation sent")
	}
	callctx, cancelCall := context.WithTimeout(ctx, 60*time.Second)
	defer cancelCall()
	commit, err := writer.WriteFirst(callctx, []appstorecrypto.SnapshotObject{object})
	if err != nil {
		return 1, writerFailure(err)
	}
	if len(commit.Refs) != 1 {
		return 1, errors.New("application-store mutation result invalid; inspect/reconcile before any new mutation")
	}
	placeholder, err := appstoreplaceholder.Encode(commit.Refs[0])
	if err != nil {
		return 1, errors.New("application-store committed; output encoding failed")
	}
	if _, err = io.WriteString(os.Stdout, string(placeholder)+"\n"); err != nil {
		clear(placeholder)
		return 1, errors.New("application-store committed; placeholder output failed")
	}
	clear(placeholder)
	if _, err := fmt.Fprintf(os.Stdout, "sequence=%d revision=%d\n", commit.State.Sequence(), commit.State.JournalCount()); err != nil {
		return 1, errors.New("application-store committed; revision output failed")
	}
	return 0, nil
}

func writerFailure(err error) error {
	switch {
	case errors.Is(err, appstorecrypto.ErrWriterPending):
		return errors.New("application-store outcome pending or uncertain; inspect/reconcile before any new mutation")
	case errors.Is(err, appstorecrypto.ErrWriterBurned):
		return errors.New("application-store reservation burned; inspect/reconcile before any new mutation")
	case errors.Is(err, appstorecrypto.ErrWriterRejected):
		return errors.New("application-store mutation rejected; inspect/reconcile before any new mutation")
	case errors.Is(err, appstorecrypto.ErrWriterPointerLag):
		return errors.New("application-store pointer lag; inspect/reconcile before any new mutation")
	default:
		return errors.New("application-store mutation outcome uncertain; inspect/reconcile before any new mutation")
	}
}

func RejectBrokerEnv() error {
	for _, n := range []string{broker.EnvFile, broker.EnvToken, broker.EnvSession, broker.EnvEndpoint, broker.EnvPin, "SSJACK_APP_ENDPOINT", "SSJACK_APP_TOKEN", "SSJACK_APP_CERTIFICATE_SHA256"} {
		if os.Getenv(n) != "" {
			return errors.New("appstore trust operations cannot run inside a broker session")
		}
	}
	return nil
}

func runAppstoreInspect(ctx context.Context, dir string) (int, error) {
	if err := RejectBrokerEnv(); err != nil {
		return 1, err
	}
	if os.Geteuid() == 0 {
		return 1, errors.New("trusted appstore inspection requires a non-root terminal")
	}
	if !appstoreentry.Supported() {
		return 1, appstoreentry.ErrUnsupported
	}
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	store, err := appstoreentry.Open(dir)
	if err != nil {
		return 1, errAppstore
	}
	defer store.Close()
	encoded, digest, err := store.Load()
	if err != nil {
		return 1, errAppstore
	}
	defer clear(encoded)
	master, err := appstoreReadInput("Application-store master secret: ", false)
	if err != nil {
		clear(master)
		return 1, errAppstore
	}
	defer clear(master)
	installation, err := appstorecrypto.UnlockInstallation(ctx, encoded, master)
	if err != nil {
		return 1, errAppstore
	}
	defer installation.Close()
	dev, ino, err := store.Identity()
	if err != nil || !installation.DirectoryMatches(dev, ino) || store.VerifyUnchanged(digest) != nil {
		return 1, errAppstore
	}
	root, err := store.Root()
	if err != nil {
		return 1, errAppstore
	}
	defer root.Close()
	directory, err := appstorefile.Open(root, installation.Header().StoreID())
	if err != nil {
		return 1, errAppstore
	}
	defer directory.Close()
	writer, transport, err := installation.Writer(directory)
	if err != nil {
		return 1, errAppstore
	}
	defer transport.Close()
	readCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	reply, err := transport.Read(readCtx)
	if err != nil {
		return 1, errors.New("application-store read failed")
	}
	state, ok := reply.State()
	if !reply.SignatureValid() || reply.Outcome() != appstoreanchorreply.ReadState || reply.Operation() != appstoreanchorreply.Read || !ok || !state.Valid() || state.StoreID() != installation.Header().StoreID() {
		return 1, errAppstore
	}
	_ = writer
	fmt.Fprintf(os.Stdout, "store_id=%x\ninstallation_sha256=%s\ndirectory_dev=%d\ndirectory_ino=%d\n", installation.Header().StoreID(), hex.EncodeToString(digest[:]), dev, ino)
	if state.Sequence() != 0 {
		fmt.Fprintf(os.Stdout, "encoded_hash=%x\nsequence=%d\n", state.CommittedFileHash(), state.Sequence())
	} else {
		fmt.Fprintln(os.Stdout, "encoded_hash=none\nsequence=0")
	}
	return 0, nil
}

func parseTextUnlock(command []string) ([]string, int, bool, bool, error) {
	if len(command) == 0 || command[0] != "--text-mode" {
		return command, -1, false, false, nil
	}
	if len(command) < 5 || (command[1] != "hydrate" && command[1] != "reverse") || command[2] != "--text-fd" {
		return nil, -1, false, true, errors.New("usage: ssjack appstore unlock --text-mode hydrate|reverse --text-fd FD HARNESS [ARGS...]")
	}
	fd, err := strconv.Atoi(command[3])
	if err != nil || fd < 3 || fd > 1024 || command[4] == "" {
		return nil, -1, false, true, errors.New("invalid trusted text descriptor or missing harness")
	}
	return command[4:], fd, command[1] == "reverse", true, nil
}

func runAppstoreUnlock(ctx context.Context, command []string) (int, error) {
	var selection io.Reader
	var selectionFile *os.File
	var reverse bool
	var textMode bool
	var fd int
	var err error
	command, fd, reverse, textMode, err = parseTextUnlock(command)
	if err != nil {
		return 1, err
	}
	if textMode {
		selectionFile = os.NewFile(uintptr(fd), "trusted-text-selection")
		if selectionFile == nil {
			return 1, errors.New("trusted text descriptor unavailable")
		}
		selection = selectionFile
	}
	if selectionFile != nil {
		defer selectionFile.Close()
	}
	if len(command) == 0 {
		return 1, errors.New("usage: ssjack appstore unlock [--text-mode hydrate|reverse --text-fd FD] HARNESS [ARGS...]")
	}
	if err := RejectBrokerEnv(); err != nil {
		return 1, err
	}
	if os.Geteuid() == 0 {
		return 1, errors.New("trusted appstore unlock requires a non-root terminal")
	}
	if !appstoreentry.Supported() {
		return 1, appstoreentry.ErrUnsupported
	}
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	refBytes, err := readVisibleInput("Exact canonical delivery reference: ", false)
	if err != nil {
		return 1, err
	}
	defer clear(refBytes)
	ref := string(refBytes)
	if err = declarativeauthority.ValidateReference(ref); err != nil {
		return 1, errors.New("reference must be the exact canonical placeholder")
	}
	snapshot, err := declarativeauthority.LoadDelivery(ref, os.Geteuid(), time.Now())
	if err != nil {
		return 1, errors.New("no active delivery grant")
	}
	grants := snapshot.Grants()
	if len(grants) != 1 {
		return 1, errors.New("no unique active delivery grant")
	}
	grant := grants[0]
	store, err := appstoreentry.Open(grant.StorePath)
	if err != nil {
		return 1, errAppstore
	}
	encoded, digest, err := store.Load()
	if err != nil {
		store.Close()
		return 1, errAppstore
	}
	if hex.EncodeToString(digest[:]) != grant.InstallationSHA256 {
		clear(encoded)
		store.Close()
		return 1, errAppstore
	}
	master, err := appstoreReadInput("Application-store master secret: ", false)
	if err != nil {
		clear(master)
		clear(encoded)
		store.Close()
		return 1, errAppstore
	}
	installation, err := appstorecrypto.UnlockInstallation(ctx, encoded, master)
	clear(master)
	clear(encoded)
	if err != nil {
		store.Close()
		return 1, errAppstore
	}
	dev, ino, err := store.Identity()
	if err != nil || dev != grant.DirectoryDev || ino != grant.DirectoryIno || !installation.DirectoryMatches(dev, ino) || store.VerifyUnchanged(digest) != nil {
		installation.Close()
		store.Close()
		return 1, errAppstore
	}
	if store.Close() != nil {
		installation.Close()
		return 1, errAppstore
	}
	parsed, err := appstoreplaceholder.Parse(refBytes)
	if err != nil {
		installation.Close()
		return 1, errAppstore
	}
	var session *declarativeslice.Session
	if selection != nil {
		session, err = declarativeslice.NewTextDelivery(ctx, installation, parsed, selection, reverse)
		_ = selectionFile.Close()
		selectionFile = nil
	} else {
		session, err = declarativeslice.NewDelivery(ctx, installation, parsed)
	}
	if err != nil {
		installation.Close()
		return 1, err
	}
	if selectionFile != nil {
		_ = selectionFile.Close()
		selectionFile = nil
	}
	defer installation.Close()
	defer session.Close()
	exe, err := os.Executable()
	if err != nil {
		return 1, err
	}
	root, err := os.Getwd()
	if err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Restricted synthetic confidential delivery; receipts do not establish adoption.")
	return launch.Run(ctx, launch.Options{Root: root, Mode: broker.ModeDeclarative, Executable: exe, Command: command, BootstrapTTL: 2 * time.Minute, Synthetic: session, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr})
}

// errAppstore is the package-internal synonym for the canonical ErrSetup
// sentinel so refusal classification keeps a single error identity.
var errAppstore = ErrSetup

func runAppstoreSetup(ctx context.Context, dir string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	if !appstoreentry.Supported() {
		return 1, appstoreentry.ErrUnsupported
	}
	store, err := appstoreentry.Open(dir)
	if err != nil {
		return 1, errAppstore
	}
	defer store.Close()
	if _, _, err = store.Identity(); err != nil {
		return 1, errAppstore
	}
	if err = store.RequireUninstalled(); err != nil {
		return 1, errAppstore
	}
	fmt.Fprintln(os.Stderr, "Independently verify the endpoint, store ID, signing key, CA certificate, and client certificate using a source outside this model before entering them.")
	endpoint, err := confirmStoreField("Exact HTTPS anchor endpoint: ", "Repeat exact endpoint from independent source: ")
	if err != nil {
		return 1, errAppstore
	}
	defer clear(endpoint)
	ep := string(endpoint)
	u, e := url.Parse(ep)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return 1, errAppstore
	}
	storeID, err := confirmStoreID()
	if err != nil {
		return 1, errAppstore
	}
	service, err := promptStoreBytes("Anchor signing public key raw 32-byte base64: ")
	if err != nil || len(service) != 32 {
		clear(service)
		return 1, errAppstore
	}
	defer clear(service)
	confirmedService, err := promptStoreBytes("Repeat signing public key from independent source: ")
	if err != nil || subtle.ConstantTimeCompare(service, confirmedService) != 1 {
		clear(confirmedService)
		return 1, errAppstore
	}
	clear(confirmedService)
	roots, err := promptStoreDERs("CA certificate DER base64 (one root only): ", 1)
	if err != nil {
		return 1, errAppstore
	}
	defer clearDERs(roots)
	chain, err := promptStoreDERs("Client certificate chain DER base64 (leaf first, max 8): ", 8)
	if err != nil {
		return 1, errAppstore
	}
	defer clearDERs(chain)
	if len(chain) == 0 {
		return 1, errAppstore
	}
	if len(roots) != 1 {
		return 1, errAppstore
	}
	if err := confirmFingerprint("CA SHA256 fingerprint from independent source: ", roots[0]); err != nil {
		return 1, errAppstore
	}
	if err := confirmFingerprint("Client leaf SHA256 fingerprint from independent source: ", chain[0]); err != nil {
		return 1, errAppstore
	}
	private, err := promptStoreBytes("Client PKCS#8 private key DER base64: ")
	if err != nil {
		return 1, errAppstore
	}
	if len(private) == 0 {
		clear(private)
		return 1, errAppstore
	}
	header, err := makeInstallationHeader(storeID)
	if err != nil {
		clear(private)
		return 1, errAppstore
	}
	dev, ino, err := store.Identity()
	if err != nil {
		clear(private)
		return 1, errAppstore
	}
	master, err := appstoreConfirmSecret("application-store master secret")
	if err != nil {
		clear(private)
		return 1, err
	}
	defer clear(master)
	if err := ctx.Err(); err != nil {
		clear(private)
		return 1, err
	}
	binding := appstorecrypto.Binding{Endpoint: ep, RootsDER: roots, CertificateDER: chain, PrivateDER: private, ServiceKey: service, Header: header, DirectoryDev: dev, DirectoryIno: ino}
	encoded, err := appstorecrypto.NewInstallation(ctx, header, master, binding)
	clear(private)
	if err != nil {
		return 1, errAppstore
	}
	defer clear(encoded)
	if err = store.Install(encoded); err != nil {
		return 1, errAppstore
	}
	fmt.Fprintln(os.Stdout, "Application-store installation created.")
	return 0, nil
}

func makeInstallationHeader(store [16]byte) (appstoreheader.Header, error) {
	if store == ([16]byte{}) {
		return appstoreheader.Header{}, errAppstore
	}
	var raw [appstoreheader.Size]byte
	copy(raw[:8], "SSAPP001")
	binary.BigEndian.PutUint16(raw[8:10], 1)
	copy(raw[12:28], store[:])
	if _, err := rand.Read(raw[28:44]); err != nil {
		return appstoreheader.Header{}, err
	}
	binary.BigEndian.PutUint32(raw[60:64], appstoreheader.ChunkSize)
	binary.BigEndian.PutUint64(raw[64:72], appstoreheader.ChunkSize)
	binary.BigEndian.PutUint32(raw[72:76], 1)
	var salts [4][32]byte
	for i := range salts {
		for {
			if _, err := rand.Read(salts[i][:]); err != nil {
				return appstoreheader.Header{}, err
			}
			unique := true
			for j := 0; j < i; j++ {
				if salts[i] == salts[j] {
					unique = false
				}
			}
			if unique {
				break
			}
		}
		copy(raw[80+i*32:112+i*32], salts[i][:])
	}
	if _, err := rand.Read(raw[208:220]); err != nil {
		return appstoreheader.Header{}, err
	}
	return appstoreheader.Parse(raw[:])
}
func promptStoreField(prompt string) ([]byte, error) {
	b, e := appstoreReadInput(prompt, false)
	if e != nil {
		clear(b)
		return nil, e
	}
	if len(b) > 4096 {
		clear(b)
		return nil, errAppstore
	}
	return b, nil
}
func promptStoreBytes(prompt string) ([]byte, error) {
	b, e := promptStoreField(prompt)
	if e != nil {
		clear(b)
		return nil, e
	}
	defer clear(b)
	v := make([]byte, base64.StdEncoding.DecodedLen(len(b)))
	n, e := base64.StdEncoding.Strict().Decode(v, bytes.TrimSpace(b))
	if e != nil || n > 1<<20 {
		clear(v)
		return nil, errAppstore
	}
	return v[:n], nil
}
func promptStoreDERs(prompt string, max int) ([][]byte, error) {
	b, e := promptStoreField(prompt)
	if e != nil {
		clear(b)
		return nil, e
	}
	defer clear(b)
	parts := strings.Split(string(b), ",")
	if len(parts) == 0 || len(parts) > max {
		return nil, errAppstore
	}
	out := make([][]byte, 0, len(parts))
	for _, p := range parts {
		v, e := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(p))
		if e != nil || len(v) == 0 || len(v) > 1<<20 {
			clear(v)
			clearDERs(out)
			return nil, errAppstore
		}
		out = append(out, v)
	}
	return out, nil
}
func clearDERs(v [][]byte) {
	for _, b := range v {
		clear(b)
	}
}
func confirmStoreField(first, again string) ([]byte, error) {
	a, e := promptStoreField(first)
	if e != nil {
		clear(a)
		return nil, e
	}
	b, e := promptStoreField(again)
	defer clear(b)
	if e != nil || subtle.ConstantTimeCompare(a, b) != 1 {
		clear(a)
		return nil, errAppstore
	}
	return a, nil
}
func confirmStoreID() ([16]byte, error) {
	a, e := promptStoreHex("Existing storeID (32 hex characters): ")
	if e != nil {
		return [16]byte{}, e
	}
	b, e := promptStoreHex("Repeat exact storeID from independent source: ")
	if e != nil || subtle.ConstantTimeCompare(a[:], b[:]) != 1 || a == ([16]byte{}) {
		clear(a[:])
		clear(b[:])
		return [16]byte{}, errAppstore
	}
	clear(b[:])
	return a, nil
}
func promptStoreHex(p string) ([16]byte, error) {
	var id [16]byte
	b, e := promptStoreField(p)
	if e != nil {
		return id, e
	}
	defer clear(b)
	v, e := hex.DecodeString(string(b))
	if e != nil || len(v) != 16 {
		clear(v)
		return id, errAppstore
	}
	copy(id[:], v)
	clear(v)
	return id, nil
}
func confirmFingerprint(prompt string, der []byte) error {
	b, e := promptStoreField(prompt)
	if e != nil {
		return e
	}
	defer clear(b)
	got, e := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(string(b)), ":", ""))
	want := sha256.Sum256(der)
	if e != nil || len(got) != 32 || subtle.ConstantTimeCompare(got, want[:]) != 1 {
		return errAppstore
	}
	clear(got)
	return nil
}
func appstoreConfirmSecret(label string) ([]byte, error) {
	a, e := appstoreReadInput("New "+label+": ", false)
	if e != nil {
		clear(a)
		return nil, e
	}
	b, e := appstoreReadInput("Confirm "+label+": ", false)
	defer clear(b)
	if e != nil || subtle.ConstantTimeCompare(a, b) != 1 {
		clear(a)
		return nil, errAppstore
	}
	return a, nil
}
