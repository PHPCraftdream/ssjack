package main

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
	"net/url"
	"os"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
)

var errAppstore = errors.New("application-store setup failed")
var appstoreReadInput = readTerminalInput

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
