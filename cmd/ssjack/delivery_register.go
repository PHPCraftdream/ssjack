package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
	"github.com/PHPCraftdream/ssjack/internal/declarativeslice"
)

const deliveryPurpose = "synthetic-confidential-delivery"
const deliveryPolicy = "synthetic-delivery-v1"

func registerDelivery() (int, error) {
	read := func(prompt string) ([]byte, error) { return readVisibleInput(prompt, false) }
	refBytes, err := read("Exact canonical confidential-delivery reference: ")
	if err != nil {
		return 1, err
	}
	ref := string(refBytes)
	if declarativeauthority.ValidateReference(ref) != nil {
		return 1, errors.New("reference must be the exact canonical placeholder")
	}
	if err = confirmVisibleValue("Repeat exact canonical reference: ", ref); err != nil {
		return 1, err
	}
	storeBytes, err := read("Trusted absolute StorePath (human verified, never supplied by model tooling): ")
	if err != nil {
		return 1, err
	}
	store := string(storeBytes)
	if store == "" || !strings.HasPrefix(store, "/") || strings.Contains(store, "\\") {
		return 1, errors.New("invalid trusted StorePath")
	}
	if err = confirmVisibleValue("Repeat exact StorePath: ", store); err != nil {
		return 1, err
	}
	dev, err := readUint("Verified store directory device number: ")
	if err != nil {
		return 1, err
	}
	if err = confirmVisibleValue("Repeat directory device number: ", strconv.FormatUint(dev, 10)); err != nil {
		return 1, err
	}
	ino, err := readUint("Verified store directory inode number: ")
	if err != nil {
		return 1, err
	}
	if err = confirmVisibleValue("Repeat directory inode number: ", strconv.FormatUint(ino, 10)); err != nil {
		return 1, err
	}
	installation, err := readDigest("Independently verified encrypted InstallationSHA256: ")
	if err != nil {
		return 1, err
	}
	encoded, err := readDigest("Current snapshot EncodedHash from independently verified keeper CLI: ")
	if err != nil {
		return 1, err
	}
	driver, err := declarativeauthority.DeliveryDriverDigest()
	if err != nil {
		return 1, err
	}
	consumer, err := declarativeauthority.DeliveryCodeDigest()
	if err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Fixed installed driver SHA256:", driver, "; verify independently and repeat.")
	if err = repeatDigest("Independent driver SHA256: ", driver); err != nil {
		return 1, err
	}
	if err = repeatDigest("Repeat driver SHA256: ", driver); err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Fixed consumer:", declarativeauthority.ConsumerPath, "SHA256:", consumer, "; verify independently and repeat.")
	if err = repeatDigest("Independent consumer SHA256: ", consumer); err != nil {
		return 1, err
	}
	if err = repeatDigest("Repeat consumer SHA256: ", consumer); err != nil {
		return 1, err
	}
	contract := declarativeslice.Contract()
	fmt.Fprintln(os.Stderr, "Fixed scope target", contract.Target, "purpose", deliveryPurpose, "desired schema", contract.DesiredSchemaID, contract.DesiredSchemaSHA256, "projection", contract.ProjectionSchemaID, contract.ProjectionSchemaSHA256, "policy", deliveryPolicy)
	if err = confirmVisibleValue("Type exact target identifier: ", contract.Target); err != nil {
		return 1, err
	}
	expBytes, err := read("Expiry RFC3339 UTC (within 24 hours): ")
	if err != nil {
		return 1, err
	}
	exp := string(expBytes)
	until, e := time.Parse(time.RFC3339, exp)
	if e != nil || until.UTC().Format(time.RFC3339) != exp || !until.After(time.Now()) || until.Sub(time.Now()) > 24*time.Hour {
		return 1, errors.New("invalid delivery expiry")
	}
	uidBytes, err := read("Keeper effective UID (non-root): ")
	if err != nil {
		return 1, err
	}
	uid, e := strconv.Atoi(string(uidBytes))
	if e != nil || uid <= 0 {
		return 1, errors.New("invalid keeper UID")
	}
	if err = confirmVisibleValue("Repeat keeper UID: ", strconv.Itoa(uid)); err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Scope:", ref, store, "device", dev, "inode", ino, "installation SHA256", installation, "snapshot EncodedHash", encoded, "UID", uid, "expires", exp)
	fmt.Fprintln(os.Stderr, "Synthetic only. Independent verification outside the model session is required; this receipt is not adoption.")
	if err = confirmVisibleValue("Type REGISTER SYNTHETIC CONFIDENTIAL DELIVERY GRANT: ", "REGISTER SYNTHETIC CONFIDENTIAL DELIVERY GRANT"); err != nil {
		return 1, err
	}
	if err = declarativeauthority.PrepareState(uid); err != nil {
		return 1, err
	}
	g := declarativeauthority.DeliveryGrant{RecipientUID: uid, Ref: ref, StorePath: store, DirectoryDev: dev, DirectoryIno: ino, InstallationSHA256: installation, EncodedHash: encoded, DriverCodeSHA256: driver, ConsumerSHA256: consumer, Target: contract.Target, Purpose: deliveryPurpose, DesiredSchemaID: contract.DesiredSchemaID, DesiredSchemaSHA256: contract.DesiredSchemaSHA256, ProjectionSchemaID: contract.ProjectionSchemaID, ProjectionSchemaSHA256: contract.ProjectionSchemaSHA256, PolicyRevision: deliveryPolicy, ExpiresAt: exp}
	if err = declarativeauthority.RegisterDelivery(g); err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Synthetic confidential delivery grant registered; receipt is not adoption.")
	return 0, nil
}

func readUint(prompt string) (uint64, error) {
	b, e := readVisibleInput(prompt, false)
	if e != nil {
		return 0, e
	}
	n, e := strconv.ParseUint(string(b), 10, 64)
	if e != nil || n == 0 {
		return 0, errors.New("invalid nonzero uint64")
	}
	return n, nil
}
func readDigest(prompt string) (string, error) {
	b, e := readVisibleInput(prompt, false)
	if e != nil {
		return "", e
	}
	s := string(b)
	if !digestHex(s) {
		return "", errors.New("digest must be canonical lowercase SHA256")
	}
	return s, nil
}
func repeatDigest(prompt, expected string) error {
	b, e := readVisibleInput(prompt, false)
	if e != nil {
		return e
	}
	if string(b) != expected {
		return errors.New("digest confirmation failed")
	}
	return nil
}
func revokeDelivery() (int, error) {
	b, e := readVisibleInput("Exact canonical confidential-delivery reference to revoke: ", false)
	if e != nil {
		return 1, e
	}
	ref := string(b)
	if declarativeauthority.ValidateReference(ref) != nil {
		return 1, errors.New("reference must be the exact canonical placeholder")
	}
	if e = confirmVisibleValue("Repeat exact canonical reference: ", ref); e != nil {
		return 1, e
	}
	if e = confirmVisibleValue("Type REVOKE SYNTHETIC CONFIDENTIAL DELIVERY GRANT: ", "REVOKE SYNTHETIC CONFIDENTIAL DELIVERY GRANT"); e != nil {
		return 1, e
	}
	return 0, declarativeauthority.RevokeDelivery(ref)
}
