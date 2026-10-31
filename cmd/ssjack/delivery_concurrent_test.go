//go:build linux && amd64

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

const raceDir = "/var/lib/ssjack/synthetic/concurrent"

type raceReply struct {
	State       string `json:"state"`
	Delivery    string `json:"delivery"`
	OperationID string `json:"operation_id"`
}
type racePlan struct {
	PlanID   string `json:"plan_id"`
	Revision string `json:"revision"`
}

func (f *deliveryFixture) deliveryConcurrentAcceptance(t *testing.T, ref string, fields map[string]string, artifacts string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("concurrent delivery requires root provisioning")
	}
	grantPath := filepath.Join(declarativeauthority.RegistryPath, declarativeauthority.GrantsName)
	deliveryPath := filepath.Join(declarativeauthority.RegistryPath, "delivery-grants.json")
	grants, err := os.ReadFile(grantPath)
	existed := err == nil
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Remove(grantPath); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	defer func() {
		if existed {
			if err := os.WriteFile(grantPath, grants, 0644); err != nil {
				t.Error(err)
			}
			_ = os.Chown(grantPath, 0, 0)
		} else {
			_ = os.Remove(grantPath)
		}
	}()
	driverPath := declarativeauthority.DriverPath
	originalDriver, err := os.ReadFile(driverPath)
	if err != nil {
		t.Fatal(err)
	}
	originalDelivery, err := os.ReadFile(deliveryPath)
	if err != nil {
		t.Fatal(err)
	}
	raceDriver, err := os.ReadFile(filepath.Join(artifacts, "driver-race"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(driverPath, raceDriver, 0755); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.WriteFile(driverPath, originalDriver, 0755); err != nil {
			t.Error(err)
		}
		_ = os.Chown(driverPath, 0, 0)
		if err := os.WriteFile(deliveryPath, originalDelivery, 0644); err != nil {
			t.Error(err)
		}
		_ = os.Chown(deliveryPath, 0, 0)
	}()
	f.registerDeliveryGrant(t, ref, fields, time.Now().UTC().Add(2*time.Hour).Format(time.RFC3339))
	if err := os.MkdirAll(raceDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(raceDir, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(raceDir, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(declarativeauthority.StatePath, "consumer-receipt")
	readMarker := func() []byte {
		b, e := os.ReadFile(marker)
		if os.IsNotExist(e) {
			return nil
		}
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	metaAnswers := []deliveryAnswer{{"Exact canonical metadata placeholder: ", []byte(ref)}, {"Repeat exact canonical reference: ", []byte(ref)}, {"Independent installed driver SHA256: ", []byte(concurrentDriverSHA256(driverPath))}, {"Repeat independently verified SHA256: ", []byte(concurrentDriverSHA256(driverPath))}, {"Type the exact target identifier to authorize: ", []byte("target")}, {"Expiry RFC3339 UTC (within 30 days): ", []byte(time.Now().UTC().Add(48 * time.Hour).Format(time.RFC3339))}, {"Keeper effective UID (non-root): ", []byte("65534")}, {"Repeat keeper UID: ", []byte("65534")}, {"Type REGISTER SYNTHETIC METADATA GRANT: ", []byte("REGISTER SYNTHETIC METADATA GRANT")}}
	f.runDeliveryCLIAs(t, 0, metaAnswers, "declarative", "register")
	for _, round := range []struct {
		name, first, winner, loser, winnerDelivery, loserDelivery string
		delta                                                     int
	}{
		{"secret-wins", "secret", "secret", "metadata", "RECEIVED", "", 48},
		{"metadata-wins", "metadata", "metadata", "secret", "", "WITHHELD", 0},
	} {
		t.Run(round.name, func(t *testing.T) {
			f.concurrentRound(t, ref, artifacts, round.first, round.winner, round.loser, round.winnerDelivery, round.loserDelivery, round.delta, readMarker)
		})
	}
}

func (f *deliveryFixture) concurrentRound(t *testing.T, ref, artifacts, first, winner, loser, winnerDelivery, loserDelivery string, delta int, marker func() []byte) {
	t.Helper()
	for _, name := range []string{"secret.planned", "secret.apply", "secret.calling", "secret.result", "metadata.planned", "metadata.apply", "metadata.calling", "metadata.result", "driver.waiting", "driver.release"} {
		if err := os.Remove(filepath.Join(raceDir, name)); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	lock, err := os.OpenFile(filepath.Join(declarativeauthority.StatePath, ".lock"), os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	locked := true
	defer func() {
		if locked {
			_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		}
		_ = lock.Close()
		_ = os.WriteFile(filepath.Join(raceDir, "driver.release"), []byte("release"), 0644)
	}()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	before := marker()
	answers := []deliveryAnswer{{"Exact canonical delivery reference: ", []byte(ref)}, {"Application-store master secret: ", []byte(f.anchor.master)}}
	type reply struct {
		side, out string
		err       error
	}
	ch := make(chan reply, 2)
	completed := 0
	defer func() {
		for _, name := range []string{"secret.apply", "metadata.apply", "driver.release"} {
			_ = os.WriteFile(filepath.Join(raceDir, name), []byte("release"), 0644)
		}
		if locked {
			_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
			locked = false
		}
		// Each PTY helper has a 120-second deadline; join before restoring fixtures.
		for completed < 2 {
			<-ch
			completed++
		}
	}()
	for _, side := range []string{"secret", "metadata"} {
		mode := "race-secret"
		if side == "metadata" {
			mode = "race-metadata"
		}
		go func(s, m string) {
			var out string
			var err error
			if s == "metadata" {
				out, err = f.tryDeliveryCLIAs(t, 65534, nil, "declarative", "run", filepath.Join(artifacts, "harness"), ref, m)
			} else {
				out, err = f.tryDeliveryCLIAs(t, 65534, answers, "appstore", "unlock", filepath.Join(artifacts, "harness"), ref, m)
			}
			ch <- reply{s, out, err}
		}(side, mode)
	}
	wait := func(name string) []byte {
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			b, e := os.ReadFile(filepath.Join(raceDir, name))
			if e == nil {
				return b
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("timeout waiting for %s", name)
		return nil
	}
	var plans [2]racePlan
	for i, side := range []string{"secret", "metadata"} {
		dec := json.NewDecoder(bytes.NewReader(wait(side + ".planned")))
		dec.DisallowUnknownFields()
		if dec.Decode(&plans[i]) != nil || plans[i].PlanID == "" {
			t.Fatal("invalid planned marker")
		}
		if i > 0 && plans[0].Revision != plans[1].Revision {
			t.Fatal("plans did not share revision")
		}
	}
	write := func(name string) {
		if err := os.WriteFile(filepath.Join(raceDir, name), []byte("go"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write(first + ".apply")
	wait("driver.waiting")
	wait(first + ".calling")
	if len(marker()) != len(before) {
		t.Fatal("receipt changed while CAS lock held")
	}
	other := "secret"
	if first == "secret" {
		other = "metadata"
	}
	write(other + ".apply")
	wait(other + ".calling")
	if _, err := os.Stat(filepath.Join(raceDir, other+".result")); !os.IsNotExist(err) {
		t.Fatal("apply returned before driver release")
	}
	write("driver.release")
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	locked = false
	results := map[string]raceReply{}
	for i := 0; i < 2; i++ {
		select {
		case r := <-ch:
			completed++
			if r.err != nil {
				t.Errorf("%s CLI: %v", r.side, r.err)
				continue
			}
			if !strings.Contains(r.out, "CONCURRENT_ACCEPTANCE_OK") {
				t.Errorf("%s harness incomplete", r.side)
			}
			dec := json.NewDecoder(bytes.NewReader(wait(r.side + ".result")))
			dec.DisallowUnknownFields()
			var got raceReply
			if dec.Decode(&got) != nil || got.OperationID == "" {
				t.Errorf("bad %s result", r.side)
				continue
			}
			results[r.side] = got
		case <-time.After(45 * time.Second):
			t.Fatal("concurrent CLI timeout")
		}
	}
	if results[winner].State != "SUCCEEDED" || results[winner].Delivery != winnerDelivery || results[loser].State != "FAILED" || results[loser].Delivery != loserDelivery {
		t.Fatalf("unexpected race outcomes: %+v", results)
	}
	if got := len(marker()) - len(before); got != delta {
		t.Fatalf("receipt delta %d, want %d", got, delta)
	}
	var state struct {
		OperationID string `json:"operation_id"`
	}
	raw, err := os.ReadFile(filepath.Join(declarativeauthority.StatePath, "state.json"))
	if err != nil || json.Unmarshal(raw, &state) != nil || state.OperationID != results[winner].OperationID {
		t.Fatal(fmt.Sprintf("persisted state operation mismatch: %v", err))
	}
}
func concurrentDriverSHA256(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
