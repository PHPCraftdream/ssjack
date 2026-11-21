//go:build linux && amd64

package delivery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
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
	metaAnswers := []deliveryAnswer{{"Exact canonical metadata placeholder: ", []byte(ref)}, {"Repeat exact canonical reference: ", []byte(ref)}, {"Independent installed driver SHA256: ", []byte(concurrentDriverSHA256(driverPath))}, {"Repeat independently verified SHA256: ", []byte(concurrentDriverSHA256(driverPath))}, {"Type the exact target identifier to authorize: ", []byte("target")}, {"Expiry RFC3339 UTC (within 30 days): ", []byte(time.Now().UTC().Add(48 * time.Hour).Format(time.RFC3339))}, {"Keeper effective UID (non-root): ", []byte("65534")}, {"Repeat keeper UID: ", []byte("65534")}, {"Type REGISTER SYNTHETIC METADATA GRANT: ", []byte("REGISTER SYNTHETIC METADATA GRANT")}}
	f.runDeliveryCLIAs(t, 0, metaAnswers, "declarative", "register")
	for _, round := range []struct {
		name, first, winner, loser, winnerDelivery, loserDelivery string
		delta                                                     int
	}{
		{"secret-wins", "secret", "secret", "metadata", "RECEIVED", "", 48},
		{"metadata-wins", "metadata", "metadata", "secret", "", "WITHHELD", 0},
	} {
		joined := true
		t.Run(round.name, func(t *testing.T) {
			f.concurrentRound(t, round.name, ref, artifacts, round.first, round.winner, round.loser, round.winnerDelivery, round.loserDelivery, round.delta, &joined)
		})
		if !joined {
			t.Fatalf("delivery race %s: helper join timed out; aborting later rounds", round.name)
		}
	}
}

func (f *deliveryFixture) concurrentRound(t *testing.T, round, ref, artifacts, first, winner, loser, winnerDelivery, loserDelivery string, delta int, joined *bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now()
	deadline := start.Add(60 * time.Second)
	sides := []string{"secret", "metadata"}
	stages := []string{"planned", "apply", "calling", "admitted", "result"}
	driverMarkers := []string{"driver.waiting", "driver.release"}
	receiptPath := filepath.Join(declarativeauthority.StatePath, "consumer-receipt")
	type reply struct {
		side, out string
		err       error
		process   deliveryProcessEvidence
		observed  bool
	}
	type transition struct {
		elapsed       int64
		event, detail string
	}
	var events []transition
	record := func(event, detail string) {
		if len(events) < 32 {
			events = append(events, transition{time.Since(start).Milliseconds(), event, detail})
		}
	}
	ch := make(chan reply, len(sides))
	var replies []reply
	returned := map[string]reply{}
	stage := map[string]string{"secret": "not_launched", "metadata": "not_launched"}
	launched := 0
	remember := func(r reply) {
		replies = append(replies, r)
		returned[r.side] = r
		record("helper_returned", r.side)
	}
	drain := func() {
		for len(replies) < launched {
			select {
			case r := <-ch:
				remember(r)
			default:
				return
			}
		}
	}
	process := func(side string) string {
		if r, ok := returned[side]; ok {
			return fmt.Sprintf("helper=returned wrapper_pid=%d wrapper_exit=%d child_pid=%d child_exit=%d", r.process.WrapperPID, r.process.WrapperExit, r.process.ChildPID, r.process.ChildExit)
		}
		status := "in_flight"
		if stage[side] == "not_launched" {
			status = "not_launched"
		}
		return fmt.Sprintf("helper=%s wrapper_pid=0 wrapper_exit=%d child_pid=0 child_exit=%d", status, deliveryUnknownExit, deliveryUnknownExit)
	}
	markerStatus := func(name string) string {
		info, err := os.Stat(filepath.Join(raceDir, name))
		if err != nil {
			return deliveryRaceErrorClass(err)
		}
		if !info.Mode().IsRegular() {
			return "not_regular"
		}
		return "regular"
	}
	baseline, expected, observed, receiptPhase := "unknown", "unknown", "unknown", "baseline"
	printedEvents := 0
	printedProcess := map[string]bool{}
	appendProcess := func(b *strings.Builder, side string) {
		if r, ok := returned[side]; ok && r.observed && !printedProcess[side] {
			fmt.Fprintln(b, strings.TrimSuffix(r.process.render(), "\n"))
			printedProcess[side] = true
		}
	}
	failureCaptured := false
	captureFailure := func(condition, detail string) {
		var snapshot strings.Builder
		if !failureCaptured {
			drain()
		}
		for _, e := range events[printedEvents:] {
			fmt.Fprintf(&snapshot, "delivery race event: round=%s elapsed_ms=%d event=%s detail=%s\n", round, e.elapsed, e.event, e.detail)
		}
		printedEvents = len(events)
		fmt.Fprintf(&snapshot, "delivery race failure: round=%s condition=%s detail=%s driver_waiting=%s driver_release=%s\n", round, condition, detail, markerStatus("driver.waiting"), markerStatus("driver.release"))
		if failureCaptured {
			t.Log("failure diagnostics:\n" + strings.TrimSuffix(snapshot.String(), "\n"))
			return
		}
		failureCaptured = true
		actual, status := "unknown", "regular"
		if info, err := os.Stat(receiptPath); err != nil {
			status = deliveryRaceErrorClass(err)
			if status == "missing" {
				actual = "0"
			}
		} else if !info.Mode().IsRegular() {
			status = "not_regular"
		} else {
			actual = fmt.Sprint(info.Size())
		}
		fmt.Fprintf(&snapshot, "delivery race receipt: round=%s phase=%s baseline_len=%s expected_len=%s observed_len=%s failure_len=%s failure_status=%s\n", round, receiptPhase, baseline, expected, observed, actual, status)
		for _, side := range sides {
			fmt.Fprintf(&snapshot, "delivery race side: round=%s phase=failure side=%s stage=%s %s", round, side, stage[side], process(side))
			for _, name := range stages {
				fmt.Fprintf(&snapshot, " %s=%s", name, markerStatus(side+"."+name))
			}
			snapshot.WriteByte('\n')
			appendProcess(&snapshot, side)
		}
		t.Log("failure diagnostics:\n" + strings.TrimSuffix(snapshot.String(), "\n"))
	}
	fail := func(condition, detail, message string) {
		t.Helper()
		captureFailure(condition, detail)
		t.Fatalf("%s (%s)", message, detail)
	}
	report := func(condition, side, message string) {
		t.Helper()
		captureFailure(condition, side)
		t.Errorf("%s (%s)", message, side)
	}
	var lock *os.File
	locked := false
	defer func() {
		if t.Failed() && !failureCaptured {
			captureFailure("unknown", "unknown")
		}
		joinDeadline := time.Now().Add(5 * time.Second)
		if testDeadline, ok := t.Deadline(); ok && testDeadline.Before(joinDeadline) {
			joinDeadline = testDeadline
		}
		cleanupFailed := false
		if launched != 0 {
			for _, name := range []string{"secret.apply", "metadata.apply", "driver.release"} {
				if err := os.WriteFile(filepath.Join(raceDir, name), []byte("release"), 0644); err != nil {
					cleanupFailed = true
				}
			}
		}
		if locked {
			if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
				cleanupFailed = true
			}
		}
		if lock != nil {
			if err := lock.Close(); err != nil {
				cleanupFailed = true
			}
		}
		if t.Failed() || cleanupFailed {
			cancel()
		}
		drain()
		if len(replies) < launched {
			timer := time.NewTimer(time.Until(joinDeadline))
			defer timer.Stop()
		join:
			for len(replies) < launched {
				select {
				case r := <-ch:
					remember(r)
				case <-timer.C:
					drain()
					break join
				}
			}
		}
		*joined = len(replies) == launched
		if !*joined {
			cancel()
			if !failureCaptured {
				captureFailure("helper_join", "timeout")
				t.Error("delivery race helper join timed out")
			}
		}
		if t.Failed() {
			joinStatus := "complete"
			if !*joined {
				joinStatus = "timeout"
			}
			cleanupStatus := "ok"
			if cleanupFailed {
				cleanupStatus = "io_error"
			}
			var b strings.Builder
			for _, side := range sides {
				fmt.Fprintf(&b, "delivery race side: round=%s phase=after_cleanup side=%s %s join=%s cleanup=%s", round, side, process(side), joinStatus, cleanupStatus)
				if r, ok := returned[side]; ok && r.observed && !printedProcess[side] {
					e := r.process
					fmt.Fprintf(&b, " pty_class=%s pty_cleanup=%s prompts_answered=%d stdout_bytes=%d terminal_bytes=%d elapsed_ms=%d",
						e.class, e.cleanup, e.prompts, e.stdoutBytes, e.terminalBytes, e.elapsedMS)
				}
				b.WriteByte('\n')
			}
			t.Log("failure diagnostics:\n" + strings.TrimSuffix(b.String(), "\n"))
		}
	}()
	waitFor := func(condition, what string, probe func() (string, bool, error)) {
		t.Helper()
		remaining := time.Until(deadline)
		if remaining <= 0 {
			if condition == "lock_acquire" {
				record("lock_acquire_failed", "deadline")
			}
			fail(condition, "deadline", "round deadline before waiting for "+what)
		}
		done, desc, err := flakediag.WaitForDesc(t, what, remaining, func() (string, bool, error) {
			if !time.Now().Before(deadline) {
				return "", false, nil
			}
			return probe()
		})
		if !done {
			if condition == "lock_acquire" {
				record("lock_acquire_failed", "deadline")
			}
			detail := "deadline"
			if desc != "" {
				detail += "_" + desc
			}
			fail(condition, detail, "round deadline waiting for "+what)
		}
		if err != nil {
			if condition == "lock_acquire" {
				record("lock_acquire_failed", err.Error())
			}
			fail(condition, err.Error(), "cannot satisfy "+what)
		}
	}
	remove := func(name string) {
		if err := os.Remove(filepath.Join(raceDir, name)); err != nil && !os.IsNotExist(err) {
			fail("marker_reset", deliveryRaceErrorClass(err), "cannot reset "+name)
		}
	}
	for _, side := range sides {
		for _, name := range stages {
			remove(side + "." + name)
		}
	}
	for _, name := range driverMarkers {
		remove(name)
	}
	var err error
	lock, err = os.OpenFile(filepath.Join(declarativeauthority.StatePath, ".lock"), os.O_RDWR, 0600)
	if err != nil {
		record("lock_open_failed", deliveryRaceErrorClass(err))
		fail("lock_open", deliveryRaceErrorClass(err), "cannot open CAS lock")
	}
	waitFor("lock_acquire", "exclusive CAS lock acquisition", func() (string, bool, error) {
		err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		switch {
		case err == nil:
			locked = true
			return "acquired", true, nil
		case errors.Is(err, syscall.EWOULDBLOCK):
			return "contended", false, nil
		case errors.Is(err, syscall.EINTR):
			return "interrupted", false, nil
		default:
			return "lock_error", true, errors.New(deliveryRaceErrorClass(err))
		}
	})
	record("lock_acquired", "cas")
	readReceiptLength := func() int {
		b, err := os.ReadFile(receiptPath)
		if err != nil && !os.IsNotExist(err) {
			observed = "unknown"
			fail("receipt_read", deliveryRaceErrorClass(err), "cannot read receipt length")
		}
		observed = fmt.Sprint(len(b))
		return len(b)
	}
	before := readReceiptLength()
	baseline = observed
	expected = fmt.Sprint(before)
	receiptPhase = "lock_held"
	observed = "unknown"
	answers := []deliveryAnswer{{"Exact canonical delivery reference: ", []byte(ref)}, {"Application-store master secret: ", []byte(f.anchor.Master)}}
	cli := f.deliveryCLI()
	for _, side := range sides {
		stage[side] = "launched"
		launched++
		record("helper_launched", side)
		go func(s string) {
			r := reply{side: s, process: deliveryProcessEvidence{WrapperExit: deliveryUnknownExit, ChildExit: deliveryUnknownExit}}
			observe := func(p deliveryProcessEvidence) { r.process, r.observed = p, true }
			harness := filepath.Join(artifacts, "harness")
			if s == "metadata" {
				r.out, r.err = cli.tryDeliveryCLIWithContext(ctx, 65534, nil, nil, observe, "declarative", "run", harness, ref, "race-metadata")
			} else {
				r.out, r.err = cli.tryDeliveryCLIWithContext(ctx, 65534, answers, nil, observe, "appstore", "unlock", harness, ref, "race-secret")
			}
			ch <- r
		}(side)
	}
	waitMarker := func(side, name, condition, what string, read bool) []byte {
		t.Helper()
		var data []byte
		waitFor(condition, what, func() (string, bool, error) {
			drain()
			status := markerStatus(name)
			if status == "regular" {
				if !read {
					return status, true, nil
				}
				var err error
				data, err = os.ReadFile(filepath.Join(raceDir, name))
				if err == nil {
					return status, true, nil
				}
				status = deliveryRaceErrorClass(err)
			}
			if status != "missing" {
				return status, true, errors.New(status)
			}
			if _, exited := returned[side]; exited {
				return status, true, errors.New("helper_returned_before_marker")
			}
			return status, false, nil
		})
		record("marker_seen", name)
		return data
	}
	var plans [2]racePlan
	for i, side := range sides {
		dec := json.NewDecoder(bytes.NewReader(waitMarker(side, side+".planned", side+"_planned", side+" plan publication", true)))
		stage[side] = "planned"
		dec.DisallowUnknownFields()
		if dec.Decode(&plans[i]) != nil {
			fail("plan_decode", side, "cannot decode planned marker")
		}
		if plans[i].PlanID == "" {
			fail("plan_id_missing", side, "planned marker has no plan ID")
		}
	}
	if plans[0].Revision != plans[1].Revision {
		fail("plan_revision_mismatch", "both", "plans did not share revision")
	}
	write := func(name string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(raceDir, name), []byte("go"), 0644); err != nil {
			fail("marker_write", deliveryRaceErrorClass(err), "cannot write "+name)
		}
		record("marker_written", name)
	}
	apply := func(side string) {
		t.Helper()
		write(side + ".apply")
		stage[side] = "apply"
		waitMarker(side, side+".calling", side+"_calling", side+" plan apply call start", true)
		stage[side] = "calling"
		waitMarker(side, side+".admitted", side+"_admitted", side+" plan apply MCP admission", false)
		stage[side] = "admitted"
	}
	apply(first)
	waitMarker(first, "driver.waiting", "driver_waiting", "first apply reaching the driver gate", false)
	stage[first] = "driver_waiting"
	if readReceiptLength() != before {
		fail("receipt_changed_under_lock", "length_mismatch", "receipt length changed while CAS lock held")
	}
	other := "secret"
	if first == "secret" {
		other = "metadata"
	}
	apply(other)
	if status := markerStatus(other + ".result"); status != "missing" {
		if status == "regular" || status == "not_regular" {
			fail("early_result", other, "other apply returned before driver release")
		}
		fail("early_result_stat", status, "cannot establish that other result is absent before release")
	}
	write("driver.release")
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
		record("lock_release_failed", deliveryRaceErrorClass(err))
		fail("lock_release", deliveryRaceErrorClass(err), "cannot release CAS lock")
	}
	locked = false
	record("lock_released", "cas")
	receiptPhase = "final"
	expected = fmt.Sprint(before + delta)
	observed = "unknown"
	waitFor("helpers_complete", "both CLI helpers returning", func() (string, bool, error) {
		drain()
		if len(replies) == launched {
			return "both_returned", true, nil
		}
		if len(replies) == 1 {
			return "one_returned", false, nil
		}
		return "none_returned", false, nil
	})
	results := map[string]raceReply{}
	for _, r := range replies {
		if r.err != nil {
			report("cli_error", r.side, "CLI helper returned an error")
			continue
		}
		if !strings.Contains(r.out, "CONCURRENT_ACCEPTANCE_OK") {
			report("harness_incomplete", r.side, "harness did not report completion")
		}
		dec := json.NewDecoder(bytes.NewReader(waitMarker(r.side, r.side+".result", r.side+"_result", r.side+" result publication", true)))
		stage[r.side] = "result"
		dec.DisallowUnknownFields()
		var got raceReply
		if dec.Decode(&got) != nil {
			report("result_decode", r.side, "cannot decode result marker")
			continue
		}
		if got.OperationID == "" {
			report("result_id_missing", r.side, "result marker has no operation ID")
			continue
		}
		results[r.side] = got
	}
	if got, ok := results[winner]; ok {
		if got.State != "SUCCEEDED" {
			record("winner_state", deliveryRaceState(got.State))
			report("winner_state", winner, "winner did not succeed")
		}
		if got.Delivery != winnerDelivery {
			record("winner_delivery", deliveryRaceDelivery(got.Delivery))
			report("winner_delivery", winner, "winner delivery did not match expectation")
		}
	}
	if got, ok := results[loser]; ok {
		if got.State != "FAILED" {
			record("loser_state", deliveryRaceState(got.State))
			report("loser_state", loser, "loser did not fail")
		}
		if got.Delivery != loserDelivery {
			record("loser_delivery", deliveryRaceDelivery(got.Delivery))
			report("loser_delivery", loser, "loser delivery did not match expectation")
		}
	}
	if readReceiptLength()-before != delta {
		fail("receipt_delta", "length_mismatch", "final receipt length did not match expectation")
	}
	if _, ok := results[winner]; !ok {
		return
	}
	var state struct {
		OperationID string `json:"operation_id"`
	}
	raw, err := os.ReadFile(filepath.Join(declarativeauthority.StatePath, "state.json"))
	if err != nil {
		fail("state_read", deliveryRaceErrorClass(err), "cannot read persisted state")
	}
	if json.Unmarshal(raw, &state) != nil {
		fail("state_decode", "invalid_json", "cannot decode persisted state")
	}
	if state.OperationID != results[winner].OperationID {
		fail("state_operation", "mismatch", "persisted state operation does not match winner")
	}
}

func deliveryRaceState(value string) string {
	switch value {
	case "SUCCEEDED", "FAILED", "UNKNOWN":
		return value
	default:
		return "invalid"
	}
}

func deliveryRaceDelivery(value string) string {
	switch value {
	case "RECEIVED", "WITHHELD", "UNKNOWN":
		return value
	case "":
		return "empty"
	default:
		return "invalid"
	}
}

func deliveryRaceErrorClass(err error) string {
	switch {
	case os.IsNotExist(err):
		return "missing"
	case os.IsPermission(err):
		return "permission_denied"
	default:
		return "io_error"
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
