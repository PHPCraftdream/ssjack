package discover

import (
	"bytes"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/application/discovery"
)

func TestReportWording(t *testing.T) {
	t.Run("exact_candidate_wording", func(t *testing.T) {
		var out bytes.Buffer
		Report(discovery.Result{Candidates: []discovery.Candidate{{Path: "services/foo", Name: "foo", Buffer: []byte("{}")}}}, &out)
		if out.String() != "Application candidate 'foo' at ./services/foo (not approved; review in --interactive)\n" {
			t.Fatalf("unexpected report: %q", out.String())
		}
	})
	t.Run("exact_collision_wording", func(t *testing.T) {
		var out bytes.Buffer
		Report(discovery.Result{Candidates: []discovery.Candidate{{Path: "services/foo", Name: "foo", Collision: true}}}, &out)
		if out.String() != "Application candidate 'foo' at ./services/foo (name conflict; not approved; review in --interactive)\n" {
			t.Fatalf("unexpected report: %q", out.String())
		}
	})
	t.Run("exact_diagnostic_and_summary_wording", func(t *testing.T) {
		var out bytes.Buffer
		Report(discovery.Result{Candidates: []discovery.Candidate{{Path: ".", Name: "root"}}, Diagnostics: []discovery.Diagnostic{{Path: "a", Reason: "descriptor_invalid"}, {Reason: "additional_rejections"}}}, &out)
		want := "Application candidate 'root' at . (not approved; review in --interactive)\nApplication candidate at ./a is invalid (descriptor_invalid; disabled)\nFurther candidate rejections were not reported individually (additional_rejections)\n"
		if out.String() != want {
			t.Fatalf("unexpected report: %q", out.String())
		}
	})
	t.Run("overflow_single_line", func(t *testing.T) {
		var out bytes.Buffer
		Report(discovery.Result{Overflow: true, OverflowReason: "candidate_cap_overflow", Candidates: []discovery.Candidate{{Name: "foo"}}, Diagnostics: []discovery.Diagnostic{{Reason: "descriptor_invalid"}}}, &out)
		if out.String() != "Application discovery overflow (candidate_cap_overflow; disabled)\n" {
			t.Fatalf("unexpected report: %q", out.String())
		}
	})
	t.Run("control_bytes_are_escaped_to_fixed_codes", func(t *testing.T) {
		var out bytes.Buffer
		Report(discovery.Result{Candidates: []discovery.Candidate{{Path: "x", Name: "bad\nname"}, {Path: "a\x01b", Name: "safe"}}}, &out)
		want := "Application candidate at ./x is invalid (candidate_name_unsafe; disabled)\nApplication candidate omitted (status_unsafe; disabled)\n"
		if out.String() != want {
			t.Fatalf("unexpected report: %q", out.String())
		}
		for _, b := range out.Bytes() {
			if b < 0x20 && b != '\n' {
				t.Fatalf("raw control byte in report: %q", out.String())
			}
		}
	})
	t.Run("post_unlock_wording", func(t *testing.T) {
		var out bytes.Buffer
		PostUnlock([]Status{{Kind: "enabled", Name: "foo", Path: "services/foo"}, {Kind: "changed", Name: "foo"}, {Kind: "absent", Name: "bar"}}, &out)
		want := "Application 'foo' approved and enabled at ./services/foo\nApplication 'foo' changed since approval; disabled until owner re-approves\nApplication 'bar' rejected/ignored; disabled\n"
		if out.String() != want {
			t.Fatalf("unexpected status: %q", out.String())
		}
	})
	t.Run("post_unlock_refusal_wording", func(t *testing.T) {
		cases := []struct {
			status Status
			want   string
		}{
			{status: Status{Kind: "overflow"}, want: "Application discovery overflow (overflow_refused; disabled)\n"},
			{status: Status{Kind: "cap_overflow_refused"}, want: "Application registration cap overflow (cap_overflow_refused; disabled)\n"},
			{status: Status{Kind: "collision_refused", Name: "foo"}, want: "Application 'foo' collision refused (collision_refused; disabled)\n"},
		}
		for _, tc := range cases {
			var out bytes.Buffer
			PostUnlock([]Status{tc.status}, &out)
			if out.String() != tc.want {
				t.Fatalf("status %#v: got %q, want %q", tc.status, out.String(), tc.want)
			}
		}
	})

	t.Run("report_loads_no_credentials", func(t *testing.T) {
		var out bytes.Buffer
		Report(discovery.Result{Candidates: []discovery.Candidate{{Path: "x", Name: "x"}}}, &out)
		if strings.TrimSpace(out.String()) != "Application candidate 'x' at ./x (not approved; review in --interactive)" {
			t.Fatalf("unexpected report: %q", out.String())
		}
	})
}
