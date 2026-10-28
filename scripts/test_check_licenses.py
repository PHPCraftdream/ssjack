import hashlib
import unittest

from check_licenses import validate


def h(text):
    return hashlib.sha256(text.encode()).hexdigest()


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.policy = {
            "modules": {"example.org/dep": {"version": "v1", "license_file": "LICENSE", "source_sha256": hashlib.sha256(b"MIT").hexdigest(), "license_sha256": h("MIT"), "source": "https://example.org/LICENSE", "source_review": "verified", "notice_heading": "Example"}},
            "toolchain": {"LICENSE": {"source_sha256": hashlib.sha256(b"Go").hexdigest(), "sha256": h("Go"), "source": "https://github.com/golang/go/blob/go1.26.0/LICENSE", "source_review": "verified", "notice_heading": "Runtime"}, "PATENTS": {"source_sha256": hashlib.sha256(b"Patent").hexdigest(), "sha256": h("Patent"), "source": "https://github.com/golang/go/blob/go1.26.0/PATENTS", "source_review": "verified", "notice_heading": "Patent"}},
            "embedded": {"LICENSE-MIT": {"kind": "file", "sha256": h("project")}},
            "factual_source_review": "verified",
            "legal_review": "required-not-asserted",
        }
        self.inventory = [{"example.org/dep": {"Version": "v1"}}]
        self.licenses = {"example.org/dep": "MIT", "toolchain:LICENSE": "Go", "toolchain:PATENTS": "Patent"}
        self.embedded = {"LICENSE-MIT": "project"}
        self.embeds = {"LICENSE-MIT"}

    def check(self, notices="## Example\n```text\nMIT\n```\n## Runtime\n```text\nGo\n```\n## Patent\n```text\nPatent\n```"):
        validate(self.inventory, notices, self.policy, self.licenses, self.embedded, self.embeds)

    def test_positive(self):
        self.check()

    def test_rejects_cross_target_version_divergence(self):
        with self.assertRaisesRegex(ValueError, "differs across target inventories"):
            validate([{"example.org/dep": {"Version": "v1"}}, {"example.org/dep": {"Version": "v2"}}], "", self.policy, self.licenses, self.embedded, self.embeds)

    def test_rejects_missing_or_changed_x_module_patents(self):
        path = "golang.org/x/crypto"
        entry = {"version": "v0.53.0", "license_file": "LICENSE", "license_sha256": h("MIT"),
                 "source_sha256": hashlib.sha256(b"MIT").hexdigest(), "source": "pinned",
                 "source_review": "verified", "notice_heading": "Go x license",
                 "patents_sha256": h("Patent"), "patents_source_sha256": hashlib.sha256(b"Patent").hexdigest(), "patents_notice_heading": "Patent notice"}
        self.policy["modules"][path] = entry
        self.inventory[0][path] = {"Version": "v0.53.0"}
        self.licenses[path] = "MIT"
        notices = "## Example\n```text\nMIT\n```\n## Runtime\n```text\nGo\n```\n## Patent\n```text\nPatent\n```\n## Go x license\n```text\nMIT\n```\n## Patent notice\n```text\nPatent\n```"
        with self.assertRaises(KeyError):
            validate(self.inventory, notices, self.policy, self.licenses, self.embedded, self.embeds)
        self.licenses[path + ":PATENTS"] = "Changed"
        with self.assertRaisesRegex(ValueError, "PATENTS digest mismatch"):
            validate(self.inventory, notices, self.policy, self.licenses, self.embedded, self.embeds)
        self.licenses[path + ":PATENTS"] = "Different Patent"
        entry["patents_sha256"] = h("Different Patent")
        entry["patents_source_sha256"] = hashlib.sha256(b"Different Patent").hexdigest()
        with self.assertRaisesRegex(ValueError, "notice heading/text pairs"):
            validate(self.inventory, notices, self.policy, self.licenses, self.embedded, self.embeds)
        changed_notices = notices.replace("## Patent notice\n```text\nPatent\n```", "## Patent notice\n```text\nDifferent Patent\n```")
        validate(self.inventory, changed_notices, self.policy, self.licenses, self.embedded, self.embeds)

    def test_x_text_patents_are_checked(self):
        path = "golang.org/x/text"
        self.policy["modules"][path] = {
            "version": "v0.38.0", "license_file": "LICENSE", "license_sha256": h("MIT"),
            "source_sha256": h("MIT"), "source": "pinned", "source_review": "verified",
            "notice_heading": "Example", "patents_sha256": h("Patent"),
            "patents_source_sha256": h("Patent"), "patents_notice_heading": "Patent"}
        self.inventory[0][path] = {"Version": "v0.38.0"}
        self.licenses[path] = "MIT"
        with self.assertRaises(KeyError):
            self.check()
        self.licenses[path + ":PATENTS"] = "Changed"
        with self.assertRaisesRegex(ValueError, "PATENTS digest mismatch"):
            self.check()
        self.licenses[path + ":PATENTS"] = "Patent"
        self.check()

    def test_rejects_inventory_version_license_and_notice_changes(self):
        self.inventory = [{"other.org/dep": {"Version": "v1"}}]
        with self.assertRaises(ValueError): self.check()
        self.inventory = [{"example.org/dep": {"Version": "v2"}}]
        with self.assertRaises(ValueError): self.check()
        self.inventory[0]["example.org/dep"]["Version"] = "v1"
        self.licenses["example.org/dep"] = "BSD"
        with self.assertRaises(ValueError): self.check()
        self.licenses["example.org/dep"] = "MIT"
        with self.assertRaises(ValueError): self.check("## Wrong\n```text\nMIT\n```\n## Runtime\n```text\nGo\n```\n## Patent\n```text\nPatent\n```")

    def test_rejects_missing_toolchain_entries_or_text(self):
        del self.policy["toolchain"]["PATENTS"]
        with self.assertRaises(ValueError): self.check()
        self.policy["toolchain"]["PATENTS"] = {"source_sha256": hashlib.sha256(b"Patent").hexdigest(), "sha256": h("Patent"), "source": "https://github.com/golang/go/blob/go1.26.0/PATENTS", "source_review": "verified", "notice_heading": "Patent"}
        self.licenses["toolchain:PATENTS"] = "Patent"
        with self.assertRaises(ValueError): self.check("## Example\n```text\nMIT\n```\n## Runtime\n```text\nGo\n```\n## Patent\n```text\nwrong\n```")

    def test_rejects_unreviewed_policy(self):
        self.policy["factual_source_review"] = "review-required"
        with self.assertRaises(ValueError): self.check()
        self.policy["factual_source_review"] = "verified"
        self.policy["legal_review"] = "approved"
        with self.assertRaises(ValueError): self.check()

    def test_rejects_unreviewed_module_source(self):
        self.policy["modules"]["example.org/dep"]["source_review"] = "review-required"
        with self.assertRaises(ValueError): self.check()

    def test_embedded_policy_fingerprints_match_every_embedded_file(self):
        from check_licenses import ROOT, digest
        policy = __import__("json").loads((ROOT / "license-policy.json").read_text(encoding="utf-8"))
        file_entries = {name: entry for name, entry in policy["embedded"].items() if entry["kind"] == "file"}
        self.assertGreaterEqual(len(file_entries), 6)
        for name, entry in file_entries.items():
            with self.subTest(name=name):
                self.assertEqual(entry["sha256"], digest((ROOT / name).read_text(encoding="utf-8")))

    def test_rejects_embedded_drift_or_inventory_change(self):
        with self.assertRaises(ValueError):
            validate(self.inventory, "", self.policy, self.licenses, self.embedded, {"unexpected"})
        self.embeds = {"unexpected"}
        with self.assertRaises(ValueError): self.check()
        self.embeds = {"LICENSE-MIT"}
        self.embedded["LICENSE-MIT"] = "changed"
        with self.assertRaises(ValueError): self.check()

if __name__ == "__main__":
    unittest.main()
