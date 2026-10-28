#!/usr/bin/env python3
"""Audit release-target Go dependency license and shipped embed policy."""
import hashlib
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / "license-policy.json").read_text(encoding="utf-8"))
TARGETS = (("linux", "amd64"), ("linux", "arm64"), ("darwin", "amd64"),
           ("darwin", "arm64"), ("windows", "amd64"), ("windows", "arm64"))
X_MODULES = ("golang.org/x/crypto", "golang.org/x/sys", "golang.org/x/term", "golang.org/x/text")


def digest(text):
    """Hash notice text after newline and boundary normalization."""
    return hashlib.sha256(text.replace("\r\n", "\n").strip().encode()).hexdigest()


def source_digest(text):
    """Hash exact decoded upstream file bytes (UTF-8)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def validate(inventories, notices, policy, license_texts, embedded_texts, embed_files):
    if policy.get("factual_source_review") != "verified":
        raise ValueError("factual source review is incomplete")
    if policy.get("legal_review") != "required-not-asserted":
        raise ValueError("legal review status must remain explicit and unasserted")
    if set(policy["toolchain"]) != {"LICENSE", "PATENTS"}:
        raise ValueError("toolchain policy must explicitly include LICENSE and PATENTS")
    for name, entry in policy["toolchain"].items():
        if entry.get("source") != f"https://github.com/golang/go/blob/go1.26.0/{name}":
            raise ValueError(f"toolchain source does not match pinned Go release: {name}")
    actual = {}
    for inv in inventories:
        for path, module in inv.items():
            version = module["Version"]
            if path in actual and actual[path] != version:
                raise ValueError(f"dependency version differs across target inventories: {path}")
            actual[path] = version
    expected = {p: e["version"] for p, e in policy["modules"].items()}
    if actual != expected:
        raise ValueError("dependency inventory differs from exact policy")
    expected_blocks = []
    for path, entry in policy["modules"].items():
        if entry.get("source_review") != "verified" or not entry.get("source"):
            raise ValueError(f"dependency source review is incomplete: {path}")
        text = license_texts[path]
        if digest(text) != entry["license_sha256"]:
            raise ValueError(f"dependency notice digest mismatch: {path}")
        if source_digest(text) != entry["source_sha256"]:
            raise ValueError(f"dependency source digest mismatch: {path}")
        expected_blocks.append((entry["notice_heading"], text.replace("\r\n", "\n").strip()))
        if path in X_MODULES:
            patent = license_texts[path + ":PATENTS"]
            if source_digest(patent) != entry["patents_source_sha256"] or digest(patent) != entry["patents_sha256"]:
                raise ValueError(f"dependency PATENTS digest mismatch: {path}")
            expected_blocks.append((entry["patents_notice_heading"], patent.replace("\r\n", "\n").strip()))
    for name, entry in policy["toolchain"].items():
        if entry.get("source_review") != "verified" or not entry.get("source"):
            raise ValueError(f"toolchain source review is incomplete: {name}")
        text = license_texts["toolchain:" + name]
        if digest(text) != entry["sha256"]:
            raise ValueError(f"toolchain notice digest mismatch: {name}")
        if source_digest(text) != entry["source_sha256"]:
            raise ValueError(f"toolchain source digest mismatch: {name}")
        expected_blocks.append((entry["notice_heading"], text.replace("\r\n", "\n").strip()))
    actual_blocks = []
    current, heading, inside = [], None, False
    for line in notices.splitlines():
        if line.startswith("## ") and not inside:
            heading = line[3:]
        elif line == "```text":
            if inside or heading is None:
                raise ValueError("invalid notice fence placement")
            current, inside = [], True
        elif line == "```" and inside:
            actual_blocks.append((heading, "\n".join(current).strip()))
            inside = False
        elif inside:
            current.append(line)
    if inside or sorted(actual_blocks) != sorted(set(expected_blocks)):
        raise ValueError("notice heading/text pairs do not match policy components")
    expected_embeds = {n for n, e in policy["embedded"].items() if e["kind"] in ("file", "notice")}
    if set(embed_files) != expected_embeds:
        raise ValueError("Go embed inventory differs from explicit shipped-component policy")
    for name, entry in policy["embedded"].items():
        if entry["kind"] == "notice":
            if name != "THIRD_PARTY_NOTICES.md":
                raise ValueError("unknown dynamic notice component")
            continue
        if digest(embedded_texts[name]) != entry["sha256"]:
            raise ValueError(f"embedded component digest mismatch: {name}")


def main():
    inventories, licenses, embeds = [], {}, set()
    for goos, goarch in TARGETS:
        env = dict(os.environ, GOOS=goos, GOARCH=goarch, CGO_ENABLED="0")
        raw = subprocess.run(["go", "list", "-mod=readonly", "-deps", "-json", "./cmd/ssjack", "./plugins/ssjack-ui"], cwd=ROOT, env=env, check=True, text=True, stdout=subprocess.PIPE).stdout
        decoder, inventory, target_versions = json.JSONDecoder(), {}, {}
        while raw.strip():
            raw = raw.lstrip()
            item, end = decoder.raw_decode(raw)
            raw = raw[end:]
            embeds.update(str((pathlib.Path(item["Dir"]) / asset).resolve().relative_to(ROOT.resolve()).as_posix())
                          for asset in item.get("EmbedFiles", []) if item.get("Module", {}).get("Main"))
            mod = item.get("Module")
            if mod and not mod.get("Main"):
                path, version = mod["Path"], mod["Version"]
                if path in target_versions and target_versions[path] != version:
                    raise ValueError(f"dependency version differs within target inventory: {path}")
                target_versions[path] = version
                inventory[path] = mod
                entry = POLICY["modules"].get(path)
                if entry:
                    licenses[path] = (pathlib.Path(mod["Dir"]) / entry["license_file"]).read_bytes().decode("utf-8")
                    if path in X_MODULES:
                        licenses[path + ":PATENTS"] = (pathlib.Path(mod["Dir"]) / "PATENTS").read_bytes().decode("utf-8")
        inventories.append(inventory)
    root = pathlib.Path(subprocess.run(["go", "env", "GOROOT"], cwd=ROOT, check=True, text=True, stdout=subprocess.PIPE).stdout.strip())
    for name in POLICY["toolchain"]:
        licenses["toolchain:" + name] = (root / name).read_bytes().decode("utf-8")
    embedded = {n: (ROOT / n).read_text(encoding="utf-8") for n, e in POLICY["embedded"].items() if e["kind"] == "file"}
    validate(inventories, (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8"), POLICY, licenses, embedded, embeds)


if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, ValueError, subprocess.CalledProcessError) as exc:
        sys.exit(f"license audit failed closed: {exc}")
