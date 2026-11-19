#!/usr/bin/env python3
"""Shared KDF seam overlay helper for ssjack #457."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
MASTER = ROOT / "internal" / "appstorecrypto" / "masterkey" / "master.go"

# The only place the real seam key is stored. Never print or pass it through
# environment variables or command-line arguments.
REAL_KEY = "ssjack-kdf-seam-a41f572d9a6590834bb7131d0881cddb"
REAL_KEY_DIGEST = hashlib.sha256(REAL_KEY.encode()).hexdigest()

PLACEHOLDER = "ssjack-kdf-seam-key-placeholder"
EXPECTED_KEY_LINE = f'const kdfSeamKey = "{PLACEHOLDER}"'
EXPECTED_PLACEHOLDER_LINE = f'const kdfSeamPlaceholder = "{PLACEHOLDER}"'
EXPECTED_SEAM_KEY_LINE = f'const kdfSeamKey = "{REAL_KEY}"'
KEY_DECLARATION_PATTERN = r'^const kdfSeamKey = "[^"]*"$'
PLACEHOLDER_DECLARATION_PATTERN = r'^const kdfSeamPlaceholder = "[^"]*"$'
DIGEST_DECLARATION_PATTERN = r'^const kdfSeamDigest = "([0-9a-f]{64})"$'

# Byte-for-byte Argon2 body and its fast replacement.
OLD = '''func argonDerive(password, salt []byte) []byte {
\tpart := argon2.IDKey(password, salt, 1, 1048576, 1, 32)
\truntime.GC()
\treturn part
}'''
NEW = '''func argonDerive(password, salt []byte) []byte {
\tinput := append(append([]byte(nil), password...), salt...)
\tsum := sha256.Sum256(input)
\tclear(input)
\truntime.KeepAlive(argon2.IDKey)
\treturn append([]byte(nil), sum[:]...)
}'''

VARIANTS = ("test", "scoped-test", "scoped-build")


def _fail(message: str) -> None:
    raise SystemExit(message)


def _declaration(source: str, pattern: str, name: str) -> str:
    matches = re.findall(pattern, source, flags=re.MULTILINE)
    if len(matches) != 1:
        _fail(f"expected exactly one {name} declaration in {MASTER.name}")
    return matches[0]


def _verify_digest(source: str) -> None:
    digest = _declaration(source, DIGEST_DECLARATION_PATTERN, "KDF seam digest")
    if digest != REAL_KEY_DIGEST:
        _fail("KDF seam digest mismatch; refusing to apply overlay")


def _require_ci_environment() -> Path:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        _fail("overlay generation requires GITHUB_ACTIONS=true")
    raw = os.environ.get("RUNNER_TEMP", "")
    if not raw:
        _fail("overlay generation requires RUNNER_TEMP")
    runner_temp = Path(raw)
    if not runner_temp.is_absolute():
        _fail("RUNNER_TEMP must point to an existing absolute directory")
    resolved = runner_temp.resolve()
    if not resolved.is_dir():
        _fail("RUNNER_TEMP must point to an existing absolute directory")
    try:
        resolved.relative_to(ROOT)
    except ValueError:
        pass
    else:
        _fail("RUNNER_TEMP must point outside the repository")
    return resolved


def patched_source(source: str, variant: str) -> str:
    """Return the source for `variant`, replacing only the intended lines."""
    if variant not in VARIANTS:
        _fail("unrecognized overlay variant")
    _verify_digest(source)
    key_line = _declaration(source, KEY_DECLARATION_PATTERN, "KDF seam key")
    placeholder_line = _declaration(
        source, PLACEHOLDER_DECLARATION_PATTERN, "KDF seam placeholder"
    )
    if key_line != EXPECTED_KEY_LINE or placeholder_line != EXPECTED_PLACEHOLDER_LINE:
        _fail("KDF seam declarations must hold the placeholder values")
    patched = source
    if variant in ("test", "scoped-test"):
        # Substitute the anchored declaration line only, never an earlier
        # substring match such as a comment mentioning the placeholder.
        patched = re.sub(
            KEY_DECLARATION_PATTERN,
            lambda _: EXPECTED_SEAM_KEY_LINE,
            patched,
            count=1,
            flags=re.MULTILINE,
        )
    if variant in ("scoped-test", "scoped-build"):
        if source.count(OLD) != 1:
            _fail("expected exactly one existing argonDerive body")
        patched = patched.replace(OLD, NEW, 1)
    return patched


def _overlay_files(variant: str, runner_temp: Path):
    source = MASTER.read_text(encoding="utf-8")
    patched = patched_source(source, variant)
    directory = Path(tempfile.mkdtemp(prefix="ssjack-kdfseam-", dir=str(runner_temp)))
    overlay_source = directory / "master.go"
    overlay_source.write_text(patched, encoding="utf-8")
    overlay = directory / "overlay.json"
    overlay.write_text(
        json.dumps(
            {"Replace": {str(MASTER.resolve()): str(overlay_source.resolve())}}
        ),
        encoding="utf-8",
    )
    return overlay, directory


@contextmanager
def temporary_overlay(variant: str = "test"):
    """Yield the absolute overlay JSON Path, cleaning unique files when done."""
    runner_temp = _require_ci_environment()
    overlay, directory = _overlay_files(variant, runner_temp)
    try:
        yield overlay
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def _emit(line: str) -> None:
    """Write one LF-terminated line; native Windows text mode would add a CR
    that bash command substitution keeps."""
    raw = getattr(sys.stdout, "buffer", None)
    if raw is None:
        sys.stdout.write(line + "
")
        return
    sys.stdout.flush()
    raw.write((line + "
").encode("utf-8"))
    raw.flush()


def main() -> int:
    variant = sys.argv[1] if len(sys.argv) > 1 else "test"
    if variant not in VARIANTS:
        _fail("unrecognized overlay variant")
    runner_temp = _require_ci_environment()
    # The overlay must persist for the subsequent go test -overlay step.
    overlay, _ = _overlay_files(variant, runner_temp)
    _emit(overlay.as_posix())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
