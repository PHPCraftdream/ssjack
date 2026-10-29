"""Select changed Go packages and reverse test dependencies; never run a shell."""

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import subprocess


SHARED = {"go.mod", "go.sum", "go.work", "go.work.sum", ".gitattributes"}
INSTALLERS = {"install.sh", "install.ps1", "tests/installers.sh",
              "tests/installers.ps1", "tests/installers-local.sh"}


def select(packages, changed):
    """Return local package arguments and explicit broadening reasons."""
    by_dir = {p["directory"]: p for p in packages}
    by_import = {p["import"]: p["directory"] for p in packages}
    selected, reasons = set(), set()
    installers = False
    for path in changed:
        if path in INSTALLERS or path.startswith("tests/fixtures/installbinary/"):
            installers = True
        if (path in SHARED or path.startswith(".github/")
                or path.startswith("scripts/ci/")):
            reasons.add("shared dependency or CI configuration")
            continue
        owners = {directory for directory, package in by_dir.items()
                  if path in package.get("inputs", [])}
        if owners:
            selected.update(owners)
            continue
        if path.startswith("docs/") or path.endswith(".md"):
            continue
        directory = str(PurePosixPath(path).parent)
        if path.endswith(".go") and directory in by_dir:
            selected.add(directory)
        elif path in INSTALLERS or path in {"scripts/check_licenses.py", "scripts/test_check_licenses.py"}:
            continue
        else:
            reasons.add("unmapped path: " + path)
    if reasons:
        selected = set(by_dir)
    # TestImports and XTestImports are edges too, not just production imports.
    pending = list(selected)
    reverse = {directory: set() for directory in by_dir}
    for directory, package in by_dir.items():
        for dependency in package["dependencies"]:
            target = by_import.get(dependency)
            if target is not None:
                reverse[target].add(directory)
    while pending:
        for parent in reverse[pending.pop()]:
            if parent not in selected:
                selected.add(parent)
                pending.append(parent)
    return {"packages": ["." if p == "." else "./" + p for p in sorted(selected)],
            "reasons": sorted(reasons), "installers": installers}


def decode_stream(text):
    decoder = json.JSONDecoder()
    offset = 0
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            return
        value, offset = decoder.raw_decode(text, offset)
        yield value


def graph(root):
    raw = subprocess.check_output(
        ["go", "list", "-mod=readonly", "-json", "./..."], text=True)
    result = []
    for package in decode_stream(raw):
        directory = Path(package["Dir"]).resolve().relative_to(root).as_posix()
        inputs = [str(PurePosixPath(directory) / name)
                  for field in ("EmbedFiles", "TestEmbedFiles", "XTestEmbedFiles")
                  for name in package.get(field, [])]
        result.append({"directory": directory, "import": package["ImportPath"],
                       "inputs": inputs,
                       "dependencies": package.get("Imports", [])
                       + package.get("TestImports", [])
                       + package.get("XTestImports", [])})
    if not result:
        raise RuntimeError("empty Go package graph")
    return result


def changes(base, head):
    if not base or set(base) == {"0"}:
        return [".github/unknown-base"]
    raw = subprocess.check_output(
        ["git", "diff", "--name-only", "--no-renames", "-z", base, head, "--"])
    return [p.decode("utf-8", errors="strict") for p in raw.split(b"\0") if p]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["plan", "test"])
    parser.add_argument("--base", default="")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    if args.mode == "plan":
        root = Path(subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"], text=True).strip()).resolve()
        plan = select(graph(root), changes(args.base, args.head))
        output.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(plan, indent=2))
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
                stream.write("installers=" + str(plan["installers"]).lower() + "\n")
    else:
        plan = json.loads(output.read_text(encoding="utf-8"))
        packages = plan["packages"]
        if not packages:
            print("No impacted Go packages")
            return
        for package in packages:
            if package != "." and not package.startswith("./"):
                raise ValueError("nonlocal Go package argument")
        files = [str(p) for package in packages
                 for p in sorted(Path(package).glob("*.go"))]
        for offset in range(0, len(files), 40):
            formatted = subprocess.check_output(
                ["gofmt", "-l"] + files[offset:offset + 40], text=True)
            if formatted:
                raise RuntimeError("Go formatting differs:\n" + formatted)
        command = ["go", "test", "-mod=readonly", "-count=1", "-timeout=180s"]
        if os.environ.get("RUNNER_OS") == "Linux":
            command.append("-race")
        subprocess.run(command + packages, check=True)


if __name__ == "__main__":
    main()
