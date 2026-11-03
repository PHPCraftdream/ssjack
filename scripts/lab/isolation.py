#!/usr/bin/env python3
"""Fail closed unless the disposable container matches the documented boundary."""
import os
import re
import resource
import stat
import sys

CAPS = (1 << 0) | (1 << 1) | (1 << 3) | (1 << 5) | (1 << 6) | (1 << 7)

CHECK = 0

def require(value):
    global CHECK
    CHECK += 1
    if not value:
        raise RuntimeError("isolation check")

def main():
    require(os.geteuid() == 0 and os.getpid() == 1 and len(sys.argv) == 1)
    require(resource.getrlimit(resource.RLIMIT_CORE)[0] == 0)
    status = open("/proc/self/status", encoding="ascii").read()
    fields = dict(re.findall(r"^(CapEff|NoNewPrivs|Seccomp):\s*([0-9a-fA-F]+)$", status, re.M))
    require(int(fields.get("CapEff", "0"), 16) == CAPS)
    require(fields.get("NoNewPrivs") == "1" and fields.get("Seccomp") == "2")
    require(os.stat("/proc/self/ns/pid").st_ino == os.stat("/proc/1/ns/pid").st_ino)
    require(open("/sys/fs/cgroup/memory.swap.max", encoding="ascii").read().strip() == "0")
    require(open("/sys/fs/cgroup/memory.swap.current", encoding="ascii").read().strip() == "0")
    require(os.statvfs("/sys/fs/cgroup").f_flag & os.ST_RDONLY != 0)
    require(sorted(os.listdir("/sys/class/net")) == ["lo"])
    mountinfo = open("/proc/self/mountinfo", encoding="ascii").read()
    require("docker.sock" not in mountinfo and "/lab" not in mountinfo)
    expected = {"PATH", "LANG", "LC_ALL", "GITHUB_SHA", "GITHUB_RUN_ID"}
    require(set(os.environ) == expected)
    require(os.environ["PATH"] == "/usr/local/bin:/usr/bin:/bin")
    require(os.environ["LANG"] == "C.UTF-8" and os.environ["LC_ALL"] == "C.UTF-8")
    require(re.fullmatch(r"[a-f0-9]{40}", os.environ["GITHUB_SHA"]) is not None)
    require(re.fullmatch(r"[0-9]+", os.environ["GITHUB_RUN_ID"]) is not None)
    for path in ("/lab/ssjack", "/lab/conductor", "/lab/driver", "/lab/consumer", "/lab/harness", "/lab/delivery_pty.py"):
        entry = os.lstat(path)
        valid = stat.S_ISREG(entry.st_mode) and entry.st_uid == 0 and entry.st_mode & 0o022 == 0
        if not valid:
            os.write(2, f"standalone-lab: artifact uid={entry.st_uid} mode={entry.st_mode & 0o7777:o} regular={int(stat.S_ISREG(entry.st_mode))}\n".encode("ascii"))
        require(valid)
    for path in ("/etc/ssjack", "/var/lib/ssjack", "/usr/libexec/ssjack-synthetic-driver", "/usr/libexec/ssjack-synthetic-consumer"):
        require(not os.path.lexists(path))
    fd = os.open("/lab/isolation-ok", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    os.close(fd)
    environment = {"PATH": os.environ["PATH"], "LANG": os.environ["LANG"], "LC_ALL": os.environ["LC_ALL"],
                   "GITHUB_SHA": os.environ["GITHUB_SHA"], "GITHUB_RUN_ID": os.environ["GITHUB_RUN_ID"]}
    os.execve("/lab/conductor", ["/lab/conductor"], environment)

if __name__ == "__main__":
    try:
        main()
    except Exception:
        os.write(2, f"standalone-lab: isolation failed check={CHECK}\n".encode("ascii"))
        raise SystemExit(1)
