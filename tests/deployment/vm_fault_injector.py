#!/usr/bin/env python3
"""Inject a process kill or forced reboot at a v1.6 transaction checkpoint.

Run only as root inside a disposable Ubuntu test VM. This helper is not shipped
in the release package and refuses to watch any install root except the
standard disposable-test path.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import selectors
import signal
import stat
import struct
import sys
import time
from pathlib import Path


INSTALL_ROOT = Path("/opt/jellyfin-proxy")
JOURNAL_NAME = ".update-transaction.json"
INSTALL_CHECKPOINT = Path("/opt/.jellyfin-proxy.install-checkpoint.json")
RESTORE_JOURNAL = Path("/opt/jellyfin-proxy/.restore-transaction.json")
JOURNAL_EVENT_MASK = 0x00000002 | 0x00000008 | 0x00000080 | 0x00000100
EVENT_HEADER = struct.Struct("iIII")
VALID_STAGES = {
    "prepared",
    "stopping",
    "replacing",
    "starting",
    "verifying",
    "committing",
}
VALID_OPERATIONS = {
    "install": {"preparing", "ready", "complete"},
    "restore": {"prepared", "stopping", "replacing"},
    "update": VALID_STAGES,
}


def journal_state(path: Path, state_key: str = "state") -> str | None:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            return None
        with path.open("r", encoding="utf-8") as source:
            value = json.load(source)
        state = value.get(state_key)
        return state if isinstance(state, str) else None
    except (FileNotFoundError, PermissionError, OSError, json.JSONDecodeError):
        return None


def transaction_process_pid(operation: str) -> int | None:
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal() or int(entry.name) == os.getpid():
            continue
        try:
            if (entry / "comm").read_text(encoding="ascii").strip() != "proxyctl":
                continue
            argv = (entry / "cmdline").read_bytes().split(b"\0")
            if len(argv) > 1 and argv[1] == operation.encode("ascii"):
                return int(entry.name)
        except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
            continue
    return None


def process_stopped(pid: int) -> bool:
    try:
        status = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        return False
    for line in status.splitlines():
        if line.startswith("State:"):
            return line.split()[1] in {"T", "t"}
    return False


def write_marker(target: str, action: str, pid: int | None) -> None:
    path = Path("/var/tmp/jp-v16-fault-injection.log")
    line = f"{time.time_ns()} stage={target} action={action} pid={pid or 'n/a'}\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, line.encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage")
    parser.add_argument("action", choices=("kill", "reboot"))
    parser.add_argument("--operation", choices=sorted(VALID_OPERATIONS), default="update")
    parser.add_argument("--timeout", type=float, default=300.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.stage not in VALID_OPERATIONS[args.operation]:
        print(f"Stage {args.stage!r} is not valid for {args.operation}.", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("Run this test helper with sudo inside a disposable Ubuntu VM.", file=sys.stderr)
        return 2
    if INSTALL_ROOT.resolve() != Path("/opt/jellyfin-proxy"):
        print("Refusing an unexpected installation root.", file=sys.stderr)
        return 2
    if args.timeout <= 0 or args.timeout > 1800:
        print("Timeout must be between 0 and 1800 seconds.", file=sys.stderr)
        return 2

    libc = ctypes.CDLL(None, use_errno=True)
    init_inotify = getattr(libc, "inotify_init1", None)
    add_watch = getattr(libc, "inotify_add_watch", None)
    if init_inotify is None or add_watch is None:
        print("Linux inotify is required for precise stage injection.", file=sys.stderr)
        return 2
    init_inotify.argtypes = [ctypes.c_int]
    init_inotify.restype = ctypes.c_int
    add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    add_watch.restype = ctypes.c_int

    fd = init_inotify(os.O_CLOEXEC | os.O_NONBLOCK)
    if fd < 0:
        error = ctypes.get_errno()
        print(f"inotify_init1 failed: {os.strerror(error)}", file=sys.stderr)
        return 2
    try:
        watch_dir = INSTALL_CHECKPOINT.parent if args.operation == "install" else INSTALL_ROOT
        watch = add_watch(fd, os.fsencode(watch_dir), JOURNAL_EVENT_MASK)
        if watch < 0:
            error = ctypes.get_errno()
            print(f"Could not watch transaction directory: {os.strerror(error)}", file=sys.stderr)
            return 2

        deadline = time.monotonic() + args.timeout
        if args.operation == "install":
            journal = INSTALL_CHECKPOINT
            state_key = "phase"
        elif args.operation == "restore":
            journal = RESTORE_JOURNAL
            state_key = "state"
        else:
            journal = INSTALL_ROOT / JOURNAL_NAME
            state_key = "state"
        selector = selectors.DefaultSelector()
        selector.register(fd, selectors.EVENT_READ)
        pid = None
        next_process_scan = 0.0
        while time.monotonic() < deadline:
            now = time.monotonic()
            if pid is None and now >= next_process_scan:
                pid = transaction_process_pid(args.operation)
                next_process_scan = now + 0.01

            if journal_state(journal, state_key) == args.stage:
                if pid is None:
                    pid = transaction_process_pid(args.operation)
                if pid is None:
                    print("Target state appeared, but proxyctl update was not found.", file=sys.stderr)
                    return 1
                try:
                    os.kill(pid, signal.SIGKILL if args.action == "kill" else signal.SIGSTOP)
                except ProcessLookupError:
                    print("proxyctl update exited before fault injection.", file=sys.stderr)
                    return 1
                if args.action == "reboot":
                    stop_deadline = time.monotonic() + 1.0
                    while time.monotonic() < stop_deadline and not process_stopped(pid):
                        time.sleep(0.001)
                    if not process_stopped(pid):
                        print("proxyctl update did not stop before forced reboot.", file=sys.stderr)
                        return 1
                write_marker(args.stage, args.action, pid)
                print(f"Injected {args.action} at update stage {args.stage} (pid {pid}).", flush=True)
                if args.action == "reboot":
                    os.execl("/sbin/reboot", "reboot", "-f")
                return 0

            events = selector.select(timeout=0.0001)
            for key, _ in events:
                try:
                    while os.read(key.fd, 65536):
                        pass
                except BlockingIOError:
                    pass
        print(f"Timed out waiting for update stage {args.stage}.", file=sys.stderr)
        return 1
    finally:
        os.close(fd)


if __name__ == "__main__":
    raise SystemExit(main())
