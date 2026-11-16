"""The plugin from the command line (the platform app asks the same hooks from its page):

    python -m plugin_platform_ebpf status
    python -m plugin_platform_ebpf compare
    python -m plugin_platform_ebpf functions
    python -m plugin_platform_ebpf watch KINDS... [--seconds N] [--pid PID] [--address ADDRESS]

status (the default) reads this machine's eBPF runtime and prints the plugin's status as JSON, exiting 1 when the
runtime is not there (on Linux bpftool did not answer; on Windows eBPF for Windows is not installed). compare and
functions print those tabs' pages (JSON). watch starts a watch of those kinds (net, process and file; registry on
Windows) through the plugin's watch service, prints its events as they come and stops it: on Ctrl+C, after --seconds,
or when it ends by itself, saying why. --pid follows one process's file opens (Linux: a pid as the kernel numbers it,
which inside a WSL distribution is not the one ps shows there), --address names the adapter a Windows net watch reads
(else this machine's way out). On Linux a watch needs bpftrace through sudo -n (never a password), the platform root or
not; on Windows Npcap and ETW."""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime

from liminal_libs.machines.plugin import CommandError

from . import MACHINE, libs_too_old

POLL_S = 1.0  # how often a watch is read


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m plugin_platform_ebpf",
                                description="This machine's eBPF: its runtime, the comparison, the basic functions, a "
                                            "watch")
    sub = p.add_subparsers(dest="what")
    sub.add_parser("status", help="the plugin's status as the platform's page reads it (JSON)")
    sub.add_parser("compare", help="the Compare tab's page: eBPF on Linux and on Windows (JSON)")
    sub.add_parser("functions", help="the Functions tab's page: the basic functions and their forms (JSON)")
    w = sub.add_parser("watch", help="a watch of these kinds, its events printed as they come")
    w.add_argument("kinds", nargs="+", help="net, process, file (and registry on Windows)")
    w.add_argument("--seconds", type=float, default=0.0, help="stop after this long (else Ctrl+C stops it)")
    w.add_argument("--pid", type=int, help="the process whose file opens are followed (Linux), as the kernel numbers "
                                           "it: inside a WSL distribution not the pid ps shows there, but one an "
                                           "event showed")
    w.add_argument("--address", help="the address of the adapter a Windows net watch reads")
    return p


def stamp(at) -> str:
    """An event's wall time as this machine's local time, to the millisecond."""
    if not isinstance(at, (int, float)) or isinstance(at, bool):
        return "--:--:--.---"
    try:
        return datetime.fromtimestamp(at).strftime("%H:%M:%S.%f")[:-3]
    except (OSError, OverflowError, ValueError):
        return "--:--:--.---"


def event_line(e: dict) -> str:
    """One event as a line: when, its kind and action, the process, and its path or its addresses."""
    who = str(e.get("program") or "")
    if e.get("pid") is not None:
        who = f"{who}[{e['pid']}]" if who else f"pid {e['pid']}"
    where = str(e.get("path") or "") or " -> ".join(str(x) for x in (e.get("local"), e.get("remote")) if x)
    extra = e.get("extra") if isinstance(e.get("extra"), dict) else {}
    tail = f"({extra['count']} held back)" if "count" in extra else f"{e['bytes']} bytes" if e.get("bytes") else ""
    return "  ".join(x for x in (stamp(e.get("at")), f"{e.get('kind')} {e.get('action')}", str(e.get("proto") or ""),
                                 who, where, tail) if x)


def watch(m, kinds, spec: dict, seconds: float) -> int:
    """A watch started, its events printed as they come, and stopped: 0 when it was stopped here, 1 when it ended by
    itself with why (bpftrace missing, sudo asking for a password, Npcap or ETW not open here)."""
    started = m.watch_start(list(kinds), spec or None)
    wid = started["id"]
    at = f" at {started['address']}" if started.get("address") else ""
    until = f" for {seconds:g} s" if seconds > 0 else "; Ctrl+C stops it"
    print(f"watching {', '.join(started['kinds'])} on {started['system']}{at}{until}", file=sys.stderr)
    deadline = time.monotonic() + seconds if seconds > 0 else None
    since, ended = 0, ""
    try:
        while True:
            got = m.watch_read(wid, since)
            for e in got["events"]:
                print(event_line(e), flush=True)
            since = got["seq"]
            if got["stopped"]:
                ended = got["error"] or "it stopped by itself"
                break
            if deadline is not None and time.monotonic() >= deadline:
                break
            time.sleep(POLL_S if deadline is None else max(0.0, min(POLL_S, deadline - time.monotonic())))
    except KeyboardInterrupt:
        pass
    finally:
        m.watch_stop(wid)
    if ended:
        print(f"the watch ended: {ended}", file=sys.stderr)
        return 1 if got.get("error") else 0
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(list(sys.argv[1:] if argv is None else argv) or ["status"])
    too_old = libs_too_old()
    if too_old:  # nothing is read or run on an older library
        print(too_old, file=sys.stderr)
        return 1
    m = MACHINE
    try:
        if args.what in ("status", "compare", "functions"):
            m.read()
            page = getattr(m, args.what)()
            print(json.dumps(page, indent=1))
            return 1 if args.what == "status" and not page.get("present") else 0
        if args.what == "watch":
            spec = {k: v for k, v in (("pid", args.pid), ("address", args.address)) if v is not None}
            return watch(m, args.kinds, spec, args.seconds)
    except (CommandError, ValueError, LookupError) as e:
        print(str(e), file=sys.stderr)
        return 1
    parser().print_usage(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
