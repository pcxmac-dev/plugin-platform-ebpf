"""eBPF for Liminal (the user, 2026-11-14: "we need an ebpf api plugin, that shows the difference between windows and
linux capabilities as well as basic functionality"; "trap door uses the ebpf API" / "plugin"; 2026-11-15: "wsl and
firewall linux should always work under linux, if wsl prevents or misses some capability this should reflect in the
plugin"): this machine's eBPF runtime, read and shown; eBPF on Linux and on Windows compared, point by point; the basic
functions, each change confirmed; and the watch service the firewalls' Filter tabs and trapdoor ask through the
platform. The library's eBPF layer (liminal_libs.ebpf, machines/etw.py) reads and drives the runtime; this plugin says
what it read, asks the risky changes twice, and holds the watches.

- The runtime, by the system the platform runs on: on Linux the kernel's own (ebpf.LinuxRuntime: bpftool's JSON and a
  few /proc and /sys files, root through sudo -n, never a password), a WSL distribution the platform runs inside
  included; on Windows eBPF for Windows (ebpf.WindowsRuntime: its three services and its version, and whether a
  test-signed driver can load here: Secure Boot, memory integrity, test signing). Read on a thread and kept READ_S, so
  the platform's page, which asks the status every 30 s, waits on nothing; Read again reads it at once. A one-shot
  command's attach reads nothing (the platform's rule); its status reads for itself.
- Root's rights on Linux are read from each command the plugin runs, never from one check: `sudo -n true` says whether
  sudo runs any command without a password; the listing is asked whenever bpftool answered (a sudoers rule may let
  bpftool alone run without one, and a refusal comes back in sudo's words); the watch's own command, sudo -n bpftrace
  -V, says whether a watch can run (the library runs bpftrace through sudo, the platform root or not), with the kernel
  functions its scripts' kprobes need looked for in /proc/kallsyms. Under WSL 1 nothing more is asked: no Linux kernel.
- Valid wherever it serves anything, and it serves everywhere: the comparison needs nothing of the machine, and the
  watch needs only its backend. Whether the runtime is there, and why it cannot load, are facts on the page, never a
  reason to be invalid: the platform detaches a plugin that is not valid, and its tabs and its watch service would go
  with it. present(), which the platform's tray asks, agrees: True wherever the plugin serves. The one place it does
  not: a liminal-libs older than its floor (LIBS_FLOOR, libs_too_old), which the platform's folder loader does not
  check; there the status says which library it needs, and no hook reads or runs anything.
- Compare (a tab): the library's comparison (ebpf.CAPABILITIES: 65 points in 12 areas, read 2026-11-14), Linux beside
  Windows, each point's source under its name (apis.SOURCES), this machine's column marked by what the machine is
  (neither on macOS, or under WSL 1), and a Here column only where this machine's status read something, each naming
  the read it came from.
- Functions (a tab): the nine basic functions, how each is done on each system and the rights it needs, and the forms
  of those offered here: show a program and dump a map (reads); load, attach, detach and unload (changes, each
  confirmed; a load, the unload of a pin that is not Liminal's, and an XDP, cgroup or overwriting attach asked twice).
  What the last read says cannot run here is disabled, with why. On Windows every change is refused in words: eBPF for
  Windows' public builds are all test-signed, and Windows loads those only in test-signing mode, which needs Secure
  Boot off. Under WSL 1 every function is.
- Inside WSL (liminal-libs 1.57.0 or newer): the Linux runtime applies, and Main ends with an Under WSL table of the
  plugin's own, from the library's machines.linux.wsl, wsl_generation and systemd_runs (reached through getattr; never
  wsl_table, whose rows are the firewalls' and the admin plugins'): what WSL changes or lacks for eBPF. A platform on
  Windows never reaches into a WSL distribution.
- The watch service (watch_service.py; the user, 2026-11-14: "the filter allows (uses ebpf) tracking one off
  connections"; "trapdoor will monitor all processes"): watch_start, watch_read and watch_stop, asked through the
  platform with the arguments as one list (self.app.ask("ebpf", "watch_read", [watch_id, since])) and never drawn on
  the page. A watch of its own for each caller, at most 8 at once, each stopping itself 20 s after its last read; the
  detach stops every one and starts none until the plugin is attached again. On Windows, at the plugin's first attach
  on the platform, the ETW sessions a killed platform left are stopped (etw.reclaim_stale_sessions); a capture or an
  ETW session lost after it opened ends its watch, said in the watch's error (liminal-libs 1.60.0).
- Who may ask (0.1.2, the sweep after the review's PLT-H1; liminal-libs 1.66.0's apps/asking.py): the four changes
  only from the page (PAGE_ONLY_HOOKS: another plugin's ask is refused, and liminal-platform 0.34.0 asks its login
  whether you are at the page), the watch service only by another plugin through the platform (PLUGIN_ONLY_HOOKS:
  never from a page or by a program over HTTP). Before, any program on this PC asked either with two headers: where
  sudo runs bpftool without a password, a program loaded into the kernel as root, its second confirmation being only
  an argument; on any machine, a watch started and every process, connection and file open read. Since 0.1.3 its two
  reads as root, show_program and dump, are page-only too (the user's choice of 2026-11-25), and since 0.1.4 Read
  again (refresh), which reads the runtime as root as well (the user, 2026-11-26: "Page-only"). The status and the
  tabs are asked by anyone, and the command line calls the code itself. Since 0.1.5 a status or a tab another plugin
  asks starts no read (the read that runs sudo -n is started for its page alone) and holds no programs, maps or links
  table: what the last read listed as root is its page's.
- What it attaches to (plugin API 2.2; the user, 2026-11-11: "each plugin should reflect the the API its attached to,
  and present links that provide documentation"): apis.py's cards; `api_facts` says what the last read and the watch
  service learned, asking nothing.

    python -m plugin_platform_ebpf status | compare | functions | watch KINDS...
"""
from __future__ import annotations

import functools
import json
import math
import os
import platform as py_platform
import re
import sys
import threading
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone

import liminal_libs
from liminal_libs import capture
from liminal_libs.apps.tabs import Tab
from liminal_libs.ebpf import capabilities
from liminal_libs.ebpf.linux import (BPF_FS, CGROUP_FLAGS, DUMP_LIMIT, NET_KINDS, PIN_PREFIX, PROG_KINDS, LinuxRuntime,
                                     default_pin, in_bpf_fs, liminal_pin)
from liminal_libs.ebpf.watch import SCRIPTS, SCRIPTS_DIR, make_watch
from liminal_libs.ebpf.windows import TEST_SIGNED, WindowsRuntime
from liminal_libs.machines import etw, linux
from liminal_libs.machines.linux import Shell
from liminal_libs.machines.plugin import CommandError, MachinePlugin
from liminal_libs.machines.windows import is_elevated

try:  # who asks a hook, handed over in so many words (liminal-libs 1.66.0's apps/asking.py)
    from liminal_libs.apps import asking
except ImportError:  # an older library hands no one over: every ask is its page's, as before
    asking = None

from .apis import APIS, BPFTOOL, BPFTRACE, EBPF_WINDOWS, ETW, KERNEL, NPCAP, SOURCES, VERIFIED
from .watch_service import WatchService

__version__ = "0.1.5"
SYSTEMS = ("linux", "windows")
READ_S = 60.0  # the runtime read again once its read is this old (the platform asks the status every 30 s)
FIRST_WAIT_S = 8.0  # how long a status, or a tab, waits for the first read
READER = "ebpf-read"  # the reading thread's name
# what a status another plugin asks says in place of the programs, maps and links (0.1.5)
LISTS_WORDS = ("the programs, maps and links are listed on its page alone (read as root through sudo -n on Linux), "
               "and only its page starts a read")
OBJECTS = ("programs", "maps", "links")  # what the runtime lists, in its order
BPFTOOL_OBJECTS = {"programs": "prog", "maps": "map", "links": "link"}  # bpftool's word for each
ROWS = 200  # programs, maps or links listed at most in a table
LINES = 200  # lines a show or a dump answers with at most (all it read is in its own key beside them)
SHOWN = 300  # characters of one value in such a line
MAX_ID = 2 ** 32 - 1  # an eBPF object's id is the kernel's u32
XDP_KINDS = tuple(k for k in NET_KINDS if k.startswith("xdp"))  # an attach on them is asked twice
SOCKMAP_KINDS = tuple(k for k in PROG_KINDS if k.startswith("sk_"))  # attached with the sockmap's id
CGROUP_KINDS = (  # the cgroup hooks the attach form offers (bpftool cgroup attach); the hook takes any plain word
    "ingress", "egress", "sock_create", "sock_release", "sock_ops", "device", "bind4", "bind6", "post_bind4",
    "post_bind6", "connect4", "connect6", "getpeername4", "getpeername6", "getsockname4", "getsockname6", "sendmsg4",
    "sendmsg6", "recvmsg4", "recvmsg6", "sysctl", "getsockopt", "setsockopt")
KIND_NOTES = {  # bpftool-net(8)'s words for its attach types, and what the others go on
    "xdp": "XDP: the driver's own where it has one, else generic",
    "xdpgeneric": "generic XDP: once the packet is in the kernel's receive path",
    "xdpdrv": "native XDP: at the earliest point of the driver's receive path",
    "xdpoffload": "XDP run on the network card itself",
    "tcx_ingress": "tcx, on what comes in",
    "tcx_egress": "tcx, on what goes out",
    "sk_msg_verdict": "a sockmap's messages (its map id)",
    "sk_skb_verdict": "a sockmap's packets (its map id)",
    "sk_skb_stream_verdict": "a sockmap's stream (its map id)",
    "sk_skb_stream_parser": "a sockmap's stream parser (its map id)",
    "flow_dissector": "this network namespace's flow dissector",
}
SERVICE_ROLES = {"eBPFCore": "the core (a kernel driver)", "NetEbpfExt": "the network hooks (a kernel driver)",
                 "eBPFSvc": "the service that lets a native program attach"}
ROOT = "as root, through sudo -n (never a password)"
DETACHED = "the eBPF plugin was detached: no watch is started until it is attached again"
OWN_PIN = f"{BPF_FS}/{PIN_PREFIX}program"  # a pin of Liminal's own, as the forms show one
WORD = re.compile(r"[a-z][a-z0-9_]*")  # bpftool's keywords, as the library takes them
DEVICE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,14}")  # a Linux interface name, never one read as an option
WSL_NOTE = ("A WSL distribution's Linux eBPF is the eBPF plugin's on the platform that runs inside it: this platform "
            "does not reach into WSL.")
# what the watch's own command answers: the library's BpftraceWatch runs bpftrace through sudo -n, the platform root
# or not, so readiness is read from that, not from `sudo -n true` or bpftrace on the platform's user's path
WATCH_PROBE = ("sudo", "-n", "bpftrace", "-V")
KPROBE = re.compile(r"(?m)^\s*k(?:ret)?probe:([A-Za-z_][A-Za-z0-9_]*)")  # a kprobe a watch script attaches
KALLSYMS = "/proc/kallsyms"  # the kernel's functions, world-readable: where a kprobe's function is looked for
NO_KERNEL = "WSL 1 has no Linux kernel, so no eBPF"
MOUNTS_ITSELF = ("bpftool mounts it there first, as root (it stays mounted until it is unmounted or the machine "
                 "restarts)")
NETSH_DUMP = ("the plugin reads eBPF for Windows through netsh, which lists maps but cannot read one's entries (its "
              "bpftool port can)")
LIBS_FLOOR = "1.60.0"  # pyproject's floor, checked by the plugin itself (libs_too_old)
LOST_SAID = ("a capture or an ETW session lost after it opened (an adapter removed, a session stopped from outside) "
             "ends the watch, its error in the source's own words, and its caller can start another")
# Where test signing was read (liminal-libs 1.60.0's `test_signing_source`), as a page names that read
SIGNING_FROM = {"boot options": r"the registry (SystemStartOptions: this boot's start options)",
                "bcdedit": "bcdedit /enum {current}"}
SIGNING_UNREAD = "this boot's start options, then bcdedit /enum {current}: neither answered"


# -- words and cells ----------------------------------------------------------------------------------------------

def cell(text, sub=None):
    """A table cell: its text, with `sub` under it in small type when there is one."""
    return {"text": text, "sub": sub} if sub else text


def point(text):
    """A comparison's cell as the page draws it (its cells draw no line breaks): its first line, and the lines after
    it under it in small type, joined by " · ", a list item's "- " dropped."""
    lines = [ln.strip() for ln in str(text or "").splitlines() if ln.strip()]
    lines = [ln[2:].strip() if ln.startswith("- ") else ln for ln in lines]
    if not lines:
        return "–"
    return cell(lines[0], " · ".join(lines[1:]) or None)


def when(seconds) -> str:
    """A time (seconds since 1970) as this machine's local time; in UTC where it cannot be localized."""
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not math.isfinite(seconds) or seconds <= 0:
        return "–"
    try:
        return datetime.fromtimestamp(seconds).astimezone().strftime("%b %d %H:%M:%S")
    except (OSError, OverflowError, ValueError):
        try:
            return datetime.fromtimestamp(seconds, timezone.utc).strftime("%b %d %H:%M:%S UTC")
        except (OSError, OverflowError, ValueError):
            return "–"


def plural(n: int, one: str, many: str = "") -> str:
    return f"{n:,} {one if n == 1 else many or one + 's'}"


def shown(value) -> str:
    """A value as a refusal shows it back: short."""
    try:
        said = repr(value)
    except Exception:  # noqa: BLE001 - a value that cannot say itself
        said = type(value).__name__
    return said if len(said) <= 60 else said[:59] + "…"


def blank(value) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def plain(value, depth: int = 0):
    """`value` as plain JSON, whatever a tool printed: a number that is no number (NaN, infinity) is null, a set a
    sorted list, bytes text, a key text; anything else, or deeper than 8, said as text."""
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if depth >= 8:
        return str(value)
    if isinstance(value, dict):
        return {str(k): plain(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(v, depth + 1) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted((plain(v, depth + 1) for v in value), key=lambda v: (type(v).__name__, str(v)))
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    return str(value)


def compact(value) -> str:
    """A value in a line: text as it is, anything else as compact JSON, cut to SHOWN characters."""
    text = value if isinstance(value, str) else json.dumps(plain(value), separators=(",", ":"), ensure_ascii=False)
    return text if len(text) <= SHOWN else text[:SHOWN - 1] + "…"


def output_lines(text) -> list[str]:
    """A command's output as the lines an answer shows (LINES at most)."""
    return [line.rstrip() for line in str(text or "").splitlines() if line.strip()][:LINES]


# -- what a change is asked with, checked before it is asked twice --------------------------------------------------

def whole(value, what: str, low: int = 0, high: int = MAX_ID) -> int:
    """A whole number as a form or a command line gives it (5, 5.0, "5"), from `low` to `high`; ValueError, in
    words, for anything else."""
    n = value
    if isinstance(n, float) and math.isfinite(n) and n.is_integer():
        n = int(n)
    elif isinstance(n, str) and n.strip().isascii() and n.strip().isdigit():
        n = int(n.strip())
    if isinstance(n, bool) or not isinstance(n, int) or not low <= n <= high:
        raise ValueError(f"{what} is a whole number from {low:,} to {high:,}, not {shown(value)}")
    return n


def optional_whole(value, what: str) -> int | None:
    return None if blank(value) else whole(value, what)


def word(value, what: str) -> str:
    """bpftool's keyword (an attach type, a program type, a flag): lower-case letters, digits and _, as the library
    takes it."""
    text = str(value if value is not None else "").strip().lower()
    if not WORD.fullmatch(text):
        raise ValueError(f"{what} is a plain word of letters, digits and _, not {shown(value)}")
    return text


def pin_of(value, what: str = "a pin") -> str:
    """A pin: a plain path under the BPF filesystem (/sys/fs/bpf/...), with no `..` (commands run as root)."""
    if blank(value):
        raise ValueError(f"say which pin: {what} is a path under {BPF_FS}/")
    text = str(value).strip()
    if not in_bpf_fs(text):
        raise ValueError(f"{what} is a plain path under {BPF_FS}/, with no '..', not {shown(value)}")
    return text


def program_path(value) -> str:
    """A program file's full path on this machine (it starts with /, so bpftool never reads it as an option)."""
    text = str(value if value is not None else "").strip()
    if not text.startswith("/") or len(text) > 4096 or any(ord(c) < 32 for c in text):
        raise ValueError(f"a program file is named by its full path on this machine (/home/you/program.o), not "
                         f"{shown(value)}")
    return text


def device(value) -> str:
    """A network device's name, as an XDP or tcx attach goes on one."""
    text = str(value if value is not None else "").strip()
    if not DEVICE.fullmatch(text):
        raise ValueError(f"an XDP or tcx attach goes on a network device (eth0, wlan0 and the like), not "
                         f"{shown(value)}")
    return text


def cgroup_folder(value) -> str:
    """A cgroup v2 folder under /sys/fs/cgroup, as a cgroup attach goes on one."""
    text = str(value if value is not None else "").strip()
    parts = text.split("/")
    if (not (text == "/sys/fs/cgroup" or text.startswith("/sys/fs/cgroup/")) or ".." in parts
            or any(c.isspace() or ord(c) < 32 for c in text)):
        raise ValueError(f"a cgroup attach goes on a cgroup v2 folder under /sys/fs/cgroup, not {shown(value)}")
    return text.rstrip("/") or "/sys/fs/cgroup"


def flag_of(value) -> str | None:
    if blank(value):
        return None
    flag = word(value, "the cgroup attach flag")
    if flag not in CGROUP_FLAGS:
        raise ValueError(f"the cgroup attach flag is {' or '.join(CGROUP_FLAGS)}, not {shown(value)}")
    return flag


def yes_no(value, what: str) -> bool:
    """Yes or no as a form (yes, no), the command line or a caller (true, false) says it; none is no."""
    if value is None or value is False or value is True:
        return bool(value)
    text = str(value).strip().lower()
    if text in ("", "no", "false", "off", "0"):
        return False
    if text in ("yes", "true", "on", "1"):
        return True
    raise ValueError(f"{what} is yes or no, not {shown(value)}")


def which_program(pin, prog_id) -> tuple[str | None, int | None]:
    """The program an attach or a detach names: by its pin or by its id, one of them."""
    if not blank(pin) and not blank(prog_id):
        raise ValueError("say which program one way: its pin or its id, not both")
    if not blank(pin):
        return pin_of(pin, "the program's pin"), None
    if not blank(prog_id):
        return None, whole(prog_id, "a program's id")
    raise ValueError(f"say which program: its pin (a path under {BPF_FS}/) or its id")


class RiskRefused(ValueError):
    """A change asked twice, refused until it is accepted in so many words: `accept` names the argument that, exactly
    true, makes it (the platform's page asks a second time, the accept field's words with it, and sends the form again
    with that argument true; firewall-windows' RiskRefused). The page's way of asking twice, not a right: whoever
    asks, the change still needs root, through sudo -n."""

    def __init__(self, message: str, accept: str):
        super().__init__(message)
        self.accept = accept


# -- what the machine says, in words ------------------------------------------------------------------------------

def unprivileged_words(value) -> tuple[str, str]:
    return {0: ("0: allowed", "a user without CAP_BPF may load socket filters and cgroup skb programs"),
            1: ("1: off until the next boot", "only a user with CAP_BPF (root) loads programs, and it cannot be "
                "allowed again before a restart"),
            2: ("2: off", "only a user with CAP_BPF (root) loads programs; root may allow it again")}.get(
        value, (str(value) if value is not None else "not read", ""))


def jit_words(value) -> tuple[str, str]:
    return {0: ("0: off", "programs run in the kernel's interpreter"),
            1: ("1: on", "programs are compiled to this machine's code as they load"),
            2: ("2: on, with traces", "compiled, the compiler's traces written to the kernel's log")}.get(
        value, (str(value) if value is not None else "not read", ""))


def btf_words(present) -> tuple[str, str]:
    if present:
        return "yes", "CO-RE programs, fentry and LSM can use it"
    return "no", "CO-RE programs, fentry and LSM need it"


def bpffs_words(mounts) -> tuple[str, str]:
    """Where the BPF filesystem is mounted (/proc/mounts), and what that means for a load: bpftool mounts it at
    /sys/fs/bpf itself when a pin goes there and it is not mounted there (bpftool's own rule, unless --nomount)."""
    mounts = [str(m) for m in mounts or ()]
    if BPF_FS in mounts:
        return f"mounted at {BPF_FS}", "pins live there"
    if mounts:
        return f"mounted at {', '.join(mounts)}", f"not at {BPF_FS}, where a load pins its program: {MOUNTS_ITSELF}"
    return "not mounted", f"a load pins its program under {BPF_FS}: {MOUNTS_ITSELF}"


def wsl1(w: dict | None) -> bool:
    """Whether the WSL distribution read is WSL 1's: no Linux kernel, so no eBPF."""
    return bool(w) and w.get("generation") == 1


def ubuntu(w: dict | None) -> bool:
    """Whether /etc/os-release, as read, says Ubuntu or a distribution like it (ID, ID_LIKE)."""
    return bool(w) and "ubuntu" in (w.get("ids") or ())


def microsofts(release) -> bool:
    """Whether a kernel's release names Microsoft (WSL 2's own kernel, ...-microsoft-standard-WSL2)."""
    return "microsoft" in str(release or "").lower()


def bpftool_words(s: dict, wsl: dict | None) -> tuple[str, str]:
    """bpftool as `bpftool -j version` answered (as the platform's user, then through sudo -n), and what to do where it
    did not, for this Linux as read: WSL 1 has no kernel for it; Ubuntu's bpftool command (linux-tools-common's) wants a
    build for the running kernel, which Ubuntu has not made for a WSL kernel; elsewhere the distribution's package."""
    if s.get("present"):
        libbpf = f"libbpf {s['libbpf']}" if s.get("libbpf") else ""
        features = ", ".join(str(f) for f in s.get("features") or ())
        if wsl1(wsl):
            return str(s.get("bpftool") or "answered"), f"{NO_KERNEL}: bpftool has nothing to list or load here"
        return str(s.get("bpftool") or "answered"), "; ".join(
            x for x in (libbpf, f"built with {features}" if features else "") if x)
    if wsl1(wsl):
        return "did not answer", f"{NO_KERNEL}: no bpftool lists or loads anything here"
    if wsl and ubuntu(wsl):
        kernel = str(s.get("kernel") or "")
        if microsofts(kernel):
            head, none = "under WSL the kernel is Microsoft's", "there is none for Microsoft's"
        else:
            head = f"under WSL this kernel{f' ({kernel})' if kernel else ''} is not Ubuntu's"
            none = "there is none for a kernel Ubuntu did not build"
        return "did not answer", (f"{head}: on Ubuntu the bpftool command is linux-tools-common's, which wants a build "
                                  f"for the running kernel, and {none}; a bpftool built from its own source works with "
                                  "any kernel")
    return "did not answer", "it is not installed here: the distribution's bpftool package"


def bpftrace_words(s: dict, snap: "Snapshot | None" = None) -> tuple[str, str]:
    """bpftrace as `bpftrace -V` answered as the platform's user; the watch runs it through sudo -n, which the watch's
    own row says."""
    w = snap.wsl if snap is not None else None
    if s.get("bpftrace_present"):
        return str(s.get("bpftrace") or "installed"), (
            f"{NO_KERNEL}: the watch cannot run here" if wsl1(w) else
            "on the platform's user's path; the watch runs it through sudo -n (its own row says whether that answers)")
    if wsl1(w):
        return "not found", f"{NO_KERNEL}: the watch cannot run here, bpftrace installed or not"
    if snap is not None and snap.watch == "yes":
        return "on root's path only", ("the platform's user finds none, but sudo -n bpftrace -V answered: the watch "
                                       "runs it")
    return "not found", "bpftrace -V did not answer as the platform's user: the distribution's bpftrace package"


def root_words(snap: "Snapshot") -> tuple[str, str]:
    """Root's rights as read: the platform is root (its user id), or what `sudo -n true` answered. That says whether
    sudo runs any command without a password; a command it lets run alone (a least-privilege sudoers rule) says so
    itself, in the listings and the watch."""
    if wsl1(snap.wsl):
        return "not asked", f"{NO_KERNEL}: nothing here needs root"
    return {"root": ("the platform is root", "bpftool, sh and rm run as root as they are, with no sudo; the watch's "
                     "bpftrace goes through sudo -n all the same (the library's)"),
            "yes": ("sudo -n true runs without a password", "sudo runs any command as root here without one: what "
                    "needs root goes through sudo -n"),
            "password": ("sudo -n true asks for a password", "a command runs as root only where sudoers lets the "
                         "platform's user run it without one (NOPASSWD): the listings and the watch say what each was "
                         "given; a dump runs sh and an unload rm, as root"),
            "no": ("sudo could not run", snap.sudo_words)}.get(snap.sudo, ("not asked", ""))


def sudo_said(said: str) -> str:
    """sudo's own words out of the library's Shell refusal ("... (sudo: a password is required)"), else all of it."""
    return said[said.rfind("(") + 1:-1] if said.endswith(")") and "(" in said else said


def root_source(snap: "Snapshot") -> str:
    """Where root_words was read from: this process's user id when the platform is root, else sudo -n true."""
    if snap.sudo == "root":
        return "this process's user id (os.geteuid)"
    return "sudo -n true" if snap.sudo else "nothing: not asked"


def linux_watch_words(snap: "Snapshot") -> tuple[str, str]:
    """Whether the watch can run here, from what its own command answered (sudo -n bpftrace -V, as the library's
    BpftraceWatch runs it), and the kernel functions its scripts' kprobes need that this kernel lacks
    (/proc/kallsyms)."""
    if wsl1(snap.wsl):
        return "cannot run here", NO_KERNEL
    if snap.watch == "yes":
        means = (f"sudo -n bpftrace -V answered ({snap.watch_words}): a watch runs while a Filter tab or trapdoor "
                 "reads it, and stops itself 20 s after the last read")
        for kind, functions in (snap.lacking or {}).items():
            means += (f"; a watch with {kind} ends at its start here: the library's {kind} script probes "
                      f"{' and '.join(functions)}, which this kernel does not have ({KALLSYMS})")
        return "bpftrace, through sudo -n", means
    if snap.watch == "password":
        return "cannot run here", (f"sudo -n bpftrace -V was refused ({snap.watch_words}): the watch runs bpftrace "
                                   "through sudo -n, so it runs once sudo lets the platform's user run bpftrace "
                                   "without a password")
    if snap.watch == "missing":
        return "cannot run here", (f"sudo -n bpftrace -V: {snap.watch_words}: the watch runs bpftrace through sudo, "
                                   "whose path must hold it (the distribution's bpftrace package)")
    if snap.watch == "no":
        return "cannot run here", (f"sudo -n bpftrace -V: {snap.watch_words}: the watch runs bpftrace through sudo, "
                                   "so it needs sudo here, the platform root or not")
    return "not known", "its command (sudo -n bpftrace -V) was not asked"


def wsl_name(w: dict) -> str:
    """The WSL distribution's name, as WSL gives it, else as /etc/os-release does."""
    name = str(w.get("name") or "")
    return name if name and name != "WSL" else str(w.get("os") or "a WSL distribution")


def wsl_own_name(w: dict) -> str:
    """The WSL distribution's name as WSL itself knows it (WSL_DISTRO_NAME), quoted for a wsl.exe command; "<its
    name>" where WSL gave none (/etc/os-release's name is not one wsl.exe takes)."""
    name = str(w.get("name") or "")
    return f'"{name}"' if name and name != "WSL" else '"<its name>"'


def secure_boot_words(facts: dict, elevated: bool) -> tuple[str, str]:
    sb = facts.get("secure_boot")
    source = facts.get("secure_boot_source")
    where = ("the firmware (Confirm-SecureBootUEFI)" if source == "firmware" else
             r"the registry (SecureBoot\State UEFISecureBootEnabled)" + (
                 "; the firmware's own answer needs an administrator" if not elevated else "")
             if source == "registry" else "neither the firmware nor the registry answered")
    return ("on" if sb is True else "off" if sb is False else "not read"), where


def hvci_words(facts: dict) -> tuple[str, str]:
    hvci = facts.get("hvci")
    if hvci is True:
        return "on", "so the JIT cannot run, and only signed native drivers load"
    return ("off", "") if hvci is False else ("not read", "")


def release_of(version) -> tuple[int, ...]:
    """A release's number as a tuple ("1.60.0" -> (1, 60, 0)), what follows its digits (a suffix) left out."""
    parts: list[int] = []
    for piece in str(version or "").split("."):
        digits = re.match(r"\d+", piece)
        if not digits:
            break
        parts.append(int(digits.group()))
        if digits.group() != piece:
            break
    return tuple(parts)


def libs_too_old(version=None) -> str:
    """Why the liminal-libs here is older than the plugin's floor (LIBS_FLOOR, pyproject's), in words, or "" when it
    is new enough. The platform loads a plugin from its folder whatever its floor says, so the plugin checks its own:
    an older library's facts would be worded as 1.60.0's (where test signing was read, a lost Windows source said)."""
    if version is None:
        version = getattr(liminal_libs, "__version__", "")
    version = str(version or "")
    if version and release_of(version) >= release_of(LIBS_FLOOR):
        return ""
    return (f"this plugin needs liminal-libs {LIBS_FLOOR} or newer, and this is "
            + (version if version else "a liminal-libs that does not say its version"))


def signing_from(facts: dict) -> str:
    """Where test signing was read, as a page names that read, or "" when it was not read. liminal-libs 1.60.0 reads
    this boot's start options, which any user may read, else bcdedit when it answered, and names which; a read naming
    neither is no read."""
    if facts.get("test_signing") is None or not facts.get("test_signing_readable"):
        return ""
    return SIGNING_FROM.get(str(facts.get("test_signing_source") or ""), "")


def signing_words(facts: dict) -> str:
    """Test signing as it was read, elevated or not; "not read" with why where it was not."""
    if not signing_from(facts):
        return "not read: neither this boot's start options nor bcdedit answered"
    return "on" if facts.get("test_signing") is True else "off"


def verdict_words(facts: dict) -> tuple[str, str]:
    """Whether a test-signed driver can load here, from Secure Boot, memory integrity and test signing as read."""
    sb, hvci = facts.get("secure_boot"), facts.get("hvci")
    signing = facts.get("test_signing") if signing_from(facts) else None
    if sb is True and signing is not True:
        return ("no: the test-signed runtime cannot load here", "Secure Boot is on, and Windows loads a test-signed "
                "driver only in test-signing mode, which needs Secure Boot off")
    if signing is True:
        return (("yes, as native .sys programs only", "test signing is on; memory integrity is on, so no JIT")
                if hvci is True else ("yes", "test signing is on, so a test-signed driver can load"))
    if sb is False:
        if signing is False:
            return ("not as it is: test signing is off", "with Secure Boot off it can be turned on: bcdedit -set "
                    "TESTSIGNING ON, as an administrator, then a restart")
        return "not known", "Secure Boot is off; test signing could not be read"
    return "not known", "Secure Boot could not be read"


def windows_backend() -> dict:
    """What the Windows watch needs, read without opening anything (no Npcap loaded, no ETW session started): whether
    Npcap's wpcap.dll is there, whether Npcap was installed for administrators only and whether this process is one
    (the library's capture.npcap_admin_only and capture.administrator), and whether an ETW real-time session may
    start here (etw.available: this process's token)."""
    out = {"npcap": False, "admin_only": False, "administrator": False, "etw": False, "etw_why": ""}
    folder = getattr(capture, "NPCAP", "")
    try:
        out["npcap"] = bool(folder) and os.path.isfile(os.path.join(folder, "wpcap.dll"))
    except (OSError, ValueError):
        pass
    for key, name in (("admin_only", "npcap_admin_only"), ("administrator", "administrator")):
        read = getattr(capture, name, None)
        try:
            out[key] = bool(read()) if callable(read) else False
        except Exception:  # noqa: BLE001 - a fact that cannot be read is no
            out[key] = False
    available = getattr(etw, "available", None)
    try:
        ok, why = available() if callable(available) else (False, "the library has no ETW check")
        out["etw"], out["etw_why"] = bool(ok), str(why)
    except Exception as e:  # noqa: BLE001 - said as it is
        out["etw_why"] = f"ETW could not be asked: {e}"
    return out


def os_release() -> str:
    """This Linux's name as /etc/os-release gives it (PRETTY_NAME), "" where it cannot be read."""
    try:
        info = py_platform.freedesktop_os_release()
    except (OSError, AttributeError):
        return ""
    return str(info.get("PRETTY_NAME") or info.get("NAME") or "")


def os_ids() -> tuple[str, ...]:
    """What /etc/os-release says this Linux is, and is like (ID, then ID_LIKE's words: "ubuntu", "debian"), lower
    case; () where it cannot be read."""
    try:
        info = py_platform.freedesktop_os_release()
    except (OSError, AttributeError):
        return ()
    words = [str(info.get("ID") or ""), *str(info.get("ID_LIKE") or "").split()]
    return tuple(dict.fromkeys(w.strip().lower() for w in words if w.strip()))


def wsl_facts(release: str | None = None) -> dict | None:
    """The WSL distribution this Linux is, from the library's machines.linux.wsl, wsl_generation and systemd_runs
    (liminal-libs 1.57.0, reached through getattr: an older library has none, and the page no Under WSL table):
    {name, generation, systemd, os, ids}, `ids` what /etc/os-release says it is (os_ids); None on a Linux of its own,
    off Linux, and where the library cannot say. Read only: nothing is run."""
    name_of = getattr(linux, "wsl", None)
    if not callable(name_of):
        return None
    try:
        name = str(name_of(release) or "")
    except Exception:  # noqa: BLE001 - a check that cannot say: nothing said
        return None
    if not name:
        return None
    generation_of, systemd_of = getattr(linux, "wsl_generation", None), getattr(linux, "systemd_runs", None)
    try:
        generation = int(generation_of(release)) if callable(generation_of) else 0
    except Exception:  # noqa: BLE001
        generation = 0
    try:
        systemd = bool(systemd_of()) if callable(systemd_of) else None
    except Exception:  # noqa: BLE001
        systemd = None
    return {"name": name, "generation": generation, "systemd": systemd, "os": os_release() if name == "WSL" else "",
            "ids": os_ids()}


def script_kprobes() -> dict[str, tuple[str, ...]]:
    """The kernel functions each of the library's watch scripts attaches a kprobe to, read from the scripts themselves
    (liminal_libs.ebpf.watch's SCRIPTS): {kind: (function, ...)}, only the kinds with any. A kprobe on a function the
    kernel lacks keeps bpftrace from starting, and the library joins every kind's script into one program. Read only."""
    out: dict[str, tuple[str, ...]] = {}
    for kind, name in SCRIPTS.items():
        try:
            text = (SCRIPTS_DIR / name).read_text(encoding="utf-8")
        except OSError:
            continue
        found = tuple(dict.fromkeys(KPROBE.findall(text)))  # a comment line starts with //, never with kprobe:
        if found:
            out[kind] = found
    return out


# -- the read -----------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Snapshot:
    """What one read of the runtime found: when (`at`, on the plugin's clock; `wall`, seconds since 1970) and how
    long it took; the runtime's own status; for Windows, why_not_here's facts, whether the read ran as an
    administrator and what the Windows watch needs (windows_backend); the programs, maps and links read (`objects`, by
    name) and why any was not (`unread`). For Linux: which listings were asked (`listed`, bpftool as root) and whether
    one was refused for its rights (`refused`); what `sudo -n true` answered (`sudo`: root, yes, password, no; "" when
    not asked) with its words; what the watch's own command answered (`watch`: yes, password, missing, no; "" when not
    asked: sudo -n bpftrace -V) with its words; the kernel functions the watch scripts' kprobes need that this kernel
    lacks (`lacking`, by kind; None when not read); and the WSL distribution it is (`wsl`). `error`, why the read
    failed."""
    at: float
    wall: float
    took: float
    system: str
    status: dict = field(default_factory=dict)
    facts: dict | None = None
    elevated: bool = False
    backend: dict | None = None
    objects: dict = field(default_factory=dict)
    unread: dict = field(default_factory=dict)
    listed: tuple = ()
    refused: bool = False
    sudo: str = ""
    sudo_words: str = ""
    watch: str = ""
    watch_words: str = ""
    lacking: dict | None = None
    wsl: dict | None = None
    error: str = ""

    @property
    def installed(self) -> bool:
        """Windows: whether eBPF for Windows is installed (any of its three services is there)."""
        return bool(self.status.get("installed") or self.status.get("present"))


def not_installed(snap: Snapshot | None) -> bool:
    """Windows: whether a read found eBPF for Windows not installed (its three services read, none there); False when
    that is not known (no read yet, a read that failed)."""
    return bool(snap is not None and not snap.error and snap.status.get("services") and not snap.installed)


def _listed(runtime) -> tuple[dict, dict, tuple, bool]:
    """The programs, maps and links, each read on its own (bpftool -j, as root): what was listed, why any was not,
    which were asked, and whether one was refused for its rights, which stops the rest (they need the same)."""
    objects: dict = {}
    unread: dict = {}
    asked: list[str] = []
    for i, name in enumerate(OBJECTS):
        asked.append(name)
        try:
            objects[name] = tuple(plain(r) for r in getattr(runtime, name)())
        except CommandError as e:
            unread[name] = str(e)
            if e.denied:
                unread.update(dict.fromkeys(OBJECTS[i + 1:], str(e)))
                return objects, unread, tuple(asked), True
    return objects, unread, tuple(asked), False


def for_its_page() -> bool:
    """Whether the ask being answered is its page's (0.1.5; Liminal's complete review, item 14's P2-2): asked from the
    page (asking.PAGE) or naming no one. Another plugin's ask is not: the MCP plugin's, for an agent you granted this
    status, or any plugin's through the app. Such an ask of the status or a tab starts no read of the runtime (the read
    that runs sudo -n on Linux: Read again is the page's, the user, 2026-11-26: "Page-only") and is answered without
    the programs, maps and links that read listed. An ask that names no one is the page's: liminal-platform 0.42.1
    draws the plugin's page from GET /api/machines/ebpf, which asks the status naming no one, and the platform's own
    attach reads so too, so the page cannot be told from it here until the platform names its page there."""
    who = asking.asker() if asking is not None else None
    return who is None or who == asking.PAGE


@dataclass
class _Runtime:
    """What the plugin keeps while it lives, shared by its copies (the registry hands out a shallow one): the last
    read and its thread, the watch service, whether the plugin was detached, and whether the ETW sessions a killed
    platform left were reclaimed."""
    service: WatchService
    lock: threading.Lock = field(default_factory=threading.Lock)
    snap: Snapshot | None = None
    reader: threading.Thread | None = None
    detached: bool = False
    reclaimed: bool = False


# -- the forms ----------------------------------------------------------------------------------------------------

def _choices(kinds, first=()) -> list[dict]:
    return [*first, *({"value": k, "title": k, "note": KIND_NOTES.get(k, "a cgroup hook")} for k in kinds)]


def forms() -> list[dict]:
    """The Functions tab's forms (Main's rows open them too), each asking its hook with the hook's arguments in order:
    show a program and dump a map (reads: asked once filled); load, attach, detach and unload (changes, each
    confirmed, and asked a second time where the hook refuses with an `accept`)."""
    net, sockmap = list(NET_KINDS), list(SOCKMAP_KINDS)
    targeted = [*NET_KINDS, *CGROUP_KINDS]
    every = [*NET_KINDS, *PROG_KINDS, *CGROUP_KINDS]
    return [
        {"id": "show", "hook": "show_program", "title": "Show a program", "confirm": False, "submit": "Show",
         "note": "A loaded program by its id, every field of it: bpftool -j prog show id, as root.",
         "fields": [{"name": "prog_id", "label": "Program id", "type": "number", "min": 0, "required": True,
                     "note": "the Id of a row of Main's Programs table"}]},
        {"id": "dump", "hook": "dump", "title": "Dump a map", "confirm": False, "submit": "Dump",
         "note": "A map's first entries (a map can hold millions): bpftool -j map dump id, as root.",
         "fields": [{"name": "map_id", "label": "Map id", "type": "number", "min": 0, "required": True,
                     "note": "the Id of a row of Main's Maps table"},
                    {"name": "limit", "label": "Entries at most", "type": "number", "min": 1, "max": DUMP_LIMIT,
                     "value": DUMP_LIMIT}]},
        {"id": "load", "hook": "load_program", "title": "Load a program", "submit": "Review",
         "note": ("A pre-built program (an ELF .o, made with clang -target bpf) loaded into this machine's kernel and "
                  f"pinned: bpftool prog load, {ROOT}. Where the BPF filesystem is not mounted at {BPF_FS}, "
                  f"{MOUNTS_ITSELF}. Always asked twice."),
         "fields": [{"name": "path", "label": "Program file", "type": "text", "required": True,
                     "placeholder": "/home/you/program.o", "note": "its full path on this machine"},
                    {"name": "pin", "label": "Pinned at", "type": "text", "placeholder": OWN_PIN,
                     "empty": f"{BPF_FS}/{PIN_PREFIX}<the file's name>",
                     "note": f"a path under {BPF_FS}; Liminal's own begin {PIN_PREFIX}"},
                    {"name": "type", "label": "Program type", "type": "text", "placeholder": "xdp",
                     "empty": "as the file's sections say",
                     "note": "bpftool's word for it, when its sections do not say"},
                    {"name": "accept_load", "type": "accept", "title": "Load it into the kernel?", "yes": "Load it",
                     "words": ("A loaded program runs inside the kernel, as root's, until it is unloaded or the "
                               "machine restarts; the kernel's verifier checks it first.")}],
         "confirm": {"title": "Load {path}?", "words": "{path} is loaded " + ROOT + " and pinned at {pin}.",
                     "yes": "Load it"}},
        {"id": "attach", "hook": "attach_program", "title": "Attach a program", "submit": "Review",
         "note": (f"A loaded program, named by its pin or its id, attached {ROOT}: bpftool net attach (XDP, tcx), prog "
                  "attach (a sockmap, the flow dissector) or cgroup attach. An XDP or cgroup attach, and one that "
                  "replaces another, is asked twice."),
         "fields": [{"name": "kind", "label": "Attach type", "type": "choice", "value": NET_KINDS[0],
                     "choices": _choices(every)},
                    {"name": "target", "label": "On", "type": "text", "placeholder": "eth0, or /sys/fs/cgroup/app",
                     "note": "a network device for XDP and tcx; a cgroup v2 folder for a cgroup hook",
                     "when": {"kind": targeted}},
                    {"name": "pin", "label": "Program's pin", "type": "text", "placeholder": OWN_PIN,
                     "note": "its pin, or its id below"},
                    {"name": "prog_id", "label": "Program id", "type": "number", "min": 0, "note": "or its id"},
                    {"name": "map_id", "label": "Sockmap id", "type": "number", "min": 0, "when": {"kind": sockmap}},
                    {"name": "flags", "label": "Flag", "type": "choice", "value": "",
                     "when": {"kind": list(CGROUP_KINDS)},
                     "choices": [{"value": "", "title": "none", "note": "the only program on this hook"},
                                 {"value": "multi", "title": "multi", "note": "a sub-cgroup's programs run as well"},
                                 {"value": "override", "title": "override",
                                  "note": "a sub-cgroup's program runs instead of this one"}]},
                    {"name": "overwrite", "label": "Replace one there", "type": "choice", "value": "no",
                     "when": {"kind": net},
                     "choices": [{"value": "no", "title": "no", "note": "refused when a program is attached there"},
                                 {"value": "yes", "title": "yes", "note": "the program attached there is replaced"}]},
                    {"name": "accept_attach", "type": "accept", "title": "Change the kernel's datapath?",
                     "yes": "Attach it",
                     "words": ("An XDP program sees every packet its device receives, before the rest of the kernel, "
                               "and may drop it; a cgroup program runs for every process in its cgroup. It stays "
                               "attached until it is detached.")}],
         # the words name no field shown for some kinds alone (On, Sockmap id, Flag): a hidden field keeps its value
         # on the page, and would be named though the attach does not use it; the list under them shows what is used
         "confirm": {"title": "Attach the program?", "words": "A {kind} attach, " + ROOT + ": the program, and what it "
                     "goes on, as listed below.", "yes": "Attach it"}},
        {"id": "detach", "hook": "detach_program", "title": "Detach a program", "submit": "Review",
         "note": f"A link by its id, else the attach type with its target, as it was attached; {ROOT}.",
         "fields": [{"name": "link_id", "label": "Link id", "type": "number", "min": 0, "when": {"kind": [""]},
                     "note": "the Id of a row of Main's Links table"},
                    {"name": "kind", "label": "Detach", "type": "choice", "value": "",
                     "choices": _choices(every, [{"value": "", "title": "a link, by its id"}])},
                    {"name": "target", "label": "From", "type": "text", "placeholder": "eth0, or /sys/fs/cgroup/app",
                     "when": {"kind": targeted}},
                    {"name": "pin", "label": "Program's pin", "type": "text",
                     "when": {"kind": [*PROG_KINDS, *CGROUP_KINDS]}},
                    {"name": "prog_id", "label": "Program id", "type": "number", "min": 0,
                     "when": {"kind": [*PROG_KINDS, *CGROUP_KINDS]}},
                    {"name": "map_id", "label": "Sockmap id", "type": "number", "min": 0, "when": {"kind": sockmap}}],
         "confirm": {"title": "Detach it?", "words": "What is named is detached " + ROOT + ".", "yes": "Detach it",
                     "danger": True}},
        {"id": "unload", "hook": "unload_program", "title": "Unload a program", "submit": "Review",
         "note": (f"Its pin removed {ROOT}: the kernel frees the program once nothing else holds it (a link, an "
                  "attachment, another pin, an open file). A pin that is not Liminal's own is asked twice."),
         "fields": [{"name": "pin", "label": "Pin", "type": "text", "required": True, "placeholder": OWN_PIN},
                    {"name": "accept_unload", "type": "accept", "title": "Remove a pin that is not Liminal's?",
                     "yes": "Remove it",
                     "words": ("{pin} is not one of Liminal's own pins: what pinned it may rely on it. Its program "
                               "unloads once nothing else holds it.")}],
         "confirm": {"title": "Remove {pin}?", "words": "{pin} is removed " + ROOT + ".", "yes": "Remove it",
                     "danger": True}},
    ]


def _read_again() -> dict:
    return {"hook": "refresh", "args": [], "title": "Read again", "note": "reads this machine's eBPF runtime now"}


def machine_word(system: str) -> str:
    """sys.platform's word for this machine, where the plugin's system is this machine's (linux on macOS too); a system
    named for another machine (a test's) is taken as that system's own word."""
    here = "windows" if os.name == "nt" else "linux"
    return sys.platform if system == here else ("win32" if system == "windows" else "linux")


OS_NAMES = {"win32": "Windows", "cygwin": "Windows", "darwin": "macOS"}  # sys.platform's words, as said


# -- the plugin ---------------------------------------------------------------------------------------------------

class EbpfPlugin(MachinePlugin):
    name = "ebpf"
    title = "eBPF"
    about = ("This machine's eBPF: on Linux the kernel's own, on Windows eBPF for Windows; the two compared point by "
             "point, the basic functions, each change confirmed, and the watch service the firewalls' Filter tabs and "
             "trapdoor ask")
    api = "2.2"
    apis = APIS  # what it attaches to: bpftool, bpftrace, the kernel, libbpf, eBPF for Windows, Npcap, ETW (apis.py)
    order = 712  # after the two firewalls (710, 711)
    ICON = "ebpf"  # eBPF's bee, its maker's mark (liminal-libs 1.60.0's icons.js)
    SECTION = "os"  # under the platform's OS plugins (liminal-platform 0.26.0; the user, 2026-11-15: "then OS plugins")
    HOOKS = (*MachinePlugin.HOOKS, "refresh", "compare", "functions", "show_program", "dump", "load_program",
             "attach_program", "detach_program", "unload_program", "watch_start", "watch_read", "watch_stop")
    # Its changes, asked only from its page (0.1.2, the sweep after the review's PLT-H1; liminal-libs 1.66.0's
    # apps/asking.py): another plugin's ask is refused (403), and liminal-platform 0.34.0 refuses one over HTTP (401)
    # unless its login shows that you are at the page. Before, any program on this PC could ask them with two headers,
    # the second confirmation (accept_load, accept_attach, accept_unload) being only an argument: where sudo runs
    # bpftool without a password, a program loaded into the kernel, attached to every packet or every process, an
    # attachment detached or a pin removed, as root. Its two reads as root, a program shown and a map dumped, are the
    # page's too (0.1.3, the user's choice of 2026-11-25, "Root reads and Namecheap"): read through sudo -n, they gave
    # any asker every field of a loaded program and every entry of a map,
    # whoever's it was. Read again (refresh) is the page's as well (0.1.4; the user, 2026-11-26: "Yes, closed by
    # default", and of the reads made with a key or with rights: "Page-only"): it reads the runtime again at once,
    # through sudo -n on Linux. With it every hook says who may ask it (liminal-libs 1.107.0's conformance.warnings
    # is empty). Its status and its tabs are asked by anyone; asked by another plugin they start no read and hold no
    # programs, maps or links (0.1.5: for_its_page).
    PAGE_ONLY_HOOKS = ("load_program", "attach_program", "detach_program", "unload_program", "show_program", "dump",
                       "refresh")
    # The watch service, asked only by another plugin through the platform, as it was built to be (the firewalls'
    # Filter tabs, trapdoor): never from a page, which draws none of it, and never by a program over HTTP (403).
    # Before, any program on this PC started a watch with the same two headers (on Linux bpftrace as root, on Windows
    # a capture and ETW's sessions) and read every process, connection and file open it saw. The command line calls
    # the code itself, not through an ask.
    PLUGIN_ONLY_HOOKS = ("watch_start", "watch_read", "watch_stop")
    # its own tabs after Main and API (apps/tabs.py): the comparison is the same at every ask, its functions follow
    # what the last read found
    TABS = (Tab("compare", "Compare", "compare", 30.0), Tab("functions", "Functions", "functions", 5.0))

    def __init__(self, runtime=None, watch_factory=None, clock=time.monotonic, reclaim=None, system=None, where=None):
        """`runtime` stands in for this machine's (a test's), else ebpf.LinuxRuntime or ebpf.WindowsRuntime by the
        system the platform runs on: `system`, a test's word, else the runtime's, else this machine's (os.name).
        `where` is sys.platform's word for this machine (a test's; else machine_word): whether it is Linux at all, for
        the pages' "this machine" (macOS reads as the Linux system, and is neither). `watch_factory(kinds, spec)` makes
        the watch service's watches (else ebpf.make_watch, for that system); `clock` is the plugin's and the watches'
        (time.monotonic); `reclaim` stands in for etw.reclaim_stale_sessions. Nothing runs here: the plugin is made as
        its module is imported."""
        if system is not None and system not in SYSTEMS:
            raise ValueError(f"a system is linux or windows, not {shown(system)}")
        given = getattr(runtime, "system", "")
        self.system = system or (given if given in SYSTEMS else "windows" if os.name == "nt" else "linux")
        self._where = str(where or machine_word(self.system))
        if runtime is None:
            runtime = WindowsRuntime() if self.system == "windows" else LinuxRuntime()
        self._runtime = runtime
        self._clock = clock
        self._reclaim = reclaim
        factory = watch_factory if watch_factory is not None else functools.partial(make_watch, system=self.system)
        self._rt = _Runtime(WatchService(factory, clock=clock, system=self.system))

    # -- the read ------------------------------------------------------------------------------------------------
    def read(self) -> Snapshot:
        """The runtime read now and kept (Read again, the reading thread, and after each change). The machine's
        trouble never raises here: a read that fails is kept with why (`error`), and said on the page."""
        began, wall = self._clock(), time.time()
        try:
            snap = self._read_windows(began, wall) if self.system == "windows" else self._read_linux(began, wall)
        except Exception as e:  # noqa: BLE001 - the runtime's trouble is said on the page, not raised
            snap = Snapshot(began, wall, 0.0, self.system, error=f"{type(e).__name__}: {e}")
        snap = replace(snap, took=max(0.0, self._clock() - began))
        with self._rt.lock:
            self._rt.snap = snap
        return snap

    def _read_linux(self, at: float, wall: float) -> Snapshot:
        """The kernel's eBPF as the runtime reads it, then what the plugin's functions run, each asked as it runs:
        `sudo -n true` (whether sudo runs any command without a password), the listings as root whenever bpftool
        answered (a sudoers rule may let bpftool alone run without a password: a refusal comes back in sudo's words),
        and the watch's own command (sudo -n bpftrace -V) with the kernel functions its scripts probe. Under WSL 1
        nothing more is asked: it has no Linux kernel."""
        rt = self._runtime
        status = dict(rt.status() or {})
        if status.get("applies") is False:  # not for this machine (macOS; a library refusing WSL): nothing run there
            return Snapshot(at, wall, 0.0, "linux", status=status)
        w = wsl_facts(str(status.get("kernel") or "") or None)
        if wsl1(w):  # no Linux kernel: nothing that needs one is asked
            return Snapshot(at, wall, 0.0, "linux", status=status, unread=dict.fromkeys(OBJECTS, NO_KERNEL), wsl=w)
        sudo, sudo_words = self._sudo()
        if status.get("present"):
            objects, unread, listed, refused = _listed(rt)
        else:
            objects, unread, listed, refused = {}, dict.fromkeys(OBJECTS, "bpftool did not answer"), (), False
        watch, watch_words = self._watch_probe()
        lacking = self._kernel_lacks(script_kprobes()) if watch == "yes" else None
        return Snapshot(at, wall, 0.0, "linux", status=status, objects=objects, unread=unread, listed=listed,
                        refused=refused, sudo=sudo, sudo_words=sudo_words, watch=watch, watch_words=watch_words,
                        lacking=lacking, wsl=w)

    def _read_windows(self, at: float, wall: float) -> Snapshot:
        rt = self._runtime
        status = dict(rt.status() or {})
        why_not = getattr(rt, "why_not_here", None)
        facts = dict(why_not() or {}) if callable(why_not) else None
        objects: dict = {}
        unread: dict = {}
        if status.get("installed") or status.get("present"):
            note = str(status.get("programs_note") or "")
            core = any(isinstance(s, dict) and s.get("name") == "eBPFCore" and s.get("present")
                       for s in status.get("services") or ())
            if note:  # netsh needs an administrator: so do the maps and the links
                unread = dict.fromkeys(OBJECTS, note)
            elif not core:
                unread = dict.fromkeys(OBJECTS, "eBPFCore, the core driver, is not installed")
            else:
                objects = {"programs": tuple(plain(p) for p in status.get("programs") or ()),
                           "maps": tuple(plain(m) for m in rt.maps()), "links": tuple(plain(x) for x in rt.links())}
        return Snapshot(at, wall, 0.0, "windows", status=status, facts=facts, elevated=bool(is_elevated()),
                        backend=windows_backend(), objects=objects, unread=unread)

    def _sudo(self) -> tuple[str, str]:
        """Whether sudo runs any command as root without a password: the platform is root (its user id), or `sudo -n
        true` runs (the library's Shell: never a password asked). Not whether one command runs: a sudoers rule may
        let bpftool alone run without one, which its own listing then says. ("", "") when the runtime has no shell of
        its own."""
        shell = getattr(self._runtime, "shell", None)
        if not isinstance(shell, Shell):
            return "", ""
        try:
            if shell.root():
                return "root", "the platform runs as root"
            shell.run("true", timeout=10)  # sudo -n true
        except CommandError as e:
            said = str(e)
            if e.denied:
                return "password", f"sudo -n true asks for a password here ({sudo_said(said)})"
            return "no", f"sudo could not run: {said}"
        return "yes", "sudo -n true runs without a password"

    def _watch_probe(self) -> tuple[str, str]:
        """What the watch's own command answers: `sudo -n bpftrace -V`, through sudo as the library's BpftraceWatch
        runs bpftrace whether the platform is root or not (so a platform run as root needs sudo all the same, and a
        bpftrace on the platform's user's path alone is not one sudo finds). (state, words): yes and bpftrace's
        version; password when sudo refused it (its words); missing when sudo found no bpftrace; no when sudo could not
        run. ("", "") when the runtime has no shell of its own."""
        shell = getattr(self._runtime, "shell", None)
        if not isinstance(shell, Shell):
            return "", ""
        try:
            out = shell.run(*WATCH_PROBE, root=False, timeout=15)
        except CommandError as e:
            said = str(e)
            if e.denied:
                return "password", sudo_said(said)
            if "not found" in said.lower():
                return "missing", said
            return "no", said
        lines = [ln.strip() for ln in str(out or "").splitlines() if ln.strip()]
        return "yes", lines[0] if lines else "it answered"

    def _kernel_lacks(self, wanted: dict) -> dict | None:
        """Of the kernel functions the watch scripts' kprobes need (script_kprobes), those this kernel does not have:
        {kind: (function, ...)}, read from /proc/kallsyms as the platform's user (it is world-readable); None when it
        could not be read. The names are the scripts' own words (letters, digits and _ alone)."""
        shell = getattr(self._runtime, "shell", None)
        names = sorted({f for functions in wanted.values() for f in functions})
        if not names:
            return {}
        if not isinstance(shell, Shell):
            return None
        script =(f"test -r {KALLSYMS} || exit 3; grep -w -F " + " ".join(f"-e {n}" for n in names)
                  + f" {KALLSYMS}; exit 0")
        try:
            out = shell.sh(script, root=False, timeout=15)
        except CommandError:
            return None
        have = {parts[2] for parts in (ln.split() for ln in str(out or "").splitlines()) if len(parts) >= 3}
        return {kind: tuple(f for f in functions if f not in have) for kind, functions in wanted.items()
                if any(f not in have for f in functions)}

    def _read_quietly(self) -> None:
        try:
            self.read()
        finally:
            with self._rt.lock:
                if self._rt.reader is threading.current_thread():
                    self._rt.reader = None

    def snapshot(self, fresh: bool = False, wait: float = 0.0) -> Snapshot | None:
        """The runtime as last read; read again on a thread when it is older than READ_S (or `fresh`). Only while
        there is no read yet (or `fresh`) is the thread waited for, `wait` seconds at most: an older read is given at
        once, the new one following. Asked by another plugin (for_its_page False, 0.1.5) it starts no read and waits
        for none: the read as it was kept, or None."""
        mine = for_its_page()
        with self._rt.lock:
            snap, reader = self._rt.snap, self._rt.reader
            if not mine:
                return snap
            stale = snap is None or fresh or self._clock() - snap.at > READ_S
            if stale and reader is None:
                reader = self._rt.reader = threading.Thread(target=self._read_quietly, name=READER, daemon=True)
                reader.start()
        if reader is not None and wait > 0 and (snap is None or fresh):
            reader.join(wait)
        with self._rt.lock:
            return self._rt.snap

    @staticmethod
    def _needs_libs() -> None:
        """ValueError, in words, on a liminal-libs older than the floor (libs_too_old): no hook reads or runs anything
        there, as the status says it is not valid."""
        too_old = libs_too_old()
        if too_old:
            raise ValueError(too_old)

    def refresh(self) -> dict:
        """The runtime read again now (the page's Read again)."""
        self._needs_libs()
        snap = self.read()
        if snap.error:
            return {"said": f"the runtime could not be read: {snap.error}", "ok": False}
        return {"said": f"read again in {snap.took:.1f} s: {self._summary(snap)}", "ok": True}

    # -- the platform's asks -------------------------------------------------------------------------------------
    def present(self) -> bool:
        """Whether the plugin is there to serve: everywhere, as its status' `valid` says (the comparison needs nothing
        of the machine), so the platform's tray, which asks this, shows its icon whenever the list says it is active;
        on a liminal-libs older than the floor, nowhere (libs_too_old). Whether this machine's eBPF runtime is there is
        the status' own `present`, said on its page. Asks nothing."""
        return not libs_too_old()

    def attach(self, app, login=None) -> dict:
        """Attached by `app`: a watch may be started again (a detach refuses them); on Windows, at the plugin's first
        attach on the platform (not a one-shot command's), the ETW sessions a killed platform left are stopped; and,
        but for a one-shot command's attach (the platform's rule: it starts no background work of its own), the
        runtime is read on a thread, so the page's first look waits on nothing. No watch is started here."""
        interface = super().attach(app, login)
        if libs_too_old():  # an older library: nothing read and nothing reclaimed (the status says why)
            return interface
        with self._rt.lock:
            self._rt.detached = False
            reclaim = (self.system == "windows" and not self._rt.reclaimed and getattr(app, "NAME", "") == "platform"
                       and not getattr(app, "once", False))
            if reclaim:
                self._rt.reclaimed = True
        if reclaim:
            try:
                (self._reclaim or etw.reclaim_stale_sessions)()
            except Exception:  # noqa: BLE001 - best effort, as the library's own: an attach never fails on it
                pass
        if not getattr(app, "once", False):  # a one-shot command's status reads for itself, waiting on it
            self.snapshot()
        return interface

    def detach(self) -> None:
        """Detached: every live watch stopped (the service waits 3 s at most in all, and never raises), none started
        until the plugin is attached again; then the base's detach."""
        try:
            with self._rt.lock:
                self._rt.detached = True
            self._rt.service.stop_all()
        except Exception:  # noqa: BLE001 - a detach is never failed by its watches
            pass
        super().detach()

    def status(self) -> dict:
        """Main: this machine's runtime as the last read found it, valid wherever the plugin serves (everywhere), its
        facts, its tables, the forms its rows open and Read again. On a liminal-libs older than the plugin's floor it
        serves nothing it could say truly: not valid, and why."""
        too_old = libs_too_old()
        if too_old:
            return {"present": False, "valid": False, "why": too_old, "summary": too_old, "tables": [], "forms": [],
                    "actions": []}
        snap = self.snapshot(wait=FIRST_WAIT_S)
        if not for_its_page():  # another plugin's ask: no read started, and what the read listed as root left out
            if snap is None:
                return {"valid": True, "summary": "this machine's eBPF runtime is not read yet: its page reads it",
                        "tables": [], "forms": [], "actions": [], "lists": LISTS_WORDS}
            if snap.error:
                out = {"valid": True, "summary": "this machine's eBPF runtime could not be read",
                       "problem": f"the runtime could not be read: {snap.error}", "readAt": self._read_at(snap),
                       "tables": []}
            else:
                out = self._windows_status(snap) if self.system == "windows" else self._linux_status(snap)
            out.update({"forms": [], "actions": [], "lists": LISTS_WORDS})
            return out
        if snap is None:
            return {"valid": True, "summary": "reading this machine's eBPF runtime…", "tables": [], "forms": forms(),
                    "actions": [_read_again()]}
        if snap.error:
            return {"valid": True, "summary": "this machine's eBPF runtime could not be read",
                    "problem": f"the runtime could not be read: {snap.error}", "readAt": self._read_at(snap),
                    "tables": [], "forms": forms(), "actions": [_read_again()]}
        return self._windows_status(snap) if self.system == "windows" else self._linux_status(snap)

    def api_facts(self) -> dict:
        """What the last read and the watch service learned of what the plugin attaches to, asking nothing (a read
        under way is not waited for): on Linux bpftool, bpftrace and the kernel as read, on Windows eBPF for Windows,
        Npcap and ETW; the watches running now. Nothing before the first read but the watches; on a liminal-libs older
        than the floor, only that."""
        too_old = libs_too_old()
        if too_old:
            return {(EBPF_WINDOWS if self.system == "windows" else BPFTOOL).name: {"Not read": too_old}}
        with self._rt.lock:
            snap = self._rt.snap
        out: dict[str, dict[str, str]] = {}
        if snap is not None and snap.error:
            out[(EBPF_WINDOWS if self.system == "windows" else BPFTOOL).name] = {
                "Last read failed": snap.error, "Last read": self._read_at(snap)}
        elif snap is not None:
            out.update(self._windows_facts(snap) if self.system == "windows" else self._linux_facts(snap))
        for api, facts in self._watch_facts().items():
            out.setdefault(api, {}).update(facts)
        return out

    # -- Main ----------------------------------------------------------------------------------------------------
    def _summary(self, snap: Snapshot) -> str:
        if snap.error:
            return "this machine's eBPF runtime could not be read"
        return self._windows_summary(snap) if self.system == "windows" else self._linux_summary(snap)

    @staticmethod
    def _read_at(snap: Snapshot) -> str:
        return f"{when(snap.wall)}, in {snap.took:.1f} s"

    def _linux_summary(self, snap: Snapshot) -> str:
        s, w = snap.status, snap.wsl
        if s.get("applies") is False:
            return "not for this machine: " + str(s.get("why") or "the eBPF runtime is Linux's")
        kernel = str(s.get("kernel") or "")
        head = f"Linux {kernel}" if kernel else "Linux"
        if w:
            head += f" (WSL {w.get('generation') or 2}: {wsl_name(w)})"
        if wsl1(w):
            return f"{head}: {NO_KERNEL}"
        parts = [f"bpftool {s['bpftool']}" if s.get("present") and s.get("bpftool") else
                 "bpftool" if s.get("present") else "no bpftool",
                 "bpftrace" if s.get("bpftrace_present") else "no bpftrace",
                 "kernel BTF" if s.get("btf") else "no kernel BTF"]
        if BPF_FS not in (s.get("bpffs") or ()):
            parts.append("the BPF filesystem not mounted")
        if snap.refused:
            parts.append("bpftool refused as root")
        elif snap.sudo == "password":
            parts.append("sudo -n true asks for a password")
        elif snap.sudo == "no":
            parts.append("sudo could not run")
        if snap.watch and snap.watch != "yes":
            parts.append("the watch cannot run")
        return f"{head}: {', '.join(parts)}"

    def _linux_status(self, snap: Snapshot) -> dict:
        s, w = snap.status, snap.wsl
        if s.get("applies") is False:
            return {"present": False, "valid": True, "summary": self._linux_summary(snap) + "; the comparison serves "
                    "all the same", "runtime": "none here", "readAt": self._read_at(snap), "tables": [],
                    "forms": forms(), "actions": [_read_again()]}
        kernel = str(s.get("kernel") or "")
        tables = [self._kernel_table(snap), *self._object_tables(snap)]
        under = self._under_wsl(snap)
        if under is not None:
            tables.append(under)
        # WSL 1 has no Linux kernel: no runtime is there, whatever a bpftool built for another kernel answers
        out = {"present": bool(s.get("present")) and not wsl1(w), "valid": True,
               "summary": self._linux_summary(snap),
               "runtime": f"none: {NO_KERNEL}" if wsl1(w) else "the Linux kernel's own" + (f" ({kernel})" if kernel
                                                                                           else "")}
        if w:
            out["wsl"] = f"WSL {w.get('generation') or 2}: {wsl_name(w)}"
        out.update({"bpftool": bpftool_words(s, w)[0], "btf": btf_words(s.get("btf"))[0],
                    "jit": jit_words(s.get("bpf_jit_enable"))[0],
                    "unprivilegedBpf": unprivileged_words(s.get("unprivileged_bpf_disabled"))[0],
                    "bpfFilesystem": bpffs_words(s.get("bpffs"))[0], "bpftrace": bpftrace_words(s, snap)[0],
                    "root": root_words(snap)[0], "watch": " — ".join(linux_watch_words(snap)),
                    "readAt": self._read_at(snap), "tables": tables, "forms": forms(), "actions": [_read_again()]})
        return out

    def _kernel_table(self, snap: Snapshot) -> dict:
        s, w = snap.status, snap.wsl
        watch_from = ("uname -r: WSL 1's kernel release" if wsl1(w) else
                      "sudo -n bpftrace -V, the watch's own command" + (f"; {KALLSYMS}" if snap.lacking is not None
                                                                         else ""))

        def means(words: tuple[str, str]) -> dict | str:  # what was read; under WSL 1 it means no eBPF all the same
            return cell(words[0], NO_KERNEL) if wsl1(w) else cell(*words)
        rows = [["Kernel release", str(s.get("kernel") or "not read"), "uname -r"],
                ["bpftool", cell(*bpftool_words(s, w)), "bpftool -j version"],
                ["Unprivileged BPF", means(unprivileged_words(s.get("unprivileged_bpf_disabled"))),
                 "/proc/sys/kernel/unprivileged_bpf_disabled"],
                ["JIT", means(jit_words(s.get("bpf_jit_enable"))), "/proc/sys/net/core/bpf_jit_enable"],
                ["Kernel BTF", means(btf_words(s.get("btf"))), "/sys/kernel/btf/vmlinux"],
                ["BPF filesystem", means(bpffs_words(s.get("bpffs"))), "/proc/mounts"],
                ["bpftrace", cell(*bpftrace_words(s, snap)), "bpftrace -V, as the platform's user"],
                ["Root", cell(*root_words(snap)), root_source(snap)],
                ["The watch", cell(*linux_watch_words(snap)), watch_from]]
        return {"title": "This kernel's eBPF",
                "note": (f"read {self._read_at(snap)}: the kernel's files and the tools' versions as the platform's "
                         "user (bpftool's through sudo -n too, where it is on root's path alone); root's rights as "
                         "sudo -n true answered, and the watch's as its own command did"),
                "columns": [{"title": "What"}, {"title": "Here"}, {"title": "Read from"}], "rows": rows}

    def _under_wsl(self, snap: Snapshot) -> dict | None:
        """What running inside a WSL distribution changes or lacks for eBPF, as a table of the plugin's own (the
        user, 2026-11-15: "if wsl prevents or misses some capability this should reflect in the plugin"; the model:
        machines.world.under_wsl). None on a Linux of its own. Each row from what was read."""
        w = snap.wsl
        if not w:
            return None
        s, name = snap.status, wsl_name(w)
        systemd = {True: "systemd runs", False: "systemd does not run"}.get(w.get("systemd"),
                                                                            "whether systemd runs was not read")
        if wsl1(w):
            rows = [["This Linux", cell(f"WSL 1: {name}", systemd), f"{NO_KERNEL}: nothing can be loaded or watched "
                     "here"],
                    ["WSL 2", "not this distribution", f"WSL 2 runs a Linux kernel: wsl --set-version "
                     f"{wsl_own_name(w)} 2, from Windows"]]
        else:
            kernel = str(s.get("kernel") or "")
            mounted, means = bpffs_words(s.get("bpffs"))
            if mounted == "not mounted" and w.get("systemd"):
                mounted = "not mounted, though systemd runs here"
            its = "its kernel" + (f" ({kernel})" if kernel else "")
            whose = (f"{its} is Microsoft's, updated by WSL rather than this distribution's packages"
                     if microsofts(kernel) else
                     f"{its} is not Microsoft's build: WSL runs it in place of its own, and does not update it")
            fetch = ("" if s.get("bpftrace_present") or snap.watch == "yes" else
                     ": the distribution's bpftrace package" + (" (sudo apt install bpftrace)" if ubuntu(w) else ""))
            rows = [["This Linux", cell(f"WSL {w.get('generation') or 2}: {name}", systemd),
                     f"a WSL distribution on Windows: {whose}; every WSL 2 distribution on this PC shares it"],
                    ["What is seen", "the whole WSL virtual machine",
                     "programs, maps, links and events are the virtual machine's: every running WSL 2 distribution's "
                     "and WSL's own. An event's pid is the kernel's, not the one this distribution's own pid namespace "
                     "shows (ps, /proc), and a watch's spec pid is matched against the kernel's: give it one an event "
                     "showed (a process watch's exec), not one ps shows here"],
                    ["Network", "WSL's, behind Windows",
                     "a net watch sees WSL's virtual network (behind Windows' NAT by default): Windows' own traffic is "
                     "not seen here, but by the eBPF plugin on the Windows platform"],
                    ["bpftool", *bpftool_words(s, w)],
                    ["bpftrace", bpftrace_words(s, snap)[0], "the watch runs it through sudo -n" + fetch],
                    ["The BPF filesystem", mounted, means],
                    ["Root", *root_words(snap)],
                    ["Lifetime", "while WSL runs it",
                     "everything loaded or pinned here ends when WSL stops its virtual machine"]]
        return {"title": "Under WSL", "note": "What running inside a WSL distribution changes for eBPF here.",
                "columns": [{"title": "What"}, {"title": "Here"}, {"title": "What it means"}], "rows": rows}

    def _object_tables(self, snap: Snapshot) -> list[dict]:
        """Main's programs, maps and links tables: none for another plugin's ask (0.1.5: they were listed as root)."""
        return [self._object_table(snap, name) for name in OBJECTS] if for_its_page() else []

    def _object_table(self, snap: Snapshot, name: str) -> dict:
        """Main's programs, maps or links as read: each row with the button that shows, dumps or detaches it; why
        they were not listed, when they were not; none on Windows while eBPF for Windows is not installed."""
        title = name.capitalize()
        rows = snap.objects.get(name)
        if rows is None:
            why = str(snap.unread.get(name) or "").rstrip(".")
            if why:
                empty = f"Not listed: {why}."
            elif snap.system != "windows":
                empty = "Not listed."
            elif not_installed(snap):  # its three services read, none there
                empty = "None: eBPF for Windows is not installed."
            else:  # its services could not be read: whether it is installed is not known
                empty = "Not listed: eBPF for Windows' services could not be read."
            return {"title": title, "columns": [{"title": "Id", "num": True}], "rows": [], "empty": empty}
        shown_rows = list(rows[:ROWS])
        command = (f"netsh ebpf show {name}" if snap.system == "windows" else
                   f"bpftool -j {BPFTOOL_OBJECTS[name]} show, as root")
        first = f"the first {ROWS} of {len(rows):,}; " if len(rows) > ROWS else ""
        note = f"{first}read {when(snap.wall)}: {command}"
        if snap.system == "windows":
            keys = list(dict.fromkeys(k for r in shown_rows for k in r))[:6]
            columns = [{"title": k.capitalize()} for k in keys]
            cells = [[str(r.get(k, "")) or "–" for k in keys] for r in shown_rows]
            if name == "programs" and "id" in keys:
                columns.append({"title": ""})
                for c, r in zip(cells, shown_rows):
                    c.append(self._button("show", r.get("id")))
        elif name == "programs":
            columns = [{"title": "Id", "num": True}, {"title": "Type"}, {"title": "Name"}, {"title": "Tag"},
                       {"title": "Loaded"}, {"title": "Maps"}, {"title": ""}]
            cells = [[p.get("id", "–"), p.get("type") or "–", p.get("name") or "–", p.get("tag") or "–",
                      when(p.get("loaded_at")) if isinstance(p.get("loaded_at"), (int, float)) else
                      str(p.get("loaded_at") or "–"), ", ".join(str(i) for i in p.get("map_ids") or ()) or "–",
                      self._button("show", p.get("id"))] for p in shown_rows]
        elif name == "maps":
            columns = [{"title": "Id", "num": True}, {"title": "Type"}, {"title": "Name"}, {"title": "Key → value"},
                       {"title": "Entries at most", "num": True}, {"title": ""}]
            cells = [[m.get("id", "–"), m.get("type") or "–", m.get("name") or "–", sizes(m),
                      m.get("max_entries", "–"), self._button("dump", m.get("id"))] for m in shown_rows]
        else:
            columns = [{"title": "Id", "num": True}, {"title": "Type"}, {"title": "Program", "num": True},
                       {"title": "Attached to"}, {"title": ""}]
            cells = [[x.get("id", "–"), x.get("type") or "–", x.get("prog_id", "–"), attached_to(x),
                      self._button("detach", x.get("id"))] for x in shown_rows]
        empty = {"programs": "No program is loaded.", "maps": "No map.", "links": "No link."}[name]
        return {"title": title, "note": note, "columns": columns, "rows": cells, "empty": empty}

    @staticmethod
    def _button(form: str, ident) -> dict | str:
        """A row's button opening a form with its id filled in: Show… a program, Dump… a map, Detach… a link."""
        try:
            n = whole(ident, "an id")
        except ValueError:
            return "–"
        key, words = {"show": ("prog_id", "Show program"), "dump": ("map_id", "Dump map"),
                      "detach": ("link_id", "Detach link")}[form]
        values = {key: n, "limit": DUMP_LIMIT} if form == "dump" else {key: n}
        return {"form": form, "title": f"{words.split()[0]}…", "values": values, "label": f"{words} {n}"}

    def _windows_summary(self, snap: Snapshot) -> str:
        s, f = snap.status, snap.facts or {}
        if not s.get("services"):
            return "eBPF for Windows could not be read"
        running = any(x.get("name") == "eBPFCore" and x.get("status") == "Running" for x in s["services"])
        if snap.installed:
            head = ("eBPF for Windows" + (f" v{s['version']}" if s.get("version") else "") + " installed, its core "
                    + ("running" if running else "not running"))
        else:
            head = "eBPF for Windows is not installed"
        if not running and f.get("secure_boot") is True and f.get("test_signing") is not True:
            head += ", and it could not load here: Secure Boot is on"  # a core running loaded all the same
        return head + "; the watch uses Npcap and ETW"

    def _windows_status(self, snap: Snapshot) -> dict:
        s, f = snap.status, snap.facts or {}
        services = [x for x in s.get("services") or () if isinstance(x, dict)]
        if not services:
            runtime = f"not read: {s.get('why') or 'its services could not be read'}"
        elif snap.installed:
            runtime = "eBPF for Windows" + (f" v{s['version']}" if s.get("version") else "") + ", installed"
        else:
            runtime = "eBPF for Windows: not installed"
        b = snap.backend or {}
        missing = [words for words, lacking in (
            ("Npcap is not installed", not b.get("npcap")),
            ("Npcap is for administrators only", b.get("npcap") and b.get("admin_only") and not b.get("administrator")),
            ("ETW cannot start a session here", not b.get("etw"))) if lacking]
        return {"present": snap.installed, "valid": True, "summary": self._windows_summary(snap), "runtime": runtime,
                "secureBoot": secure_boot_words(f, snap.elevated)[0], "memoryIntegrity": hvci_words(f)[0],
                "testSigning": signing_words(f),
                "canItLoad": " — ".join(x for x in verdict_words(f) if x),
                "watch": "Npcap and ETW, not eBPF" + (f": {'; '.join(missing)}" if missing else ""),
                "administrator": "yes" if snap.elevated else "no", "readAt": self._read_at(snap),
                "tables": [self._windows_runtime_table(snap), self._can_it_load_table(snap),
                           self._windows_watch_table(snap), *self._object_tables(snap)],
                "forms": forms(), "actions": [_read_again()]}

    def _windows_runtime_table(self, snap: Snapshot) -> dict:
        s = snap.status
        services = [x for x in s.get("services") or () if isinstance(x, dict)]
        reads = "Get-Service eBPFCore, NetEbpfExt, eBPFSvc"
        if not services:
            rows = [["Installed", cell("not read", str(s.get("why") or "")), reads]]
        else:
            rows = [["Installed", "yes" if snap.installed else "no", reads],
                    ["Version", f"v{s['version']}" if s.get("version") else "–",
                     r"%ProgramFiles%\ebpf-for-windows\EbpfApi.dll"]]
            for x in services:
                state = (", ".join(str(v) for v in (x.get("status"), x.get("start")) if v) or "present"
                         if x.get("present") else "absent")
                rows.append([str(x.get("name") or "–"), cell(state, SERVICE_ROLES.get(str(x.get("name")), "")),
                             "Get-Service"])
        rows.append(["Linux here", "WSL's, not this platform's", WSL_NOTE])
        return {"title": "eBPF for Windows", "note": "Microsoft's separate, pre-release download, read without asking "
                "for an administrator", "columns": [{"title": "What"}, {"title": "Here"}, {"title": "Read from"}],
                "rows": rows}

    def _can_it_load_table(self, snap: Snapshot) -> dict:
        f, elevated = snap.facts or {}, snap.elevated
        sb, sb_from = secure_boot_words(f, elevated)
        hv, hv_means = hvci_words(f)
        rows = [["Secure Boot", sb, sb_from],
                ["Memory integrity", cell(hv, hv_means), "Win32_DeviceGuard (SecurityServicesRunning), read "
                 + ("as an administrator" if elevated else "without an administrator")],
                ["Test signing", signing_words(f), signing_from(f) or SIGNING_UNREAD],
                ["Can it load", cell(*verdict_words(f)), "the three above"]]
        unread = all(f.get(k) is None for k in ("secure_boot", "hvci", "test_signing")) and f.get("words")
        note = str(f["words"]) if unread else TEST_SIGNED[0].upper() + TEST_SIGNED[1:] + "."
        return {"title": "Can a test-signed driver load here", "note": note,
                "columns": [{"title": "What"}, {"title": "Here"}, {"title": "Read from"}], "rows": rows}

    def _windows_watch_table(self, snap: Snapshot) -> dict:
        b = snap.backend or {}
        if not b.get("npcap"):
            npcap = cell("not installed", "a net watch needs it (npcap.com; Wireshark installs it)")
        elif b.get("admin_only") and not b.get("administrator"):
            npcap = cell("installed, for administrators only", "and the platform is none: a net watch asks Npcap "
                         "nothing, since it would ask for UAC; install it again with that option off, or run the "
                         "platform as an administrator")
        else:
            npcap = cell("installed", "for any user" if not b.get("admin_only") else "for administrators: the "
                         "platform is one")
        events = cell("a real-time session may start here" if b.get("etw") else "a real-time session cannot start "
                      "here", str(b.get("etw_why") or ""))
        rows = [["Npcap", npcap, r"%SystemRoot%\System32\Npcap\wpcap.dll and its AdminOnly option"],
                ["ETW", events, "this process's access token"],
                ["The watch", cell("Npcap and ETW, not eBPF", "net from Npcap, each flow's program from ETW; process, "
                                   "file and registry from ETW: what the firewalls' Filter tabs and trapdoor ask; "
                                   + LOST_SAID), "the two above"]]
        return {"title": "Watching here", "note": "The library's Windows watch, behind the same interface an eBPF one "
                "would fill once signed builds exist; read without opening Npcap or starting a session",
                "columns": [{"title": "What"}, {"title": "Here"}, {"title": "Read from"}], "rows": rows}

    # -- Compare ---------------------------------------------------------------------------------------------------
    def compare(self) -> dict:
        """The Compare tab: the library's comparison by area (capabilities.by_area with apis.SOURCES, each point's
        source under its name), Linux beside Windows, this machine's column marked (none where neither is: macOS, WSL
        1), and a Here column in the areas where this machine's status read something, each cell saying where it was
        read. Nothing static is claimed there."""
        self._needs_libs()
        snap = self.snapshot(wait=FIRST_WAIT_S)
        here = self._here(snap)
        this, marked = self._this_machine(snap), self._marked(snap)
        tables = []
        for group in capabilities.by_area(SOURCES):
            area = group["area"]
            with_here = any((area, r["item"]) in here for r in group["rows"])
            columns = [{"title": "What"}, {"title": "Linux" + (" (this machine)" if marked == "linux" else "")},
                       {"title": "Windows" + (" (this machine)" if marked == "windows" else "")}]
            if with_here:
                columns.append({"title": "Here"})
            rows = []
            for r in group["rows"]:
                row = [cell(r["item"], r.get("source") or None), point(r["linux"]), point(r["windows"])]
                if with_here:
                    row.append(here.get((area, r["item"]), "–"))
                rows.append(row)
            tables.append({"title": area, "columns": columns, "rows": rows})
        points, areas = len(capabilities.CAPABILITIES), len(capabilities.AREAS)
        mark = "its column is marked" if marked else "neither column is this machine's"
        return {"title": "eBPF on Linux and on Windows",
                "note": (f"This machine: {this}; {mark}. {points} points in {areas} areas, read on {VERIFIED} from the "
                         "maintainers' own documentation, headers and release notes, each point's source under its "
                         f"name. {self._here_said(snap, here)}"),
                "tables": tables}

    def _marked(self, snap: Snapshot | None) -> str:
        """The comparison's column that is this machine's: Windows' on Windows; Linux's on Linux (a WSL 2
        distribution's included); none on a machine that is neither (macOS) or under WSL 1, which has no Linux
        kernel."""
        if self.system == "windows":
            return "windows"
        if not self._where.startswith("linux") or (snap is not None and wsl1(snap.wsl)):
            return ""
        return "linux"

    def _this_machine(self, snap: Snapshot | None) -> str:
        """This machine in words: by what it is (sys.platform, and the WSL distribution read), not by whether the
        runtime applies (a library before 1.57.0 refuses a WSL kernel, which is Linux all the same)."""
        if self.system == "windows":
            return "Windows"
        if not self._where.startswith("linux"):
            return f"{OS_NAMES.get(self._where, self._where)}, neither Linux nor Windows"
        w = snap.wsl if snap is not None else None
        if w:
            name = f"WSL {w.get('generation') or 2}: {wsl_name(w)}"
            return f"{name}, which has no Linux kernel, so no eBPF" if wsl1(w) else name
        return "Linux"

    @staticmethod
    def _here_said(snap: Snapshot | None, here: dict) -> str:
        """What the Here column holds, or why there is none: not read yet, a read that failed, a runtime that does not
        apply here (its words)."""
        if snap is None:
            return "Nothing of this machine is read yet: a Here column comes once its status is."
        if snap.error:
            return f"This machine's status could not be read ({snap.error}): a Here column comes once a read succeeds."
        if snap.status.get("applies") is False:
            why = str(snap.status.get("why") or "the eBPF runtime does not apply here")
            return f"Nothing of this machine is read: {why[:1].lower()}{why[1:]}."
        if here:
            return "The Here column holds only what this machine's status read, each saying where."
        return "Nothing this machine's status read bears on these points."

    def _here(self, snap: Snapshot | None) -> dict:
        """What this machine's status read, by the comparison's (area, item): {text, sub} cells, `sub` saying
        where each was read. Nothing that was not read."""
        if snap is None or snap.error:
            return {}
        return self._here_windows(snap) if self.system == "windows" else self._here_linux(snap)

    def _here_linux(self, snap: Snapshot) -> dict:
        s, w = snap.status, snap.wsl
        if s.get("applies") is False:
            return {}
        kernel = str(s.get("kernel") or "")
        if wsl1(w):  # no Linux kernel: what was read is that, and what it means for the watch
            return {("Install and status", "Current version"): cell(
                        "none: WSL 1 has no Linux kernel", "read from the kernel's release" + (
                            f" ({kernel})" if kernel else "")),
                    ("Basic functions", "Watch events (ring buffer, perf buffer, printk)"): cell(
                        f"the watch service: cannot run here — {NO_KERNEL}", "read from the kernel's release")}
        here: dict = {}
        tool = f"; bpftool {s['bpftool']}" if s.get("present") and s.get("bpftool") else ""
        if kernel:
            here[("Install and status", "Current version")] = cell(
                f"kernel {kernel}{tool}", "read from uname -r" + ("; bpftool -j version" if tool else ""))
        if s.get("bpf_jit_enable") is not None:
            here[("Execution", "Interpreter / JIT / native")] = cell(
                "JIT " + jit_words(s["bpf_jit_enable"])[0], "read from /proc/sys/net/core/bpf_jit_enable")
        here[("Loading", "Pinning")] = cell("BPF filesystem " + bpffs_words(s.get("bpffs"))[0],
                                            "read from /proc/mounts")
        here[("Loading", "BTF and CO-RE")] = cell("kernel BTF present" if s.get("btf") else "no kernel BTF",
                                                  "read from /sys/kernel/btf/vmlinux")
        here[("Loading", "bpftool")] = cell(
            f"bpftool {s['bpftool']}" if s.get("present") and s.get("bpftool") else
            "bpftool answered" if s.get("present") else "bpftool did not answer",
            "read from bpftool -j version (as the platform's user, then through sudo -n)")
        unpriv = s.get("unprivileged_bpf_disabled")
        words, sources = [], []
        if unpriv is not None:
            words.append(f"unprivileged_bpf_disabled {unprivileged_words(unpriv)[0]}")
            sources.append("/proc/sys/kernel/unprivileged_bpf_disabled")
        if snap.sudo:
            words.append(root_words(snap)[0])
            sources.append(root_source(snap))
        if words:
            here[("Privileges", "Load and attach")] = cell("; ".join(words), "read from " + "; ".join(sources))
        if snap.listed:  # the listings asked, as root: what they gave, and why one did not
            listed = [plural(len(snap.objects[n]), n[:-1]) for n in OBJECTS if n in snap.objects]
            why = next((snap.unread[n] for n in snap.listed if n in snap.unread), "")
            here[("Privileges", "List and read")] = cell(
                ("listed as root: " + ", ".join(listed)) if listed and not why else
                f"not listed: {why}" if not listed else "listed in part: " + ", ".join(listed) + f"; {why}",
                "read from bpftool -j " + ", ".join(f"{BPFTOOL_OBJECTS[n]} show" for n in snap.listed) + ", as root")
        elif not s.get("present"):  # none asked: bpftool did not answer its version
            here[("Privileges", "List and read")] = cell(
                "not listed: bpftool did not answer",
                "read from bpftool -j version (as the platform's user, then through sudo -n)")
        if snap.watch:
            here[("Basic functions", "Watch events (ring buffer, perf buffer, printk)")] = cell(
                "the watch service: " + " — ".join(linux_watch_words(snap)),
                "read from sudo -n bpftrace -V" + (f"; {KALLSYMS}" if snap.lacking is not None else ""))
        return here

    def _here_windows(self, snap: Snapshot) -> dict:
        s, f, elevated = snap.status, snap.facts or {}, snap.elevated
        here: dict = {}
        if s.get("services"):
            here[("Install and status", "Where it comes from")] = cell(
                "eBPF for Windows installed" if snap.installed else "eBPF for Windows not installed",
                "read from Get-Service eBPFCore, NetEbpfExt, eBPFSvc")
            here[("Install and status", "Current version")] = cell(
                f"v{s['version']}" if s.get("version") else "none: not installed" if not snap.installed else
                "not read", r"read from %ProgramFiles%\ebpf-for-windows\EbpfApi.dll")
        sb, hv = f.get("secure_boot"), f.get("hvci")
        signing = signing_from(f)
        sb_from = {"firmware": "Confirm-SecureBootUEFI",
                   "registry": r"the registry (SecureBoot\State)"}.get(f.get("secure_boot_source"), "")
        reads = [x for x, read in ((f"Secure Boot from {sb_from}", sb is not None),
                                   ("memory integrity from Win32_DeviceGuard", hv is not None),
                                   (f"test signing from {signing}", bool(signing))) if read]
        if reads:  # the verdict from what of the three was read, and only those named
            verdict, means = verdict_words(f)
            here[("Install and status", "Production or preview")] = cell(
                f"test-signed: {verdict}", "read here: " + "; ".join(reads) + (f". {means}" if means else ""))
        read = "read from Win32_DeviceGuard, " + ("as an administrator" if elevated else "without an administrator")
        if hv is not None:
            here[("Execution", "HVCI (memory integrity)")] = cell("memory integrity " + hvci_words(f)[0], read)
        if hv is True:
            here[("Execution", "Interpreter / JIT / native")] = cell("no JIT here: memory integrity is on", read)
        if sb is not None or signing:
            sources = [x for x, used in ((secure_boot_words(f, elevated)[1], sb is not None),
                                         (signing, bool(signing))) if used]
            here[("Execution", "Signing and test signing")] = cell(
                f"Secure Boot {secure_boot_words(f, elevated)[0]}; test signing {signing_words(f)}",
                "read from " + "; ".join(sources))
        here[("Privileges", "Load and attach")] = cell(
            "the platform runs as an administrator" if elevated else "the platform runs without an administrator's "
            "rights", "read from this process's token (IsUserAnAdmin)")
        b = snap.backend or {}
        ready = b.get("npcap") and b.get("etw") and not (b.get("admin_only") and not b.get("administrator"))
        here[("Basic functions", "Watch events (ring buffer, perf buffer, printk)")] = cell(
            "the watch service: Npcap and ETW" + ("" if ready else ", not all of it ready here"),
            "read from wpcap.dll, Npcap's AdminOnly option and this process's token")
        return here

    # -- Functions -------------------------------------------------------------------------------------------------
    def functions(self) -> dict:
        """The Functions tab: the comparison's nine basic functions, how each is done on Linux and on Windows and the
        rights it needs, what this plugin offers of each here, and the forms of those it offers (the buttons at the
        top). What the last read says cannot run here is shown so, its button disabled with why: on Windows every
        change; on Linux what WSL 1, a missing bpftool, root refused or no BPF filesystem keeps from running, and
        everything where the runtime does not apply (the user, 2026-11-15: "if wsl prevents or misses some capability
        this should reflect in the plugin")."""
        self._needs_libs()
        snap = self.snapshot(wait=FIRST_WAIT_S)
        refused = self._no_change(snap) if self.system == "windows" else ""
        gates = self._gates(snap, refused)
        rows = []
        for r in capabilities.functions(SOURCES):
            rows.append([cell(r["item"], r.get("source") or None), point(r["linux"]), point(r["windows"]),
                         self._offered(r["item"], snap, gates, refused)])
        marked = self._marked(snap)
        columns = [{"title": "Function"}, {"title": "Linux" + (" (this machine)" if marked == "linux" else "")},
                   {"title": "Windows" + (" (this machine)" if marked == "windows" else "")}, {"title": "Here"}]
        note = (f"How each is done on Linux and on Windows, and the rights it needs; Here, what this plugin offers of "
                f"it on this machine ({self._this_machine(snap)}).")
        if refused:
            note += f" Every change is refused here: {refused}"
        elif gates:
            note += " What the last read says cannot run here is said so, with why."
        return {"title": "Basic functions", "note": note,
                "tables": [{"title": "The basic functions", "columns": columns, "rows": rows}],
                "forms": forms(), "actions": self._function_buttons(gates)}

    def _not_here(self, snap: Snapshot | None) -> str:
        """Why nothing of this machine's runtime is there to offer, in words ("" when something is): a read that
        failed, a runtime that does not apply here, WSL 1."""
        if snap is None:
            return ""
        if snap.error:
            return f"this machine's status could not be read: {snap.error}"
        if self.system != "windows" and snap.status.get("applies") is False:
            return str(snap.status.get("why") or "the eBPF runtime does not apply here")
        if self.system != "windows" and wsl1(snap.wsl):
            return NO_KERNEL
        return ""

    def _gates(self, snap: Snapshot | None, refused: str) -> dict[str, str]:
        """The forms the last read says cannot run here, each with why: {form: words}. On Windows every change (and
        the reads where eBPF for Windows is not installed, netsh cannot be read or cannot dump). On Linux: all six
        where the runtime does not apply or under WSL 1; show, dump, load, attach and detach where bpftool did not
        answer or was refused as root (its listing said so, in sudo's words); unload where no BPF filesystem is at
        /sys/fs/bpf (no pin can be there). Not on `sudo -n true` alone: a sudoers rule may let bpftool run without a
        password while `true` asks for one. Nothing before the first read, or after one that failed."""
        if self.system == "windows":
            out = dict.fromkeys(("load", "attach", "detach", "unload"), refused)
            if not_installed(snap):
                out["show"] = out["dump"] = "eBPF for Windows is not installed"
            else:
                listing = str(snap.unread.get("programs") or "") if snap is not None else ""
                if listing:
                    out["show"] = listing
                out["dump"] = NETSH_DUMP
            return out
        if snap is None or snap.error:
            return {}
        s = snap.status
        gone = self._not_here(snap)
        if gone:
            return dict.fromkeys(("show", "dump", "load", "attach", "detach", "unload"),
                                 f"{gone}: nothing is shown, dumped, loaded, attached, detached or unloaded here")
        out: dict[str, str] = {}
        uses_bpftool = ("show", "dump", "load", "attach", "detach")
        if not s.get("present"):  # what to do about it is Main's bpftool row
            out.update(dict.fromkeys(uses_bpftool, "bpftool did not answer here (bpftool -j version, as the "
                                                   "platform's user and through sudo -n): see Main's bpftool row"))
        elif snap.refused:
            words = next((snap.unread[n] for n in snap.listed if n in snap.unread), "")
            out.update(dict.fromkeys(uses_bpftool, f"bpftool was refused as root here, listing: {words}"))
        if BPF_FS not in (s.get("bpffs") or ()):
            out["unload"] = f"the BPF filesystem is not mounted at {BPF_FS} (/proc/mounts): no pin is there to remove"
        return out

    def _offered(self, item: str, snap: Snapshot | None, gates: dict, refused: str):
        windows = self.system == "windows"
        absent = windows and not_installed(snap)
        unread = snap.unread if snap is not None else {}
        gone = self._not_here(snap)
        if item == "Runtime status and version":
            if gone:  # Main says why there is no runtime to read here
                return cell("on Main", gone)
            return cell("on Main", "its services and version, and whether a test-signed driver can load here" if windows
                        else "the kernel's release, bpftool and libbpf, unprivileged BPF and the JIT, BTF, the BPF "
                        "filesystem and bpftrace")
        if item == "List programs, maps and links":
            if absent:
                return cell("none here", "eBPF for Windows is not installed")
            if gone:
                return cell("not here", gone)
            why = next((unread[n] for n in OBJECTS if n in unread), "")
            if windows and snap is not None and not snap.status.get("services"):
                why = "eBPF for Windows' services could not be read"
            return cell("on Main", f"not listed now: {why}" if why else "its Programs, Maps and Links tables, " + (
                "netsh ebpf show (an administrator's)" if windows else "listed as root"))
        if item == "Show a program's info":
            if absent:
                return cell("nothing to show", "eBPF for Windows is not installed")
            if gates.get("show"):
                return cell("not here", gates["show"])
            return {"form": "show", "title": "Show…", "label": "Show a program"}
        if item == "Dump or read a map":
            if absent:
                return cell("nothing to dump", "eBPF for Windows is not installed")
            if windows:
                return cell("not offered here", NETSH_DUMP)
            if gates.get("dump"):
                return cell("not here", gates["dump"])
            return {"form": "dump", "title": "Dump…", "label": "Dump a map"}
        rights = self._rights(snap)
        if item == "Load and attach a pre-built program":
            if windows:
                return cell("refused here", refused)
            if gates.get("load"):
                return cell("not here", gates["load"])
            return cell("Load… and Attach…, above", "a load is always asked twice; an XDP or cgroup attach, and "
                        "one that replaces another, too" + rights)
        if item == "Detach and unload":
            if windows:
                return cell("refused here", refused)
            detach, unload = gates.get("detach"), gates.get("unload")
            if detach and unload:
                return cell("not here", detach if detach == unload else f"detach: {detach}; unload: {unload}")
            if detach:
                return cell("Unload…, above; Detach… not here", f"detach: {detach}")
            if unload:
                return cell("Detach…, above; Unload… not here", f"unload: {unload}")
            return cell("Detach… and Unload…, above", "the unload of a pin that is not Liminal's own is asked twice"
                        + rights)
        if item == "Watch events (ring buffer, perf buffer, printk)":
            if gone:
                return cell("not here", gone)
            if not windows and snap is not None and snap.watch and snap.watch != "yes":
                return cell("the watch service: cannot run here", linux_watch_words(snap)[1] + "; not a form here")
            return cell("the watch service", ("Npcap and ETW, not eBPF" if windows else "bpftrace's scripts")
                        + ", while the firewalls' Filter tabs or trapdoor read: not a form here")
        return cell("not offered yet", "the library has no call for it yet")

    @staticmethod
    def _rights(snap: Snapshot | None) -> str:
        """How the changes run here, as the last read found it: as root, through sudo -n, or bpftool alone through it
        (a sudoers rule letting it run without a password while `sudo -n true` asks for one)."""
        if snap is None or snap.system == "windows":
            return ""
        if snap.sudo == "root":
            return "; the platform is root: they run as it is"
        if snap.sudo == "yes":
            return f"; {ROOT}"
        if snap.sudo == "password" and snap.listed and not snap.refused:
            return ("; bpftool runs as root here through sudo -n (it listed so), though sudo -n true asks for a "
                    "password: a dump (sh) and an unload (rm) run only where sudoers lets them")
        return ""

    @staticmethod
    def _function_buttons(gates: dict) -> list[dict]:
        """The buttons opening the forms; those the last read says cannot run here disabled, with why."""
        buttons = [{"form": "show", "title": "Show a program…"}, {"form": "dump", "title": "Dump a map…"},
                   {"form": "load", "title": "Load…"}, {"form": "attach", "title": "Attach…"},
                   {"form": "detach", "title": "Detach…"}, {"form": "unload", "title": "Unload…"}]
        return [{**b, "disabled": True, "note": gates[b["form"]]} if gates.get(b["form"]) else b for b in buttons]

    def _no_change(self, snap: Snapshot | None) -> str:
        """Why no change is made on Windows, in words: what holds on any machine (every public build is
        test-signed), then what this PC's last read found."""
        found = []
        f = (snap.facts or {}) if snap is not None else {}
        if f.get("secure_boot") is True:
            found.append(f"Secure Boot is on (read from {secure_boot_words(f, snap.elevated)[1].split(' (')[0]})")
        if f.get("hvci") is True:
            found.append("memory integrity is on (Win32_DeviceGuard), so only signed native .sys programs load")
        words = ("eBPF for Windows' public builds are all test-signed, and Windows loads a test-signed driver only in "
                 "test-signing mode, which needs Secure Boot off")
        if found:
            words += ": on this PC " + " and ".join(found)
        if not_installed(snap):
            words += "; eBPF for Windows is not installed here either"
        return words + ". This plugin loads, attaches, detaches and unloads nothing on Windows: on Linux it does."

    def _refuse_on_windows(self) -> None:
        if self.system == "windows":
            with self._rt.lock:
                snap = self._rt.snap
            raise ValueError(self._no_change(snap))
        self._refuse_without_kernel()

    def _refuse_without_kernel(self) -> None:
        """Under WSL 1, as the last read found it: no Linux kernel, so nothing is shown, dumped or changed (an unload's
        rm -f would answer as if it had removed a pin), said in words."""
        if self.system == "windows":
            return
        with self._rt.lock:
            snap = self._rt.snap
        if snap is not None and wsl1(snap.wsl):
            raise ValueError(f"{NO_KERNEL}: nothing is shown, dumped, loaded, attached, detached or unloaded here")

    # -- the functions' hooks --------------------------------------------------------------------------------------
    def show_program(self, prog_id) -> dict:
        """One loaded program by its id, every field of it: bpftool -j prog show id, as root (on Windows netsh ebpf
        show programs id= level=verbose, an administrator's)."""
        self._needs_libs()
        n = whole(prog_id, "a program's id")
        self._refuse_without_kernel()
        if self.system == "windows":
            with self._rt.lock:
                snap = self._rt.snap
            if not_installed(snap):
                raise ValueError("eBPF for Windows is not installed here: there is no program to show")
        found = plain(self._runtime.program(n) or {})
        if not found and self.system == "windows":
            # the Windows runtime answers nothing only when netsh could not be read (a read that works always gives
            # something): that is not a program missing
            if not is_elevated():
                raise LookupError(f"program {n} could not be read: netsh ebpf show programs needs an administrator, "
                                  "and the platform runs without one")
            raise LookupError(f"program {n} could not be read: netsh ebpf show programs id={n} answered nothing it "
                              "could read (no program has that id, or netsh failed)")
        if not found:
            raise LookupError(f"no program has the id {n}")
        lines = [f"{k}: {compact(v)}" for k, v in found.items()][:LINES]
        what = ", ".join(str(found[k]) for k in ("name", "type") if found.get(k))
        return {"said": f"program {n}" + (f": {what}" if what else ""), "lines": lines, "ok": True, "program": found}

    def dump(self, map_id, limit=DUMP_LIMIT) -> dict:
        """A map's first `limit` entries (DUMP_LIMIT at most: a map can hold millions): bpftool -j map dump id, as
        root, at most 8 MB of its output read. On Windows netsh lists maps but cannot read one, so a dump there is
        empty and says why."""
        self._needs_libs()
        n = whole(map_id, "a map's id")
        most = DUMP_LIMIT if blank(limit) else whole(limit, "the entries to read", 1, DUMP_LIMIT)
        self._refuse_without_kernel()
        if self.system == "windows":
            with self._rt.lock:
                snap = self._rt.snap
            said = ("eBPF for Windows is not installed here: there is no map to dump" if not_installed(snap) else
                    f"{NETSH_DUMP}: nothing is dumped on Windows")
            return {"said": said, "lines": [], "ok": True, "entries": []}
        entries = [plain(e) for e in self._runtime.dump_map(n, most)]
        lines = [entry_line(e) for e in entries[:LINES]]
        said = f"map {n}: {plural(len(entries), 'entry', 'entries')}" + (
            f", the first {most:,}" if len(entries) >= most else "") + (
            f"; the first {LINES} shown, all of them in the answer" if len(entries) > LINES else "")
        return {"said": said, "lines": lines, "ok": True, "entries": entries}

    def load_program(self, path, pin=None, type=None, accept_load=False) -> dict:
        """A pre-built program (an ELF .o) loaded into this machine's kernel and pinned: bpftool prog load, as root
        through sudo -n. `pin` is a path under /sys/fs/bpf (by default /sys/fs/bpf/liminal_<the file's name>);
        `type` bpftool's program type word, when the file's sections do not say. Always asked twice (accept_load):
        the design's "Loading eBPF programs is a confirmed action", and a loaded program runs inside the kernel."""
        self._needs_libs()
        self._refuse_on_windows()
        file = program_path(path)
        where = default_pin(file) if blank(pin) else pin_of(pin)
        kind = None if blank(type) else word(type, "a program type")
        if accept_load is not True:
            raise RiskRefused(f"loading a program into the kernel is asked twice: {file} would be checked by the "
                              f"kernel's verifier, loaded as root and pinned at {where}, where it stays until it is "
                              "unloaded or the machine restarts" + self._mount_words(), "accept_load")
        return self._change(f"{file} loaded and pinned at {where}",
                            lambda: self._runtime.load(file, pin=where, type=kind))

    def attach_program(self, kind, target=None, pin=None, prog_id=None, map_id=None, flags=None, overwrite=False,
                       accept_attach=False) -> dict:
        """A loaded program, named by its pin or its id, attached as root through sudo -n: XDP or tcx on a network
        device (bpftool net attach; `overwrite` replaces a program attached there), a sockmap's or the flow
        dissector's (bpftool prog attach, the sockmap's `map_id`), else a cgroup hook on a cgroup v2 folder (bpftool
        cgroup attach, `flags` multi or override). Asked twice (accept_attach) for XDP, for a cgroup hook and for
        an overwrite: each changes what every packet or every process meets."""
        self._needs_libs()
        self._refuse_on_windows()
        k = word(kind, "the attach type")
        prog_pin, prog = which_program(pin, prog_id)
        replacing = yes_no(overwrite, "overwrite")
        risky: list[str] = []
        if k in NET_KINDS:
            if not blank(map_id) or not blank(flags):
                raise ValueError(f"an attach of {k} goes on a network device: it takes no sockmap and no flag")
            on = device(target)
            where, sock, flag = f"{on} ({k})", None, None
            if k in XDP_KINDS:
                risky.append(f"an XDP program on {on} sees every packet it receives, before the rest of the kernel, "
                             "and may drop it")
            if replacing:
                risky.append(f"it replaces the program attached to {on} already")
        else:
            if replacing:
                raise ValueError("overwrite is an XDP or tcx attach's, on a network device")
            if k in PROG_KINDS:
                if not blank(target) or not blank(flags):
                    raise ValueError(f"an attach of {k} takes no target and no flag" + (
                        ": it goes on its sockmap (map_id)" if k in SOCKMAP_KINDS else ""))
                sock, on, flag = optional_whole(map_id, "the sockmap's id"), None, None
                if sock is None and k != "flow_dissector":
                    raise ValueError(f"an attach of {k} needs the sockmap's id (map_id)")
                where = f"sockmap {sock} ({k})" if sock is not None else "this network namespace's flow dissector"
            else:
                if not blank(map_id):
                    raise ValueError("a sockmap's id is a sk_msg or sk_skb attach's")
                on, flag, sock = cgroup_folder(target), flag_of(flags), None
                where = f"{on} ({k})"
                risky.append(f"a program on the cgroup hook {k} runs for every process in {on}" + (
                    ", which is every process on this machine" if on == "/sys/fs/cgroup" else ""))
        if risky and accept_attach is not True:
            raise RiskRefused("; ".join(risky) + ": an attach like this is asked twice", "accept_attach")
        named = prog_pin or f"program {prog}"
        return self._change(f"{named} attached to {where}", lambda: self._runtime.attach(
            kind=k, target=on, pin=prog_pin, prog_id=prog, flags=flag, map_id=sock, overwrite=replacing))

    def detach_program(self, link_id=None, kind=None, target=None, pin=None, prog_id=None, map_id=None) -> dict:
        """An attachment detached as root through sudo -n, the way it was made: a link by its id (bpftool link
        detach), else the attach type with its target (XDP and tcx: the device; a cgroup hook: the folder and the
        program; a sockmap's: the program and the sockmap). Confirmed once."""
        self._needs_libs()
        self._refuse_on_windows()
        link = optional_whole(link_id, "a link's id")
        if link is not None:
            if not all(blank(x) for x in (kind, target, pin, prog_id, map_id)):
                raise ValueError("say what to detach one way: a link's id alone, or the attach type with its target")
            return self._change(f"link {link} detached", lambda: self._runtime.detach(link_id=link))
        if blank(kind):
            raise ValueError("say what to detach: a link's id, or the attach type with its target")
        k = word(kind, "the attach type")
        if k in NET_KINDS:
            if not all(blank(x) for x in (pin, prog_id, map_id)):
                raise ValueError(f"an attachment of {k} is detached from its device alone")
            on = device(target)
            return self._change(f"{k} detached from {on}", lambda: self._runtime.detach(kind=k, target=on))
        prog_pin, prog = which_program(pin, prog_id)
        named = prog_pin or f"program {prog}"
        if k in PROG_KINDS:
            sock = optional_whole(map_id, "the sockmap's id")
            if sock is None and k != "flow_dissector":
                raise ValueError(f"an attachment of {k} is detached with its sockmap's id (map_id)")
            return self._change(f"{named} detached ({k})", lambda: self._runtime.detach(
                kind=k, pin=prog_pin, prog_id=prog, map_id=sock))
        if not blank(map_id):
            raise ValueError("a sockmap's id is a sk_msg or sk_skb attachment's")
        on = cgroup_folder(target)
        return self._change(f"{named} detached from {on} ({k})", lambda: self._runtime.detach(
            kind=k, target=on, pin=prog_pin, prog_id=prog))

    def unload_program(self, pin, accept_unload=False) -> dict:
        """A program unloaded by removing its pin (rm -f, as root through sudo -n): the kernel frees it once nothing
        else holds it. A pin that is not Liminal's own (/sys/fs/bpf/liminal_*) is asked twice (accept_unload), as the
        library says a plugin does: what pinned it may rely on it."""
        self._needs_libs()
        self._refuse_on_windows()
        where = pin_of(pin)
        if not liminal_pin(where) and accept_unload is not True:
            raise RiskRefused(f"{where} is not one of Liminal's own pins ({BPF_FS}/{PIN_PREFIX}*): what pinned it may "
                              "rely on it, so removing it is asked twice", "accept_unload")
        return self._change(f"{where} removed: its program unloads once nothing else holds it",
                            lambda: self._runtime.unload(pin=where))

    def _mount_words(self) -> str:
        """For a load's second ask, the root change bpftool makes before it: where the last read found no BPF
        filesystem at /sys/fs/bpf (/proc/mounts), bpftool mounts one there first (bpftool's own rule, unless --nomount);
        said as a condition before anything is read; nothing where it is mounted."""
        with self._rt.lock:
            snap = self._rt.snap
        if snap is None or snap.error:
            return f"; where the BPF filesystem is not mounted at {BPF_FS}, {MOUNTS_ITSELF}"
        if BPF_FS in (snap.status.get("bpffs") or ()):
            return ""
        return f"; the BPF filesystem is not mounted at {BPF_FS} (/proc/mounts), so {MOUNTS_ITSELF}"

    def _change(self, said: str, run) -> dict:
        """A change run (the runtime builds the command and runs it as root), then the runtime read again at once,
        whatever it did: Main shows what is there now. CommandError, in bpftool's or sudo's words, when it failed."""
        try:
            out = run()
        finally:
            self.read()
        return {"said": said, "lines": output_lines(out), "ok": True}

    # -- the watch service (never drawn on the page) ---------------------------------------------------------------
    def watch_start(self, kinds, spec=None) -> dict:
        """A watch of this caller's own (watch_service.WatchService.start): {"id", "kinds", "system", "address",
        "timeout", "stopped", "error"}. ValueError, in words, for kinds or a spec it does not take, while 8 watches
        run, and once the plugin was detached (until it is attached again). On Linux `spec["pid"]` is matched against
        bpftrace's pid, the kernel's numbering: inside a WSL distribution (a pid namespace of its own) that is not the
        pid ps shows there, so give one an event showed (a process watch's exec)."""
        self._needs_libs()
        service = self._rt.service
        with self._rt.lock:
            if self._rt.detached:
                raise ValueError(DETACHED)
        answer = service.start(kinds, spec)
        with self._rt.lock:
            late = self._rt.detached
        if late:  # detached while it started: stopped, as every other watch was
            service.stop(answer["id"])
            raise ValueError(DETACHED)
        return answer

    def watch_read(self, watch_id, since=0) -> dict:
        """What a watch saw after `since`, its events as plain JSON with their wall time (WatchService.read): {"id",
        "seq", "events", "lost", "stopped", "error", "stats"}. Each read keeps it going."""
        return self._rt.service.read(watch_id, since)

    def watch_stop(self, watch_id) -> dict:
        """A watch ended now and its id let go (WatchService.stop): {"id", "stopped", "error"}; a second stop answers
        the same."""
        return self._rt.service.stop(watch_id)

    # -- what it learned of its APIs -------------------------------------------------------------------------------
    def _linux_facts(self, snap: Snapshot) -> dict:
        s = snap.status
        if s.get("applies") is False:
            return {KERNEL.name: {"This machine": str(s.get("why") or "not Linux"), "Last read": self._read_at(snap)}}
        listed = {n.capitalize(): plural(len(snap.objects[n]), n[:-1]) if n in snap.objects else
                  f"not listed: {snap.unread.get(n) or 'not asked'}" for n in OBJECTS}
        probes = {}
        if snap.lacking is not None:  # the kernel functions the watch scripts' kprobes need, read from /proc/kallsyms
            probes["The watch's kprobes"] = "; ".join(
                f"{kind}: {', '.join(functions)} missing" for kind, functions in snap.lacking.items()) or "all there"
        return {BPFTOOL.name: {"Version": " — ".join(x for x in bpftool_words(s, snap.wsl) if x), **listed,
                               "Last read": self._read_at(snap)},
                BPFTRACE.name: {"Version": bpftrace_words(s, snap)[0],
                                "The watch": " — ".join(linux_watch_words(snap))},
                KERNEL.name: {"Release": str(s.get("kernel") or "not read"),
                              "unprivileged_bpf_disabled": unprivileged_words(s.get("unprivileged_bpf_disabled"))[0],
                              "bpf_jit_enable": jit_words(s.get("bpf_jit_enable"))[0],
                              "Kernel BTF": btf_words(s.get("btf"))[0],
                              "BPF filesystem": bpffs_words(s.get("bpffs"))[0], **probes,
                              **({"Under WSL": f"WSL {snap.wsl.get('generation') or 2}: {wsl_name(snap.wsl)}"}
                                 if snap.wsl else {})}}

    def _windows_facts(self, snap: Snapshot) -> dict:
        s, f, b = snap.status, snap.facts or {}, snap.backend or {}
        services = [x for x in s.get("services") or () if isinstance(x, dict)]
        out = {EBPF_WINDOWS.name: {
            "Installed": ("yes" + (f", v{s['version']}" if s.get("version") else "")) if snap.installed else
            "no" if services else f"not read: {s.get('why') or ''}",
            "Services": "; ".join(f"{x.get('name')} {(x.get('status') or 'present') if x.get('present') else 'absent'}"
                                  for x in services) or "not read",
            "Secure Boot": secure_boot_words(f, snap.elevated)[0], "Memory integrity": hvci_words(f)[0],
            "Test signing": signing_words(f) + (f", read from {signing_from(f)}" if signing_from(f) else ""),
            "Can it load here": " — ".join(x for x in verdict_words(f) if x),
            "Last read": self._read_at(snap)}}
        if b:
            out[NPCAP.name] = {"wpcap.dll": "installed" if b.get("npcap") else "not installed",
                               "Administrators only": "yes" if b.get("admin_only") else "no"}
            out[ETW.name] = {"Real-time session": ("may start here" if b.get("etw") else "cannot start here")
                             + (f": {b['etw_why']}" if b.get("etw_why") else "")}
        return out

    def _watch_facts(self) -> dict:
        """The watches running now (WatchService.live: asking keeps none going), under what each reads with, out of
        the service's own cap. A watch whose source ended stops, so running is reading: on Linux when bpftrace ends,
        on Windows when its capture or ETW session is lost (LOST_SAID)."""
        service = self._rt.service
        live = service.live()

        def said(watches, none: str) -> str:
            if not watches:
                return f"{none} (at most {service.cap} at once)"
            return f"{len(watches)} of {service.cap}: " + "; ".join(
                f"{'+'.join(w['kinds'])} since {when(w['started'])}" for w in watches)
        if self.system == "windows":
            return {NPCAP.name: {"Net watches running": said([w for w in live if "net" in w["kinds"]], "none")},
                    ETW.name: {"Watches running": said(live, "none")}}
        return {BPFTRACE.name: {"Watches running": said(live, "none running")}}


def entry_line(entry) -> str:
    """One of a map's entries (bpftool -j map dump) as a line: its key and its value, else all of it."""
    if isinstance(entry, dict) and "key" in entry and "value" in entry:
        return f"{compact(entry['key'])} → {compact(entry['value'])}"
    return compact(entry)


def sizes(m: dict) -> str:
    """A map's key and value sizes (bpftool -j map show), in bytes."""
    if "bytes_key" in m and "bytes_value" in m:
        return f"{m['bytes_key']} B → {m['bytes_value']} B"
    return "–"


def attached_to(link: dict) -> str:
    """Where a link (bpftool -j link show) is attached, in its own words: its attach type and its device, cgroup or
    target."""
    parts = [str(link[k]) for k in ("attach_type", "devname", "target_name", "tp_name") if link.get(k)]
    if link.get("ifindex") and not link.get("devname"):
        parts.append(f"ifindex {link['ifindex']}")
    if link.get("cgroup_id"):
        parts.append(f"cgroup {link['cgroup_id']}")
    return ", ".join(parts) or "–"


MACHINE = EbpfPlugin()
