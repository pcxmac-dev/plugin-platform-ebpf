"""The eBPF plugin driven on stand-in machines (nothing here runs bpftool, bpftrace, PowerShell, sudo or wsl.exe, loads
Npcap, starts ETW, opens a port or reaches the network: conftest refuses each, and fails a test that reaches one): the
runtime picked by the system the platform runs on; the status valid on every machine and never a bare problem, read on
a thread and kept, its facts and tables on Linux, inside WSL and on Windows (this PC's: eBPF for Windows not installed,
Secure Boot and memory integrity on, test signing off, read from this boot's start options); a liminal-libs older than
the plugin's floor said, and the plugin then not valid; root's rights read from each
command the plugin runs, not from `sudo -n true` alone, and the watch's from its own command; the Compare tab's 65
points by area with their sources, and a Here column only from what was read, each naming the read it came from; the
Functions tab, its forms asking each hook with its arguments in order, and what the last read says cannot run disabled
with why; the changes asked twice where they are risky (exactly true accepts them), run as root through sudo -n, and
refused in words on Windows and under WSL 1; the reads (a program shown, a map dumped); the watch service's hooks, the
cap, the detach stopping every watch quickly and letting the app go, and the ETW sessions reclaimed at the first attach
on the platform; a one-shot command's attach reading nothing; what api_facts says, asking nothing; every answer plain
JSON; and the command line."""
from __future__ import annotations

import inspect
import json
import os
import re
import sys
import threading
import time

import pytest

import plugin_platform_ebpf as plugin
import plugin_platform_ebpf.__main__ as cli
from liminal_libs import capture
from liminal_libs.ebpf import capabilities
from liminal_libs.ebpf.linux import LinuxRuntime
from liminal_libs.ebpf.watch import Watch
from liminal_libs.ebpf.windows import WindowsRuntime
from liminal_libs.machines import etw, linux as machines_linux, world
from liminal_libs.machines.plugin import CommandError
from liminal_libs.sources.apis import facts_of
from plugin_platform_ebpf import MACHINE, SOURCES, EbpfPlugin, RiskRefused, windows_backend  # the real one: see below
from plugin_platform_ebpf import watch_service

from conftest import NO_SUDO, SYMBOLS

REAL_OS_IDS = plugin.os_ids  # bound as this module is imported: conftest stands in for it in every test
WATCH_HOOKS = ("watch_start", "watch_read", "watch_stop")
WATCH_ITEM = "Watch events (ring buffer, perf buffer, printk)"
KERNEL_CARD = "The Linux kernel — bpf(2) and BTF"
WSL2 = "6.18.58.1-microsoft-standard-WSL2"
THIS_PC = ("eBPF for Windows' public builds are all test-signed, and Windows loads a test-signed driver only in "
           "test-signing mode, which needs Secure Boot off: on this PC Secure Boot is on (read from the registry) and "
           "memory integrity is on (Win32_DeviceGuard), so only signed native .sys programs load; eBPF for Windows is "
           "not installed here either. This plugin loads, attaches, detaches and unloads nothing on Windows: on Linux "
           "it does.")
# the library's Shell, refusing a command sudo -n asks a password for
ROOT_REFUSED = ("bpftool needs root on this machine: run the platform as root, or let sudo run it without a password "
                "(sudo: a password is required)")
NO_TOOL = ("bpftool did not answer here (bpftool -j version, as the platform's user and through sudo -n): see Main's "
           "bpftool row")
NO_PINS = "the BPF filesystem is not mounted at /sys/fs/bpf (/proc/mounts): no pin is there to remove"
MOUNTS = "bpftool mounts it there first, as root (it stays mounted until it is unmounted or the machine restarts)"
LINUX_HERE = {("Install and status", "Current version"), ("Execution", "Interpreter / JIT / native"),
              ("Loading", "Pinning"), ("Loading", "BTF and CO-RE"), ("Loading", "bpftool"),
              ("Privileges", "Load and attach"), ("Privileges", "List and read"), ("Basic functions", WATCH_ITEM)}
WINDOWS_HERE = {("Install and status", "Where it comes from"), ("Install and status", "Current version"),
                ("Install and status", "Production or preview"), ("Execution", "HVCI (memory integrity)"),
                ("Execution", "Interpreter / JIT / native"), ("Execution", "Signing and test signing"),
                ("Privileges", "Load and attach"), ("Basic functions", WATCH_ITEM)}


def plain(answer):
    """The answer, checked to be plain JSON: it round-trips json.dumps with no NaN and no default."""
    assert json.loads(json.dumps(answer, allow_nan=False)) == answer
    return answer


def text(c):
    """A table cell's text (a cell is its text, or {text, sub})."""
    return c["text"] if isinstance(c, dict) else c


def table(page, title):
    return next(t for t in page["tables"] if t["title"] == title)


def by_first(t) -> dict:
    """A table's rows by their first cell's text."""
    return {text(r[0]): r for r in t["rows"]}


def here_of(page) -> dict:
    """The Compare page's Here cells by (area, item), those that say something."""
    return {(t["title"], text(r[0])): r[3] for t in page["tables"] if len(t["columns"]) == 4 for r in t["rows"]
            if r[3] != "–"}


def offered(page) -> dict:
    """The Functions page's Here cells by function."""
    return {text(r[0]): r[3] for r in page["tables"][0]["rows"]}


def disabled(page) -> dict:
    """The Functions page's disabled buttons: {form: why}."""
    return {a["form"]: a["note"] for a in page["actions"] if a.get("disabled")}


def settled() -> None:
    """The reading thread done."""
    deadline = time.monotonic() + 5
    while any(t.name == plugin.READER and t.is_alive() for t in threading.enumerate()):
        assert time.monotonic() < deadline, "the read did not end"
        time.sleep(0.005)


def wsl(monkeypatch, name="Ubuntu", generation=2, systemd=True, ids=("ubuntu", "debian")):
    """This Linux a WSL distribution, as the library's 1.57.0 helpers would say it, and /etc/os-release's ID words."""
    monkeypatch.setattr(machines_linux, "wsl", lambda release=None, env=None: name, raising=False)
    monkeypatch.setattr(machines_linux, "wsl_generation", lambda release=None: generation, raising=False)
    if systemd is None:  # a library that cannot say: not read
        monkeypatch.delattr(machines_linux, "systemd_runs", raising=False)
    else:
        monkeypatch.setattr(machines_linux, "systemd_runs", lambda: systemd, raising=False)
    monkeypatch.setattr(plugin, "os_ids", lambda: tuple(ids))


class App:
    """An app a plugin is attached to: its NAME (the platform's, the charts app's), and `once` (a one-shot command)."""

    def __init__(self, name="platform", once=False):
        self.NAME, self.once = name, once


# -- the runtime, and nothing run to make it ---------------------------------------------------------------------

def test_the_runtime_is_picked_by_the_system_the_platform_runs_on():
    class Given:
        system = "windows"
    assert isinstance(EbpfPlugin(system="linux")._runtime, LinuxRuntime)
    assert isinstance(EbpfPlugin(system="windows")._runtime, WindowsRuntime)
    assert EbpfPlugin(Given()).system == "windows"  # a runtime's own word
    assert EbpfPlugin(Given(), system="linux").system == "linux"  # a test's word first
    with pytest.raises(ValueError, match=r"^a system is linux or windows, not 'darwin'$"):
        EbpfPlugin(system="darwin")
    here = "windows" if os.name == "nt" else "linux"
    assert MACHINE.system == here
    assert isinstance(MACHINE._runtime, WindowsRuntime if here == "windows" else LinuxRuntime)
    assert MACHINE._rt.service.system == here  # its watches are this machine's too (make_watch's rule)
    assert MACHINE._where == sys.platform  # whether this machine is Linux at all: sys.platform's word
    other = "linux" if here == "windows" else "windows"
    assert EbpfPlugin(system=other)._where == {"linux": "linux", "windows": "win32"}[other]  # a test's system's own


# -- Main, on Linux ----------------------------------------------------------------------------------------------

def test_on_linux_the_status_is_valid_and_says_what_was_read(linux):
    p, fake, _ = linux()
    s = plain(p.status())
    assert s["valid"] is True and s["present"] is True and "problem" not in s and "why" not in s
    assert s["summary"] == "Linux 6.8.0-45-generic: bpftool 7.4.0, bpftrace, kernel BTF"
    assert (s["runtime"], s["bpftool"], s["btf"], s["jit"], s["unprivilegedBpf"], s["bpfFilesystem"], s["bpftrace"],
            s["root"]) == ("the Linux kernel's own (6.8.0-45-generic)", "7.4.0", "yes", "1: on", "2: off",
                           "mounted at /sys/fs/bpf", "bpftrace v0.20.2", "sudo -n true runs without a password")
    assert s["watch"].startswith("bpftrace, through sudo -n — sudo -n bpftrace -V answered (bpftrace v0.20.2): a watch "
                                 "runs while a Filter tab or trapdoor reads it")
    kernel, programs, maps, links = s["tables"]
    rows = by_first(kernel)
    assert list(rows) == ["Kernel release", "bpftool", "Unprivileged BPF", "JIT", "Kernel BTF", "BPF filesystem",
                          "bpftrace", "Root", "The watch"]
    assert rows["bpftool"][1:] == [{"text": "7.4.0", "sub": "libbpf 1.4; built with llvm, skeletons"},
                                   "bpftool -j version"]
    assert rows["Unprivileged BPF"][2] == "/proc/sys/kernel/unprivileged_bpf_disabled"
    assert rows["bpftrace"][2] == "bpftrace -V, as the platform's user"
    assert rows["Root"][2] == "sudo -n true"
    assert rows["The watch"][2] == "sudo -n bpftrace -V, the watch's own command; /proc/kallsyms"
    assert programs["rows"][0][:4] == [12, "cgroup_device", "sd_devices", "e3dbd137be8d6168"]
    assert programs["rows"][0][-1] == {"form": "show", "title": "Show…", "values": {"prog_id": 12},
                                       "label": "Show program 12"}
    assert maps["rows"][0][3:5] == ["4 B → 8 B", 1024]
    assert maps["rows"][0][-1] == {"form": "dump", "title": "Dump…", "values": {"map_id": 3, "limit": 1000},
                                   "label": "Dump map 3"}
    assert links["rows"][0][:4] == [7, "xdp", 31, "eth0"]
    assert links["rows"][0][-1] == {"form": "detach", "title": "Detach…", "values": {"link_id": 7},
                                    "label": "Detach link 7"}
    assert programs["note"].endswith(": bpftool -j prog show, as root")
    # the kernel's files and the versions as the platform's user; sudo -n asked; the listings as root; and the
    # watch's own command, through sudo as the watch runs it
    assert (False, ["uname", "-r"]) in fake.commands and (False, ["bpftool", "-j", "version"]) in fake.commands
    assert (True, ["true"]) in fake.commands and (True, ["bpftool", "-j", "prog", "show"]) in fake.commands
    assert (True, ["bpftool", "-j", "map", "show"]) in fake.commands and (True, ["bpftrace", "-V"]) in fake.commands
    assert fake.changes == []
    assert [f["id"] for f in s["forms"]] == ["show", "dump", "load", "attach", "detach", "unload"]
    assert s["actions"] == [{"hook": "refresh", "args": [], "title": "Read again",
                             "note": "reads this machine's eBPF runtime now"}]


def test_without_its_tools_or_sudo_the_plugin_is_still_valid_and_says_what_is_missing(linux):
    p, fake, _ = linux(bpftool=False, bpftrace=False, btf=False, mounts="", password=True, unprivileged="1", jit="0")
    s = plain(p.status())
    assert s["valid"] is True and s["present"] is False and "problem" not in s
    assert s["summary"] == ("Linux 6.8.0-45-generic: no bpftool, no bpftrace, no kernel BTF, the BPF filesystem not "
                            "mounted, sudo -n true asks for a password, the watch cannot run")
    assert s["root"] == "sudo -n true asks for a password"
    assert s["watch"] == ("cannot run here — sudo -n bpftrace -V was refused (sudo: a password is required): the watch "
                          "runs bpftrace through sudo -n, so it runs once sudo lets the platform's user run bpftrace "
                          "without a password")
    rows = by_first(s["tables"][0])
    assert rows["bpftool"][1] == {"text": "did not answer", "sub": "it is not installed here: the distribution's "
                                                                   "bpftool package"}
    assert rows["JIT"][1] == {"text": "0: off", "sub": "programs run in the kernel's interpreter"}
    assert text(rows["Unprivileged BPF"][1]) == "1: off until the next boot" and text(rows["Kernel BTF"][1]) == "no"
    assert rows["BPF filesystem"][1] == {"text": "not mounted", "sub": f"a load pins its program under /sys/fs/bpf: "
                                                                       f"{MOUNTS}"}
    assert text(rows["bpftrace"][1]) == "not found"
    assert [t["empty"] for t in s["tables"][1:4]] == ["Not listed: bpftool did not answer."] * 3
    assert not any(argv[:3] == ["bpftool", "-j", w] for _, argv in fake.commands for w in ("prog", "map", "link"))
    # bpftool there, sudo asking a password for every command: the listing is asked all the same, and refused in
    # sudo's words; the first refusal for its rights stops the rest
    q, qfake, _ = linux(password=True)
    t = q.status()
    assert t["present"] is True and t["summary"].endswith(", bpftool refused as root, the watch cannot run")
    assert [x["empty"] for x in t["tables"][1:4]] == [f"Not listed: {ROOT_REFUSED}."] * 3
    assert [argv for root, argv in qfake.commands if argv[:2] == ["bpftool", "-j"] and argv[2] != "version"] == [
        ["bpftool", "-j", "prog", "show"]]


def test_root_is_read_from_each_command_the_plugin_runs_not_from_sudo_true_alone(linux):
    """A least-privilege sudoers rule (NOPASSWD for bpftool and bpftrace alone, the README's own advice): `sudo -n true`
    asks for a password, yet the listing, the changes bpftool makes and the watch run; a dump (sh) and an unload (rm),
    which the rule does not name, are refused in sudo's words."""
    p, fake, _ = linux(password=True, nopasswd=("bpftool", "bpftrace"))
    s = plain(p.status())
    assert s["root"] == "sudo -n true asks for a password"
    assert s["summary"] == ("Linux 6.8.0-45-generic: bpftool 7.4.0, bpftrace, kernel BTF, sudo -n true asks for a "
                            "password")
    programs, maps, links = s["tables"][1:4]
    assert (len(programs["rows"]), len(maps["rows"]), len(links["rows"])) == (2, 1, 1)  # listed as root, by its rule
    assert s["watch"].startswith("bpftrace, through sudo -n — sudo -n bpftrace -V answered (bpftrace v0.20.2)")
    root = by_first(s["tables"][0])["Root"][1]
    assert "the listings and the watch say what each was given" in root["sub"] and "refused" not in root["sub"]
    assert here_of(p.compare())[("Privileges", "List and read")] == {
        "text": "listed as root: 2 programs, 1 map, 1 link", "sub": "read from bpftool -j prog show, map show, link "
                                                                    "show, as root"}
    page = plain(p.functions())
    assert disabled(page) == {}
    assert "bpftool runs as root here through sudo -n (it listed so)" in offered(page)[
        "Load and attach a pre-built program"]["sub"]
    p.load_program("/home/you/drop.o", accept_load=True)  # what the rule gives runs: bpftool's changes
    p.detach_program(7)
    assert [argv[:3] for _, argv in fake.changes] == [["bpftool", "prog", "load"], ["bpftool", "link", "detach"]]
    assert all(root for root, _ in fake.changes)
    with pytest.raises(CommandError, match=r"^sh needs root on this machine"):  # a dump runs sh as root
        p.dump(3)
    with pytest.raises(CommandError, match=r"^rm needs root on this machine"):  # an unload rm
        p.unload_program("/sys/fs/bpf/liminal_drop")
    assert len(fake.changes) == 2


def test_the_watch_is_said_to_run_only_where_its_own_command_answers(linux):
    """The library's BpftraceWatch runs `sudo -n bpftrace`, the platform root or not: readiness is what that command
    answers (sudo -n bpftrace -V), never root alone or bpftrace on the platform's user's path."""
    p, fake, _ = linux(root=True, sudo=False)  # the platform root, on a Linux with no sudo
    s = plain(p.status())
    assert s["root"] == "the platform is root"
    assert by_first(s["tables"][0])["Root"][2] == "this process's user id (os.geteuid)"  # nothing was run for it
    assert s["watch"] == (f"cannot run here — sudo -n bpftrace -V: {NO_SUDO}: the watch runs bpftrace through sudo, so "
                          "it needs sudo here, the platform root or not")
    assert [argv for root, argv in fake.commands if root] == [["bpftrace", "-V"]]  # through sudo: the watch's alone
    here = here_of(p.compare())
    assert here[("Privileges", "Load and attach")]["sub"] == ("read from /proc/sys/kernel/unprivileged_bpf_disabled; "
                                                              "this process's user id (os.geteuid)")
    assert not any("sudo -n true" in c["sub"] for c in here.values())  # never run here: never cited
    assert text(here[("Basic functions", WATCH_ITEM)]).startswith("the watch service: cannot run here")
    # bpftrace on the platform's user's path alone (~/.local/bin): sudo's own path finds none
    q, _, _ = linux(user_only=("bpftrace",))
    t = plain(q.status())
    assert t["bpftrace"] == "bpftrace v0.20.2" and t["summary"].endswith(", the watch cannot run")
    assert t["watch"] == ("cannot run here — sudo -n bpftrace -V: sudo: bpftrace: command not found: the watch runs "
                          "bpftrace through sudo, whose path must hold it (the distribution's bpftrace package)")
    assert text(offered(q.functions())[WATCH_ITEM]) == "the watch service: cannot run here"


def test_a_kernel_lacking_a_function_the_watch_scripts_probe_is_said(linux, monkeypatch):
    """bpftrace refuses a kprobe on a function the kernel does not have, and the library joins every kind's script in
    one program: a watch with that kind ends at its start. The functions are read from the library's scripts and
    looked for in /proc/kallsyms, as the platform's user."""
    assert "udp_sendmsg" in plugin.script_kprobes().get("net", ())  # read from the library's net script itself
    monkeypatch.setattr(plugin, "script_kprobes", lambda: {"net": ("udp_sendmsg", "udp_v6_sendmsg")})  # before 1.60.0
    p, fake, _ = linux()  # this kernel names the IPv6 one udpv6_sendmsg, as every kernel read here does
    s = plain(p.status())
    assert s["watch"].endswith("; a watch with net ends at its start here: the library's net script probes "
                               "udp_v6_sendmsg, which this kernel does not have (/proc/kallsyms)")
    assert p.api_facts()[KERNEL_CARD]["The watch's kprobes"] == "net: udp_v6_sendmsg missing"
    [(root, looked)] = [(r, a) for r, a in fake.commands if a[:2] == ["sh", "-c"] and "/proc/kallsyms" in a[2]]
    assert not root and looked[2] == ("test -r /proc/kallsyms || exit 3; grep -w -F -e udp_sendmsg -e udp_v6_sendmsg "
                                      "/proc/kallsyms; exit 0")
    q, _, _ = linux(symbols=(*SYMBOLS, "udp_v6_sendmsg"))  # a kernel with it: nothing said
    assert "ends at its start" not in q.status()["watch"]
    assert q.api_facts()[KERNEL_CARD]["The watch's kprobes"] == "all there"
    r, _, _ = linux(kallsyms=False)  # not read: nothing said either way
    assert "ends at its start" not in r.status()["watch"] and "The watch's kprobes" not in r.api_facts()[KERNEL_CARD]
    t, tfake, _ = linux(password=True)  # where the watch cannot run at all, its functions are not looked for
    t.status()
    assert not any(argv[:2] == ["sh", "-c"] for _, argv in tfake.commands)


def test_inside_wsl_main_ends_with_an_under_wsl_table(linux, monkeypatch):
    """The user, 2026-11-15: "wsl and firewall linux should always work under linux, if wsl prevents or misses some
    capability this should reflect in the plugin". This PC's Ubuntu: Microsoft's kernel, no bpftool or bpftrace, the
    BPF filesystem not mounted though systemd runs, sudo asking for a password."""
    releases = []
    wsl(monkeypatch)
    monkeypatch.setattr(machines_linux, "wsl", lambda release=None, env=None: releases.append(release) or "Ubuntu",
                        raising=False)
    p, _, _ = linux(release=WSL2, bpftool=False, bpftrace=False, mounts="", password=True)
    s = plain(p.status())
    assert s["valid"] is True and s["wsl"] == "WSL 2: Ubuntu" and releases == [WSL2]  # the release the runtime read
    assert s["summary"].startswith(f"Linux {WSL2} (WSL 2: Ubuntu): no bpftool, no bpftrace")
    under = s["tables"][-1]
    assert under["title"] == "Under WSL" and [r[0] for r in under["rows"]] == [
        "This Linux", "What is seen", "Network", "bpftool", "bpftrace", "The BPF filesystem", "Root", "Lifetime"]
    rows = {r[0]: r for r in under["rows"]}
    assert rows["This Linux"][1] == {"text": "WSL 2: Ubuntu", "sub": "systemd runs"}  # and whether systemd runs
    assert f"its kernel ({WSL2}) is Microsoft's" in rows["This Linux"][2]
    assert "pid is the kernel's" in rows["What is seen"][2]
    assert "a watch's spec pid is matched against the kernel's" in rows["What is seen"][2]  # not the one ps shows
    assert "Windows' own traffic is not seen here" in rows["Network"][2]
    assert rows["bpftool"][1] == "did not answer" and "linux-tools-common" in rows["bpftool"][2]
    assert rows["bpftrace"][1:] == ["not found", "the watch runs it through sudo -n: the distribution's bpftrace "
                                                 "package (sudo apt install bpftrace)"]
    assert rows["The BPF filesystem"][1] == "not mounted, though systemd runs here"
    assert rows["Root"][1] == "sudo -n true asks for a password"
    assert "Microsoft's" in by_first(s["tables"][0])["bpftool"][1]["sub"]  # not "the distribution's bpftool package"
    assert p.compare()["note"].startswith("This machine: WSL 2: Ubuntu; its column is marked.")
    # systemd not running is said too
    monkeypatch.setattr(machines_linux, "systemd_runs", lambda: False, raising=False)
    q, _, _ = linux(release=WSL2)
    assert table(q.status(), "Under WSL")["rows"][0][1] == {"text": "WSL 2: Ubuntu", "sub": "systemd does not run"}
    # WSL 1: no kernel, no eBPF
    monkeypatch.setattr(machines_linux, "wsl_generation", lambda release=None: 1, raising=False)
    r, _, _ = linux(release="4.4.0-19041-Microsoft", bpftool=False, bpftrace=False)
    under = r.status()["tables"][-1]
    assert [r[:2] for r in under["rows"]] == [["This Linux", {"text": "WSL 1: Ubuntu", "sub": "systemd does not run"}],
                                              ["WSL 2", "not this distribution"]]
    assert 'wsl --set-version "Ubuntu" 2' in under["rows"][1][2]


def test_under_wsl_names_only_what_was_read(linux, monkeypatch):
    """WSL's own name in a wsl.exe command, never /etc/os-release's; a kernel called Microsoft's only where its
    release names Microsoft."""
    wsl(monkeypatch, name="WSL", generation=1, systemd=None)  # under a unit or plain sudo WSL's variables are unset
    monkeypatch.setattr(plugin, "os_release", lambda: "Ubuntu 20.04.6 LTS")
    p, _, _ = linux(release="4.4.0-19041-Microsoft")
    rows = {r[0]: r for r in table(p.status(), "Under WSL")["rows"]}
    assert rows["This Linux"][1] == {"text": "WSL 1: Ubuntu 20.04.6 LTS", "sub": "whether systemd runs was not read"}
    assert 'wsl --set-version "<its name>" 2' in rows["WSL 2"][2] and "LTS 2" not in rows["WSL 2"][2]
    # WSL 2 on a kernel of the user's own (.wslconfig's kernel=): its release names neither Microsoft nor WSL 2
    wsl(monkeypatch, name="Ubuntu", generation=0)
    q, _, _ = linux(release="6.12.1", bpftool=False)
    s = plain(q.status())
    rows = {r[0]: r for r in table(s, "Under WSL")["rows"]}
    assert "its kernel (6.12.1) is not Microsoft's build" in rows["This Linux"][2]
    assert rows["bpftool"][2].startswith("under WSL this kernel (6.12.1) is not Ubuntu's: on Ubuntu the bpftool")
    assert "is Microsoft's" not in json.dumps(s)


def test_the_bpftool_advice_for_ubuntu_is_given_on_ubuntu_alone(linux, monkeypatch):
    """Ubuntu's bpftool command is linux-tools-common's wrapper, with no build for a WSL kernel; a Fedora or Gentoo
    distribution's bpftool package is a plain binary, which runs on Microsoft's kernel."""
    wsl(monkeypatch, name="Liminal-Fedora", ids=("fedora",))
    p, _, _ = linux(release=WSL2, bpftool=False, bpftrace=False)
    s = plain(p.status())
    package = "it is not installed here: the distribution's bpftool package"
    assert by_first(s["tables"][0])["bpftool"][1]["sub"] == package
    assert {r[0]: r for r in table(s, "Under WSL")["rows"]}["bpftool"][2] == package
    assert "linux-tools-common" not in json.dumps(s) and "apt install" not in json.dumps(s)
    wsl(monkeypatch, name="Mint", ids=("linuxmint", "ubuntu", "debian"))  # like Ubuntu (ID_LIKE): Ubuntu's story
    q, _, _ = linux(release=WSL2, bpftool=False)
    assert "linux-tools-common" in by_first(q.status()["tables"][0])["bpftool"][1]["sub"]
    # what /etc/os-release says this Linux is and is like, as the real reader gives it
    monkeypatch.setattr(plugin.py_platform, "freedesktop_os_release",
                        lambda: {"ID": "linuxmint", "ID_LIKE": "ubuntu debian", "PRETTY_NAME": "Linux Mint 22"})
    assert REAL_OS_IDS() == ("linuxmint", "ubuntu", "debian")

    def unreadable():
        raise OSError("no os-release")
    monkeypatch.setattr(plugin.py_platform, "freedesktop_os_release", unreadable)
    assert REAL_OS_IDS() == ()


def test_wsl_1_says_it_has_no_ebpf_on_every_page(linux, monkeypatch):
    """WSL 1 has no Linux kernel: whatever its tools answer (a bpftool built from source, bpftrace from the
    distribution, sudo without a password), no runtime is there, nothing that needs root is asked, and every function
    says so."""
    wsl(monkeypatch, generation=1, systemd=False)
    p, fake, _ = linux(release="4.4.0-19041-Microsoft")
    s = plain(p.status())
    assert s["valid"] is True and s["present"] is False and p.present() is True
    assert s["runtime"] == "none: WSL 1 has no Linux kernel, so no eBPF"
    assert s["summary"] == "Linux 4.4.0-19041-Microsoft (WSL 1: Ubuntu): WSL 1 has no Linux kernel, so no eBPF"
    assert s["watch"] == "cannot run here — WSL 1 has no Linux kernel, so no eBPF" and s["root"] == "not asked"
    assert not any(root for root, _ in fake.commands)  # nothing asked of sudo: nothing could run
    assert [t["empty"] for t in s["tables"][1:4]] == ["Not listed: WSL 1 has no Linux kernel, so no eBPF."] * 3
    rows = by_first(s["tables"][0])
    assert all(rows[k][1]["sub"].startswith("WSL 1 has no Linux kernel") for k in (
        "bpftool", "Unprivileged BPF", "JIT", "Kernel BTF", "BPF filesystem", "bpftrace", "Root", "The watch"))
    assert "the distribution's" not in json.dumps(s["tables"][0])  # no install advice that cannot help here
    page = plain(p.compare())
    assert page["note"].startswith("This machine: WSL 1: Ubuntu, which has no Linux kernel, so no eBPF; neither column "
                                   "is this machine's.")
    assert not any("(this machine)" in c["title"] for t in page["tables"] for c in t["columns"])
    assert set(here_of(page)) == {("Install and status", "Current version"), ("Basic functions", WATCH_ITEM)}
    fns = plain(p.functions())
    assert not any("(this machine)" in c["title"] for c in fns["tables"][0]["columns"])
    assert set(disabled(fns)) == {"show", "dump", "load", "attach", "detach", "unload"}
    assert all(why.startswith("WSL 1 has no Linux kernel, so no eBPF") for why in disabled(fns).values())
    assert text(offered(fns)["Load and attach a pre-built program"]) == "not here"
    for call in (lambda: p.show_program(12), lambda: p.dump(3), lambda: p.load_program("/x.o", accept_load=True),
                 lambda: p.attach_program("xdp", "eth0", None, 31, accept_attach=True), lambda: p.detach_program(7),
                 lambda: p.unload_program("/sys/fs/bpf/liminal_x")):
        with pytest.raises(ValueError, match=r"^WSL 1 has no Linux kernel, so no eBPF: nothing is shown"):
            call()
    assert fake.changes == []  # an unload's rm -f would have answered as if a pin were removed


def test_wsl_names_its_distribution_from_os_release_when_wsl_gives_none(linux, monkeypatch):
    """Under a systemd unit WSL's variables are not set, and the library says "WSL": /etc/os-release names it."""
    monkeypatch.setattr(machines_linux, "wsl", lambda *a, **k: "WSL", raising=False)
    monkeypatch.setattr(machines_linux, "wsl_generation", lambda *a, **k: 2, raising=False)
    monkeypatch.setattr(machines_linux, "systemd_runs", lambda: True, raising=False)
    monkeypatch.setattr(plugin, "os_release", lambda: "Ubuntu 24.04.5 LTS")
    p, _, _ = linux(release=WSL2)
    assert p.status()["wsl"] == "WSL 2: Ubuntu 24.04.5 LTS"


def test_a_library_without_the_wsl_helpers_draws_no_under_wsl_table(linux, monkeypatch):
    """liminal-libs before 1.57.0 has no machines.linux.wsl: the helpers are reached through getattr, and the page has
    no Under WSL table (never the library's wsl_table, whose rows are the firewalls')."""
    monkeypatch.delattr(machines_linux, "wsl", raising=False)
    p, _, _ = linux(release=WSL2)
    s = p.status()
    assert s["valid"] and "wsl" not in s and [t["title"] for t in s["tables"]] == [
        "This kernel's eBPF", "Programs", "Maps", "Links"]


def test_off_linux_the_linux_runtime_runs_nothing_and_the_plugin_stays_valid(linux):
    """macOS: the Linux runtime is not for it (machines.linux.why_not_native), nothing is run, and the comparison
    serves all the same; neither column is this machine's, and every function says why it is not here."""
    p, fake, _ = linux(where="darwin")
    why = "The eBPF runtime is for the Linux the platform runs on, and this one runs macOS"
    s = plain(p.status())
    assert s["valid"] is True and s["present"] is False and s["summary"].startswith(f"not for this machine: {why}")
    assert s["summary"].endswith("; the comparison serves all the same") and s["tables"] == []
    page = plain(p.compare())
    assert page["note"].startswith("This machine: macOS, neither Linux nor Windows; neither column is this machine's.")
    assert page["note"].endswith(f"Nothing of this machine is read: t{why[1:]}.")
    assert len(page["tables"]) == 12
    assert all([c["title"] for c in t["columns"]] == ["What", "Linux", "Windows"] for t in page["tables"])
    fns = plain(p.functions())
    assert [c["title"] for c in fns["tables"][0]["columns"]] == ["Function", "Linux", "Windows", "Here"]
    assert "on this machine (macOS, neither Linux nor Windows)" in fns["note"]
    assert set(disabled(fns)) == {"show", "dump", "load", "attach", "detach", "unload"}
    assert all(note.startswith(why) for note in disabled(fns).values())
    here = offered(fns)
    assert here["List programs, maps and links"] == {"text": "not here", "sub": why}  # Main has no tables to point at
    assert text(here["Load and attach a pre-built program"]) == "not here" and text(here[WATCH_ITEM]) == "not here"
    assert fake.commands == []


def test_in_wsl_where_the_library_refuses_its_kernel_the_machine_is_still_linux(clock):
    """A library before 1.57.0, inside WSL: its runtime refuses a WSL kernel (applies False), yet the machine is Linux.
    The page says so, quotes the runtime's words for why nothing is read, and offers no function."""
    words = "The eBPF runtime is for a Linux machine of its own, and this one is a WSL distribution"

    class Refusing:
        system = "linux"

        def status(self):
            return {"present": False, "system": "linux", "applies": False, "version": "", "why": words,
                    "summary": "not for this machine"}
    p = EbpfPlugin(Refusing(), lambda kinds, spec: None, clock=clock, system="linux", where="linux")
    page = plain(p.compare())
    assert page["note"].startswith("This machine: Linux; its column is marked.")
    assert page["note"].endswith(f"Nothing of this machine is read: t{words[1:]}.")
    assert page["tables"][0]["columns"][1]["title"] == "Linux (this machine)"
    fns = plain(p.functions())
    assert set(disabled(fns)) == {"show", "dump", "load", "attach", "detach", "unload"}
    assert all(note.startswith(words) for note in disabled(fns).values())
    assert offered(fns)["List programs, maps and links"] == {"text": "not here", "sub": words}
    settled()


def test_the_status_is_read_on_a_thread_kept_and_read_again_when_old(linux, clock):
    p, fake, _ = linux()
    assert p.present() is True and fake.commands == []  # it asks nothing, the tray asking it every minute
    p.attach(App())  # a served platform's attach: the read starts on its thread, and is not waited for
    settled()
    assert fake.asked("uname -r") == 1
    for ask in (p.status, p.compare, p.functions, p.present, p.api_facts):
        ask()
    assert fake.asked("uname -r") == 1  # kept: the platform asks the status every 30 s
    clock.t += plugin.READ_S + 1
    old = p.status()  # the old read at once, the new one on a thread
    assert old["valid"] and fake.asked("uname -r") in (1, 2)
    settled()
    assert fake.asked("uname -r") == 2
    said = plain(p.refresh())  # Read again: at once
    assert said["ok"] is True and said["said"].startswith("read again in 0.0 s: Linux 6.8.0-45-generic")
    assert fake.asked("uname -r") == 3


def test_a_one_shot_commands_attach_reads_nothing(linux):
    """A one-shot platform command attaches every plugin with once=True, and such a plugin starts no background work
    of its own (the platform's rule): its status reads for itself when it is asked."""
    p, fake, _ = linux()
    p.attach(App("platform", once=True))
    settled()
    assert fake.commands == []  # no read, no sudo -n asked
    assert p.status()["present"] is True  # asked, it reads, waiting for it
    p.detach()
    q, qfake, _ = linux()
    q.attach(App())  # a served platform's attach reads at once, on its thread
    settled()
    assert qfake.asked("uname -r") == 1


def test_present_agrees_with_valid_wherever_the_plugin_serves(linux, windows):
    """The platform's tray asks present(), its list the status' `valid`: both say the plugin serves, everywhere,
    while the status' own `present` says whether this machine's eBPF runtime is there."""
    for p in (windows()[0], linux(bpftool=False)[0], linux(where="darwin")[0]):
        s = plain(p.status())
        assert s["valid"] is True and s["present"] is False  # the runtime is not there: a fact on its page
        assert p.present() is True  # the plugin is: its icon stays in the tray while the list says it is active


def test_while_the_first_read_runs_the_status_is_valid_and_says_so(linux, monkeypatch):
    release = threading.Event()
    p, fake, _ = linux()
    slow = p._runtime.status

    def waiting():
        assert release.wait(5)
        return slow()
    monkeypatch.setattr(p._runtime, "status", waiting)
    monkeypatch.setattr(plugin, "FIRST_WAIT_S", 0.05)
    s = plain(p.status())
    assert s == {"valid": True, "summary": "reading this machine's eBPF runtime…", "tables": [],
                 "forms": plugin.forms(), "actions": [plugin._read_again()]}
    release.set()
    settled()
    assert p.status()["present"] is True


def test_a_read_that_fails_is_said_and_the_plugin_stays_valid(clock):
    class Broken:
        system = "linux"

        def status(self):
            raise RuntimeError("the runtime is gone")
    p = EbpfPlugin(Broken(), lambda kinds, spec: None, clock=clock)
    s = plain(p.status())
    assert s["valid"] is True and s["problem"] == "the runtime could not be read: RuntimeError: the runtime is gone"
    assert p.refresh() == {"said": "the runtime could not be read: RuntimeError: the runtime is gone", "ok": False}
    assert p.api_facts()["bpftool"]["Last read failed"] == "RuntimeError: the runtime is gone"
    page = p.compare()
    assert all(len(t["columns"]) == 3 for t in page["tables"])
    assert page["note"].endswith("This machine's status could not be read (RuntimeError: the runtime is gone): a Here "
                                 "column comes once a read succeeds.")
    fns = p.functions()
    assert offered(fns)["List programs, maps and links"] == {
        "text": "not here", "sub": "this machine's status could not be read: RuntimeError: the runtime is gone"}


# -- Main, on Windows --------------------------------------------------------------------------------------------

def test_on_windows_this_pcs_status_is_valid_and_says_why_nothing_can_load(windows):
    p, fake, _ = windows()
    s = plain(p.status())
    assert s["valid"] is True and s["present"] is False and "problem" not in s
    assert s["summary"] == ("eBPF for Windows is not installed, and it could not load here: Secure Boot is on; the "
                            "watch uses Npcap and ETW")
    assert (s["runtime"], s["secureBoot"], s["memoryIntegrity"], s["testSigning"], s["administrator"], s["watch"]) == (
        "eBPF for Windows: not installed", "on", "on", "off", "no", "Npcap and ETW, not eBPF")
    assert s["canItLoad"] == ("no: the test-signed runtime cannot load here — Secure Boot is on, and Windows loads a "
                              "test-signed driver only in test-signing mode, which needs Secure Boot off")
    runtime, load, watching, programs, maps, links = s["tables"]
    rows = by_first(runtime)
    assert rows["Installed"][1:] == ["no", "Get-Service eBPFCore, NetEbpfExt, eBPFSvc"]
    assert rows["eBPFCore"][1] == {"text": "absent", "sub": "the core (a kernel driver)"}
    assert rows["Version"][1] == "–"
    assert rows["Linux here"][1:] == ["WSL's, not this platform's", plugin.WSL_NOTE]
    rows = by_first(load)
    assert rows["Secure Boot"][1:] == ["on", r"the registry (SecureBoot\State UEFISecureBootEnabled); the firmware's "
                                             "own answer needs an administrator"]
    assert rows["Memory integrity"][1:] == [
        {"text": "on", "sub": "so the JIT cannot run, and only signed native drivers load"},
        "Win32_DeviceGuard (SecurityServicesRunning), read without an administrator"]
    # read without an administrator from this boot's start options (liminal-libs 1.60.0), so said as read
    assert rows["Test signing"][1:] == ["off", r"the registry (SystemStartOptions: this boot's start options)"]
    assert text(rows["Can it load"][1]) == "no: the test-signed runtime cannot load here"
    assert load["note"].startswith("Every eBPF for Windows build is test-signed pre-release")
    rows = by_first(watching)
    assert text(rows["Npcap"][1]) == "installed" and rows["ETW"][1]["sub"].startswith("in Performance Log Users")
    # a capture or an ETW session lost after it opened ends the watch, said (liminal-libs 1.60.0's Windows watch)
    assert rows["The watch"][1]["sub"].endswith(plugin.LOST_SAID)
    assert "ends the watch" in plugin.LOST_SAID and "not said" not in plugin.LOST_SAID
    assert [t["empty"] for t in (programs, maps, links)] == ["None: eBPF for Windows is not installed."] * 3
    assert fake.ran("netsh ebpf") == 0  # nothing to list: nothing is installed
    assert fake.ran("Get-Service -Name $n") == 1 and fake.ran("Confirm-SecureBootUEFI") == 1


def test_on_windows_as_an_administrator_test_signing_is_said_as_read(windows):
    p, _, _ = windows(elevated=True)
    s = p.status()
    assert s["testSigning"] == "off" and s["administrator"] == "yes"
    rows = by_first(table(s, "Can a test-signed driver load here"))
    assert rows["Secure Boot"][2] == r"the registry (SecureBoot\State UEFISecureBootEnabled)"
    assert rows["Memory integrity"][2].endswith("read as an administrator")


def test_on_windows_what_could_not_be_read_is_said(windows):
    p, _, _ = windows(fail_services="Get-Service failed", fail_facts="Access is denied.")
    s = plain(p.status())
    assert s["valid"] is True and s["summary"] == "eBPF for Windows could not be read"
    assert s["runtime"] == "not read: the eBPF services could not be read: Get-Service failed"
    assert (s["secureBoot"], s["memoryIntegrity"], s["testSigning"]) == (
        "not read", "not read", "not read: neither this boot's start options nor bcdedit answered")
    assert by_first(table(s, "Can a test-signed driver load here"))["Test signing"][2] == plugin.SIGNING_UNREAD
    assert s["canItLoad"] == "not known — Secure Boot could not be read"
    load = table(s, "Can a test-signed driver load here")
    assert load["note"].startswith("this machine's Secure Boot and memory-integrity state could not be read (Access is "
                                   "denied.)")
    # what was not read is not said: neither that eBPF for Windows is not installed, nor a fact of this PC's
    assert [t["empty"] for t in s["tables"][3:]] == ["Not listed: eBPF for Windows' services could not be read."] * 3
    page = p.functions()
    here = offered(page)
    assert here["Show a program's info"]["form"] == "show"
    assert here["List programs, maps and links"] == {"text": "on Main", "sub": "not listed now: eBPF for Windows' "
                                                                               "services could not be read"}
    assert not any(a.get("disabled") for a in page["actions"] if a["form"] == "show")
    with pytest.raises(ValueError) as refused:
        p.unload_program("/sys/fs/bpf/liminal_x")
    assert "not installed" not in str(refused.value) and "on this PC" not in str(refused.value)


def test_on_windows_with_ebpf_for_windows_installed_its_listing_is_read(windows):
    p, fake, _ = windows(installed=True)
    s = plain(p.status())
    assert s["present"] is True and s["runtime"] == "eBPF for Windows v1.7.0, installed"
    # its core running: it loaded, whatever Secure Boot says of a test-signed driver
    assert s["summary"] == "eBPF for Windows v1.7.0 installed, its core running; the watch uses Npcap and ETW"
    assert text(by_first(s["tables"][0])["eBPFCore"][1]) == "Running, Automatic"
    programs = table(s, "Programs")
    assert [c["title"] for c in programs["columns"]] == ["Id", "Pins", "Links", "Mode", "Type", "Name", ""]
    assert programs["rows"][0][:6] == ["65537", "1", "1", "NATIVE", "xdp", "dropper"]
    assert programs["rows"][0][6]["values"] == {"prog_id": 65537} and table(s, "Maps")["empty"] == "No map."
    assert plain(p.show_program(65537))["said"] == "program 65537: dropper, xdp"
    # netsh needs an administrator: said once for all three, the maps and links not asked
    q, qfake, _ = windows(installed=True, netsh_denied=True)
    t = q.status()
    listing = "the program listing needs an administrator: Access is denied."
    assert [x["empty"] for x in t["tables"][3:]] == [f"Not listed: {listing}"] * 3
    assert qfake.ran("netsh ebpf show maps") == 0 and qfake.ran("netsh ebpf show links") == 0
    # a program netsh would not show without an administrator is not said to be missing
    with pytest.raises(LookupError) as unread:
        q.show_program(65537)
    assert str(unread.value) == ("program 65537 could not be read: netsh ebpf show programs needs an administrator, "
                                 "and the platform runs without one")
    fns = q.functions()
    assert disabled(fns)["show"] == listing and offered(fns)["Show a program's info"] == {"text": "not here",
                                                                                          "sub": listing}
    e, _, _ = windows(installed=True, netsh_denied=True, elevated=True)  # an administrator's netsh that failed
    e.status()
    with pytest.raises(LookupError, match=r"^program 65537 could not be read: netsh ebpf show programs id=65537 "
                                          r"answered nothing it could read"):
        e.show_program(65537)
    r, _, _ = windows(installed=True, running=False)  # installed, its core stopped: Secure Boot keeps it from loading
    assert r.status()["summary"] == ("eBPF for Windows v1.7.0 installed, its core not running, and it could not load "
                                     "here: Secure Boot is on; the watch uses Npcap and ETW")


def test_a_liminal_libs_older_than_the_floor_is_said_and_the_plugin_is_not_valid(linux, windows, monkeypatch):
    # the platform loads a plugin from its folder whatever its floor says: on an older library the plugin would word
    # that library's facts as 1.60.0's, so it says which library it needs and serves nothing
    import pathlib

    import liminal_libs
    pyproject = (pathlib.Path(plugin.__file__).resolve().parents[2] / "pyproject.toml").read_text(encoding="utf-8")
    assert f'dependencies = ["liminal-libs>={plugin.LIBS_FLOOR}"]' in pyproject
    for make in (linux, windows):
        p = make()[0]
        monkeypatch.setattr(liminal_libs, "__version__", "1.59.0")
        s = plain(p.status())
        assert (s["valid"], s["present"]) == (False, False)
        assert s["why"] == s["summary"] == "this plugin needs liminal-libs 1.60.0 or newer, and this is 1.59.0"
        assert (s["tables"], s["forms"], s["actions"]) == ([], [], [])
        monkeypatch.setattr(liminal_libs, "__version__", plugin.LIBS_FLOOR)
        assert p.status()["valid"] is True
    # nothing else reads or runs on it either: the tray, the attach, the API facts, every hook, the command line
    for make, card in ((linux, "bpftool"), (windows, "eBPF for Windows")):
        p, fake, _ = make()
        monkeypatch.setattr(liminal_libs, "__version__", "1.59.0")
        said = "this plugin needs liminal-libs 1.60.0 or newer, and this is 1.59.0"
        assert p.present() is False
        p.attach(App())  # a served platform's attach: on an older library nothing read, nothing reclaimed
        assert p.snapshot() is None
        assert p.api_facts() == {card: {"Not read": said}}
        for hook, args in (("refresh", ()), ("compare", ()), ("functions", ()), ("show_program", (1,)), ("dump", (1,)),
                           ("load_program", ("/tmp/x.o",)), ("attach_program", ("xdp",)), ("detach_program", (1,)),
                           ("unload_program", ("/sys/fs/bpf/liminal_x",)), ("watch_start", (["process"],))):
            with pytest.raises(ValueError, match=f"^{re.escape(said)}$"):
                getattr(p, hook)(*args)
        p.detach()
        monkeypatch.setattr(liminal_libs, "__version__", plugin.LIBS_FLOOR)
    monkeypatch.setattr(liminal_libs, "__version__", "1.59.0")
    assert cli.main(["status"]) == 1 and cli.main(["watch", "net"]) == 1
    words = plugin.libs_too_old
    assert words("1.60.0") == words("1.60.1") == words("1.61.0") == words("2.0.0") == words("1.60.0rc1") == ""
    assert words("1.6.0").endswith("and this is 1.6.0") and words("1.59.9").endswith("and this is 1.59.9")
    assert words("") == ("this plugin needs liminal-libs 1.60.0 or newer, and this is a liminal-libs that does not "
                         "say its version")
    assert plugin.release_of("1.60.0rc1") == (1, 60, 0) and plugin.release_of("1.59") == (1, 59)


def test_the_windows_verdict_from_what_was_read():
    words = plugin.verdict_words
    read = {"test_signing_readable": True, "test_signing_source": "boot options"}  # liminal-libs 1.60.0's read
    assert words({"secure_boot": True, "hvci": True, "test_signing": False, **read})[0] == (
        "no: the test-signed runtime cannot load here")
    assert words({"secure_boot": True, "hvci": True})[0] == "no: the test-signed runtime cannot load here"
    assert words({"secure_boot": False, "hvci": False, "test_signing": True, **read}) == (
        "yes", "test signing is on, so a test-signed driver can load")
    by_bcdedit = {**read, "test_signing_source": "bcdedit"}
    assert words({"secure_boot": False, "hvci": True, "test_signing": True, **by_bcdedit})[0] == (
        "yes, as native .sys programs only")
    assert words({"secure_boot": False, "test_signing": False, **read})[0] == "not as it is: test signing is off"
    # a read that names no source, or not one the library reads, is no read: nothing is said of test signing from it
    for unread in ({"test_signing_readable": True}, {"test_signing_readable": True, "test_signing_source": "unknown"},
                   {"test_signing_readable": False, "test_signing_source": "boot options"}):
        assert words({"secure_boot": False, "test_signing": True, **unread}) == (
            "not known", "Secure Boot is off; test signing could not be read")
        assert plugin.signing_words({"test_signing": True, **unread}) == (
            "not read: neither this boot's start options nor bcdedit answered")
    assert words({}) == ("not known", "Secure Boot could not be read")


# -- Compare -------------------------------------------------------------------------------------------------------

def test_compare_has_every_point_by_area_each_with_its_source(linux):
    p, _, _ = linux()
    page = plain(p.compare())
    assert page["title"] == "eBPF on Linux and on Windows"
    assert page["note"].startswith("This machine: Linux; its column is marked. 65 points in 12 areas, read on "
                                   "2026-11-14 from the maintainers' own documentation")
    assert [t["title"] for t in page["tables"]] == list(capabilities.AREAS)
    assert sum(len(t["rows"]) for t in page["tables"]) == len(capabilities.CAPABILITIES) == len(SOURCES) == 65
    for t in page["tables"]:
        assert [c["title"] for c in t["columns"]][:3] == ["What", "Linux (this machine)", "Windows"]
        for r in t["rows"]:
            assert r[0]["sub"] == SOURCES[(t["title"], r[0]["text"])]  # each point's source under its name
    assert "\\n" not in json.dumps(page)  # the page's cells draw no line breaks: a point's lines go under its first
    production = by_first(table(page, "Install and status"))["Production or preview"]
    assert production[2]["text"] == "Preview in practice:"
    assert production[2]["sub"].startswith("Every public release, including v1.7.0, is flagged Pre-release. · ")
    assert plugin.point("one\n- two\n- three") == {"text": "one", "sub": "two · three"}
    assert plugin.point("one") == "one"


def test_compares_here_column_holds_only_what_was_read_each_saying_where(linux, windows):
    p, _, _ = linux(mounts="")
    here = here_of(plain(p.compare()))
    assert set(here) == LINUX_HERE  # the eight points this machine's status read, and no other
    assert all(isinstance(c, dict) and c["sub"].startswith("read from ") for c in here.values())
    assert here[("Loading", "Pinning")] == {"text": "BPF filesystem not mounted", "sub": "read from /proc/mounts"}
    assert here[("Execution", "Interpreter / JIT / native")] == {"text": "JIT 1: on", "sub": "read from "
                                                                 "/proc/sys/net/core/bpf_jit_enable"}
    assert here[("Privileges", "List and read")]["text"] == "listed as root: 2 programs, 1 map, 1 link"
    assert here[("Privileges", "Load and attach")] == {
        "text": "unprivileged_bpf_disabled 2: off; sudo -n true runs without a password",
        "sub": "read from /proc/sys/kernel/unprivileged_bpf_disabled; sudo -n true"}
    assert here[("Basic functions", WATCH_ITEM)]["sub"] == "read from sudo -n bpftrace -V; /proc/kallsyms"
    page = p.compare()
    assert all(len(t["columns"]) == 3 for t in page["tables"]  # nothing read of these areas: no Here column
               if t["title"] in ("Program types", "Attach types", "Map types", "Helpers", "Verifier",
                                 "Events to user space", "Process attribution"))
    # what could not be read is not said
    q, _, _ = linux(fail={"cat /proc/sys/net/core/bpf_jit_enable": (1, "", "denied\n"),
                          "uname -r": (1, "", "uname failed\n"),
                          "cat /proc/sys/kernel/unprivileged_bpf_disabled": (1, "", "denied\n")})
    here = here_of(q.compare())
    assert ("Execution", "Interpreter / JIT / native") not in here
    assert ("Install and status", "Current version") not in here
    assert here[("Privileges", "Load and attach")] == {"text": "sudo -n true runs without a password",
                                                       "sub": "read from sudo -n true"}  # the file not cited
    # a listing never asked is never cited: bpftool did not answer its version, so that is the read named
    r, _, _ = linux(bpftool=False, password=True)
    assert here_of(r.compare())[("Privileges", "List and read")] == {
        "text": "not listed: bpftool did not answer",
        "sub": "read from bpftool -j version (as the platform's user, then through sudo -n)"}
    t, _, _ = linux(password=True)  # refused at its first listing: that one alone was asked, and is cited
    assert here_of(t.compare())[("Privileges", "List and read")] == {
        "text": f"not listed: {ROOT_REFUSED}", "sub": "read from bpftool -j prog show, as root"}
    # Windows: this PC
    w, _, _ = windows()
    page = plain(w.compare())
    assert page["note"].startswith("This machine: Windows;") and page["tables"][0]["columns"][2]["title"] == (
        "Windows (this machine)")
    here = here_of(page)
    assert set(here) == WINDOWS_HERE and all(isinstance(c, dict) and c["sub"] for c in here.values())
    assert here[("Install and status", "Where it comes from")]["text"] == "eBPF for Windows not installed"
    assert here[("Execution", "HVCI (memory integrity)")] == {"text": "memory integrity on", "sub": "read from "
                                                              "Win32_DeviceGuard, without an administrator"}
    assert here[("Execution", "Interpreter / JIT / native")]["text"] == "no JIT here: memory integrity is on"
    assert here[("Execution", "Signing and test signing")]["text"] == "Secure Boot on; test signing off"
    assert here[("Execution", "Signing and test signing")]["sub"].endswith(
        "; the registry (SystemStartOptions: this boot's start options)")
    production = here[("Install and status", "Production or preview")]
    assert production["text"] == "test-signed: no: the test-signed runtime cannot load here"
    assert production["sub"].startswith(r"read here: Secure Boot from the registry (SecureBoot\State); memory "
                                        "integrity from Win32_DeviceGuard; test signing from the registry "
                                        "(SystemStartOptions: this boot's start options). ")
    # nothing of the services or the facts read: none of them said
    x, _, _ = windows(fail_services="Get-Service failed", fail_facts="Access is denied.")
    assert set(here_of(x.compare())) == {("Privileges", "Load and attach"), ("Basic functions", WATCH_ITEM)}
    # memory integrity off: said so, and no JIT claim from it
    y, _, _ = windows(hvci=False)
    here = here_of(y.compare())
    assert here[("Execution", "HVCI (memory integrity)")]["text"] == "memory integrity off"
    assert ("Execution", "Interpreter / JIT / native") not in here


# -- Functions -----------------------------------------------------------------------------------------------------

def test_functions_lists_the_nine_and_its_forms_ask_each_hook_with_its_arguments_in_order(linux):
    p, _, _ = linux()
    page = plain(p.functions())
    t = page["tables"][0]
    assert [text(r[0]) for r in t["rows"]] == [r["item"] for r in capabilities.functions()] and len(t["rows"]) == 9
    assert all(r[0]["sub"] == SOURCES[("Basic functions", r[0]["text"])] for r in t["rows"])
    here = offered(page)
    assert here["Show a program's info"] == {"form": "show", "title": "Show…", "label": "Show a program"}
    assert here["Dump or read a map"] == {"form": "dump", "title": "Dump…", "label": "Dump a map"}
    assert text(here["Feature probe"]) == "not offered yet" == text(here["Check a program file before loading"])
    assert text(here[WATCH_ITEM]) == "the watch service"
    forms = {f["id"]: f for f in page["forms"]}
    for form_id, hook in (("show", p.show_program), ("dump", p.dump), ("load", p.load_program),
                          ("attach", p.attach_program), ("detach", p.detach_program), ("unload", p.unload_program)):
        f = forms[form_id]
        assert f["hook"] == hook.__name__, form_id
        assert [x["name"] for x in f["fields"]] == list(inspect.signature(hook).parameters), form_id
        assert f["hook"] in p.HOOKS and f["hook"] in p.interface()["hooks"]
    accepts = {f["hook"]: [x["name"] for x in f["fields"] if x["type"] == "accept"] for f in page["forms"]}
    assert accepts == {"show_program": [], "dump": [], "load_program": ["accept_load"],
                       "attach_program": ["accept_attach"], "detach_program": [], "unload_program": ["accept_unload"]}
    assert forms["show"]["confirm"] is False and forms["dump"]["confirm"] is False
    assert all(forms[f]["confirm"]["yes"] for f in ("load", "attach", "detach", "unload"))
    assert forms["unload"]["confirm"]["danger"] and forms["detach"]["confirm"]["danger"]
    for f in page["forms"]:  # a field's `when` names a choice field and values it offers
        fields = {x["name"]: x for x in f["fields"]}
        for x in f["fields"]:
            for name, values in (x.get("when") or {}).items():
                assert set(values) <= {c["value"] for c in fields[name]["choices"]}, (f["id"], x["name"])
    assert [a["form"] for a in page["actions"]] == ["show", "dump", "load", "attach", "detach", "unload"]
    assert not any(a.get("disabled") for a in page["actions"])


def test_every_name_in_a_forms_words_is_a_field_shown_whatever_is_chosen():
    """The page fills `{name}` in a confirmation's and a second confirmation's words from that field's value, shown or
    not (a field whose `when` is unmet keeps its value): words naming one would name what the change does not use (the
    attach's "On" under a sockmap's kind)."""
    for f in plugin.forms():
        fields = {x["name"]: x for x in f["fields"]}
        words = [f["confirm"].get(k, "") for k in ("title", "words", "yes")] if isinstance(f["confirm"], dict) else []
        words += [x.get(k, "") for x in f["fields"] if x["type"] == "accept" for k in ("title", "words", "yes")]
        for w in words:
            for name in re.findall(r"\{(\w+)\}", w):
                assert name in fields and not fields[name].get("when"), (f["id"], name)
    attach = next(f for f in plugin.forms() if f["id"] == "attach")
    assert attach["confirm"]["words"] == ("A {kind} attach, as root, through sudo -n (never a password): the program, "
                                          "and what it goes on, as listed below.")


def test_on_linux_functions_say_what_the_last_read_says_cannot_run(linux, monkeypatch):
    """This PC's WSL Ubuntu (no bpftool, sudo asking for a password, no BPF filesystem): every form that cannot run
    is disabled with why, as on Windows; and where bpftool was refused as root, what runs it as root says so."""
    wsl(monkeypatch)
    p, _, _ = linux(release=WSL2, bpftool=False, bpftrace=False, mounts="", password=True)
    page = plain(p.functions())
    assert disabled(page) == {**dict.fromkeys(("show", "dump", "load", "attach", "detach"), NO_TOOL), "unload": NO_PINS}
    assert page["note"].endswith("What the last read says cannot run here is said so, with why.")
    here = offered(page)
    assert here["Load and attach a pre-built program"] == {"text": "not here", "sub": NO_TOOL}
    assert here["Show a program's info"] == {"text": "not here", "sub": NO_TOOL}
    assert here["Detach and unload"] == {"text": "not here", "sub": f"detach: {NO_TOOL}; unload: {NO_PINS}"}
    assert text(here[WATCH_ITEM]) == "the watch service: cannot run here"
    # bpftool there, root refused: what runs bpftool as root is refused, in sudo's words; the pins can be removed
    q, _, _ = linux(password=True)
    refused = f"bpftool was refused as root here, listing: {ROOT_REFUSED}"
    assert disabled(q.functions()) == dict.fromkeys(("show", "dump", "load", "attach", "detach"), refused)
    # bpftool there, root given, no BPF filesystem at /sys/fs/bpf: nothing to unload, the rest offered
    r, _, _ = linux(mounts="")
    assert disabled(r.functions()) == {"unload": NO_PINS}
    assert text(offered(r.functions())["Detach and unload"]) == "Detach…, above; Unload… not here"
    s, _, _ = linux()  # where it all runs: nothing disabled
    assert disabled(s.functions()) == {}


def test_the_watch_service_is_drawn_nowhere_on_the_page(linux, windows):
    """No tab, form, action or option names watch_start, watch_read or watch_stop: they are for the other plugins,
    asked through the platform."""
    for p in (linux()[0], windows()[0]):
        assert all(t.hook not in WATCH_HOOKS for t in p.TABS)
        for page in (p.status(), p.compare(), p.functions()):
            said = json.dumps(page)
            assert not any(hook in said for hook in WATCH_HOOKS)
        assert set(WATCH_HOOKS) <= set(p.interface()["hooks"])  # yet asked as any hook


# -- the changes -----------------------------------------------------------------------------------------------------

def test_a_load_is_asked_twice_then_run_as_root_and_read_back(linux):
    p, fake, _ = linux()
    p.status()
    with pytest.raises(RiskRefused) as refused:
        p.load_program("/home/you/drop.o")
    assert refused.value.accept == "accept_load" and isinstance(refused.value, ValueError)
    assert str(refused.value) == ("loading a program into the kernel is asked twice: /home/you/drop.o would be checked "
                                  "by the kernel's verifier, loaded as root and pinned at /sys/fs/bpf/liminal_drop, "
                                  "where it stays until it is unloaded or the machine restarts")
    with pytest.raises(RiskRefused):
        p.load_program("/home/you/drop.o", accept_load="yes")  # accepted only exactly: true
    assert fake.changes == []
    reads = fake.asked("uname -r")
    done = plain(p.load_program("/home/you/drop.o", None, "xdp", True))
    assert done == {"said": "/home/you/drop.o loaded and pinned at /sys/fs/bpf/liminal_drop", "lines": [], "ok": True}
    assert fake.changes == [(True, ["bpftool", "prog", "load", "/home/you/drop.o", "/sys/fs/bpf/liminal_drop", "type",
                                    "xdp"])]
    assert fake.asked("uname -r") == reads + 1  # read again at once: Main shows what is there now
    p.load_program("/home/you/drop.o", "/sys/fs/bpf/mine", accept_load=True)
    assert fake.changes[-1][1][3:] == ["/home/you/drop.o", "/sys/fs/bpf/mine"]
    for bad, words in ((("drop.o",), "full path"), (("-d",), "full path"), (("/x.o", "/tmp/pin"), "under /sys/fs/bpf/"),
                       (("/x.o", "/sys/fs/bpf/../x"), "no '..'"), (("/x.o", None, "cgroup/skb"), "plain word")):
        with pytest.raises(ValueError, match=words) as refused:
            p.load_program(*bad, accept_load=True)
        assert not isinstance(refused.value, RiskRefused)  # refused before it is asked twice
    assert len(fake.changes) == 2


def test_a_load_says_bpftool_mounts_the_bpf_filesystem_where_it_is_not(linux):
    """bpftool mounts the BPF filesystem at a pin's folder when it is not there (its own rule, unless --nomount): a
    root change the load's asks name, from what was read, and as a condition before anything is."""
    p, fake, _ = linux(mounts="")
    with pytest.raises(RiskRefused) as unread:
        p.load_program("/home/you/drop.o")
    assert str(unread.value).endswith(f"; where the BPF filesystem is not mounted at /sys/fs/bpf, {MOUNTS}")
    p.status()
    with pytest.raises(RiskRefused) as read:
        p.load_program("/home/you/drop.o")
    assert str(read.value).endswith(f"; the BPF filesystem is not mounted at /sys/fs/bpf (/proc/mounts), so {MOUNTS}")
    assert fake.changes == []
    q, _, _ = linux()  # mounted there: nothing more to say
    q.status()
    with pytest.raises(RiskRefused) as mounted:
        q.load_program("/home/you/drop.o")
    assert "mounts it" not in str(mounted.value)
    load = next(f for f in plugin.forms() if f["id"] == "load")
    assert f"Where the BPF filesystem is not mounted at /sys/fs/bpf, {MOUNTS}." in load["note"]
    assert plugin.bpffs_words(["/run/bpf"]) == ("mounted at /run/bpf", "not at /sys/fs/bpf, where a load pins its "
                                                                       f"program: {MOUNTS}")


def test_an_xdp_cgroup_or_overwriting_attach_is_asked_twice(linux):
    p, fake, _ = linux()
    with pytest.raises(RiskRefused) as refused:
        p.attach_program("xdp", "eth0", "/sys/fs/bpf/liminal_drop")
    assert refused.value.accept == "accept_attach" and str(refused.value) == (
        "an XDP program on eth0 sees every packet it receives, before the rest of the kernel, and may drop it: an "
        "attach like this is asked twice")
    for mode in ("xdp", "xdpgeneric", "xdpdrv", "xdpoffload"):  # every XDP mode, by name
        for accepted in (False, None, "yes", "no", "true", 1):  # accepted only exactly: true
            with pytest.raises(RiskRefused) as refused:
                p.attach_program(mode, "eth0", None, 31, accept_attach=accepted)
            assert refused.value.accept == "accept_attach", (mode, accepted)
    with pytest.raises(RiskRefused) as below:  # a cgroup below the root: every process in it
        p.attach_program("connect4", "/sys/fs/cgroup/app.slice", None, 31)
    assert str(below.value) == ("a program on the cgroup hook connect4 runs for every process in "
                                "/sys/fs/cgroup/app.slice: an attach like this is asked twice")
    assert fake.changes == []
    done = plain(p.attach_program("xdp", "eth0", "/sys/fs/bpf/liminal_drop", accept_attach=True))
    assert done["said"] == "/sys/fs/bpf/liminal_drop attached to eth0 (xdp)" and done["ok"]
    assert fake.changes[-1] == (True, ["bpftool", "net", "attach", "xdp", "pinned", "/sys/fs/bpf/liminal_drop", "dev",
                                       "eth0"])
    p.attach_program("tcx_ingress", "eth0", None, 31, overwrite="no")  # tcx: confirmed once
    assert fake.changes[-1][1] == ["bpftool", "net", "attach", "tcx_ingress", "id", "31", "dev", "eth0"]
    with pytest.raises(RiskRefused, match="it replaces the program attached to eth0 already"):
        p.attach_program("tcx_egress", "eth0", None, 31, overwrite="yes")
    p.attach_program("tcx_egress", "eth0", None, 31, overwrite=True, accept_attach=True)
    assert fake.changes[-1][1][-1] == "overwrite"
    with pytest.raises(RiskRefused, match="runs for every process in /sys/fs/cgroup, which is every process on this "
                                          "machine"):
        p.attach_program("connect4", "/sys/fs/cgroup", None, 31, flags="multi")
    p.attach_program("connect4", "/sys/fs/cgroup/", None, 31, flags="multi", accept_attach=True)
    assert fake.changes[-1][1] == ["bpftool", "cgroup", "attach", "/sys/fs/cgroup", "connect4", "id", "31", "multi"]
    p.attach_program("sk_msg_verdict", None, "/sys/fs/bpf/liminal_msg", map_id=3)  # a sockmap's: once
    assert fake.changes[-1][1] == ["bpftool", "prog", "attach", "pinned", "/sys/fs/bpf/liminal_msg", "sk_msg_verdict",
                                   "id", "3"]
    p.attach_program("flow_dissector", prog_id=31)
    assert fake.changes[-1][1] == ["bpftool", "prog", "attach", "id", "31", "flow_dissector"]
    count = len(fake.changes)
    for bad, words in ((dict(kind="xdp", target="-h", prog_id=31), "network device"),
                       (dict(kind="xdp", target="eth0 eth1", prog_id=31), "network device"),
                       (dict(kind="xdp", target="eth0"), "say which program"),
                       (dict(kind="xdp", target="eth0", pin="/sys/fs/bpf/liminal_x", prog_id=31), "one way"),
                       (dict(kind="xdp", target="eth0", prog_id=31, flags="multi"), "no flag"),
                       (dict(kind="sk_msg_verdict", prog_id=31), "needs the sockmap's id"),
                       (dict(kind="connect4", target="/sys/fs/cgroup", prog_id=31, overwrite=True), "overwrite is"),
                       (dict(kind="connect4", target="/etc", prog_id=31), "cgroup v2 folder"),
                       (dict(kind="connect4", target="/sys/fs/cgroup/../x", prog_id=31), "cgroup v2 folder"),
                       (dict(kind="connect4", target="/sys/fs/cgroup", prog_id=31, flags="all"), "multi or override"),
                       (dict(kind="connect4", target="/sys/fs/cgroup", prog_id=31, map_id=3), "sockmap's id"),
                       (dict(kind="XDP; rm", target="eth0", prog_id=31), "plain word"),
                       (dict(kind="xdp", target="eth0", prog_id=-1), "whole number"),
                       (dict(kind="xdp", target="eth0", prog_id=31, overwrite="maybe"), "yes or no")):
        with pytest.raises(ValueError, match=words) as refused:
            p.attach_program(accept_attach=True, **bad)
        assert not isinstance(refused.value, RiskRefused), bad
    assert len(fake.changes) == count and all(root for root, _ in fake.changes)  # every change as root


def test_a_detach_is_confirmed_once_and_an_unload_asks_twice_for_a_pin_not_liminals(linux):
    p, fake, _ = linux()
    assert plain(p.detach_program(7))["said"] == "link 7 detached"
    assert fake.changes[-1][1] == ["bpftool", "link", "detach", "id", "7"]
    p.detach_program(None, "xdp", "eth0")
    assert fake.changes[-1][1] == ["bpftool", "net", "detach", "xdp", "dev", "eth0"]
    assert p.detach_program(None, "connect4", "/sys/fs/cgroup", None, 31)["said"] == ("program 31 detached from "
                                                                                    "/sys/fs/cgroup (connect4)")
    assert fake.changes[-1][1] == ["bpftool", "cgroup", "detach", "/sys/fs/cgroup", "connect4", "id", "31"]
    p.detach_program(None, "sk_skb_verdict", None, "/sys/fs/bpf/liminal_skb", None, 3)
    assert fake.changes[-1][1] == ["bpftool", "prog", "detach", "pinned", "/sys/fs/bpf/liminal_skb", "sk_skb_verdict",
                                   "id", "3"]
    for bad, words in (((7, "xdp"), "one way"), ((), "say what to detach"), ((None, "xdp", "eth0", None, 31), "alone"),
                       ((None, "sk_msg_verdict", None, None, 31), "sockmap's id")):
        with pytest.raises(ValueError, match=words):
            p.detach_program(*bad)
    assert plain(p.unload_program("/sys/fs/bpf/liminal_drop"))["said"] == ("/sys/fs/bpf/liminal_drop removed: its "
                                                                           "program unloads once nothing else holds it")
    assert fake.changes[-1] == (True, ["rm", "-f", "/sys/fs/bpf/liminal_drop"])
    with pytest.raises(RiskRefused) as refused:
        p.unload_program("/sys/fs/bpf/sd_devices")
    assert refused.value.accept == "accept_unload" and "not one of Liminal's own pins" in str(refused.value)
    for accepted in ("yes", "no", "true", 1, None):  # accepted only exactly: true
        with pytest.raises(RiskRefused):
            p.unload_program("/sys/fs/bpf/sd_devices", accepted)
    assert len(fake.changes) == 5
    p.unload_program("/sys/fs/bpf/sd_devices", True)
    assert fake.changes[-1][1] == ["rm", "-f", "/sys/fs/bpf/sd_devices"]
    for bad in ("/etc/passwd", "/sys/fs/bpf/", "", None, "/sys/fs/bpf/a/../../x"):
        with pytest.raises(ValueError):
            p.unload_program(bad, True)
    assert len(fake.changes) == 6


def test_a_change_that_fails_says_bpftools_own_words_and_main_is_read_again(linux):
    p, fake, _ = linux(fail={"bpftool prog load": (255, json.dumps({"error": "failed to open object file"}), "")})
    p.status()
    reads = fake.asked("uname -r")
    with pytest.raises(CommandError, match=r"^bpftool: failed to open object file$"):
        p.load_program("/home/you/missing.o", accept_load=True)
    assert fake.asked("uname -r") == reads + 1
    q, qfake, _ = linux(password=True)  # sudo asks for a password: refused in sudo's words, said how to give the right
    with pytest.raises(CommandError, match="let sudo run it without a password") as refused:
        q.unload_program("/sys/fs/bpf/liminal_drop")
    assert refused.value.denied and qfake.changes == []


def test_on_windows_every_change_is_refused_in_words(windows):
    p, fake, _ = windows()
    p.status()
    before = len(fake.scripts)
    for call in (lambda: p.load_program("/x.o", accept_load=True),
                 lambda: p.attach_program("xdp", "eth0", "/sys/fs/bpf/liminal_x", accept_attach=True),
                 lambda: p.detach_program(7), lambda: p.unload_program("/sys/fs/bpf/liminal_x", True)):
        with pytest.raises(ValueError) as refused:
            call()
        assert str(refused.value) == THIS_PC and not isinstance(refused.value, RiskRefused)
    assert len(fake.scripts) == before  # nothing was asked of the machine
    page = plain(p.functions())
    here = offered(page)
    assert here["Load and attach a pre-built program"] == {"text": "refused here", "sub": THIS_PC}
    assert here["Detach and unload"] == {"text": "refused here", "sub": THIS_PC}
    assert here["Dump or read a map"] == {"text": "nothing to dump", "sub": "eBPF for Windows is not installed"}
    assert text(here["Show a program's info"]) == "nothing to show"
    assert page["note"].endswith(f"Every change is refused here: {THIS_PC}")
    assert disabled(page) == {"show": "eBPF for Windows is not installed", "dump": "eBPF for Windows is not installed",
                              "load": THIS_PC, "attach": THIS_PC, "detach": THIS_PC, "unload": THIS_PC}
    assert [f["id"] for f in page["forms"]] == ["show", "dump", "load", "attach", "detach", "unload"]
    # before anything is read, the words say what holds on any machine
    q, _, _ = windows()
    with pytest.raises(ValueError, match=r"^eBPF for Windows' public builds are all test-signed, and Windows loads a "
                                         r"test-signed driver only in test-signing mode, which needs Secure Boot off\. "
                                         r"This plugin loads"):
        q.load_program("/x.o")


# -- the reads -----------------------------------------------------------------------------------------------------

def test_a_program_is_shown_and_a_map_dumped_as_root_in_lines(linux):
    p, fake, _ = linux()
    shown = plain(p.show_program(12))
    assert shown["said"] == "program 12: sd_devices, cgroup_device" and shown["ok"] is True
    assert "tag: e3dbd137be8d6168" in shown["lines"] and "map_ids: [3]" in shown["lines"]
    assert shown["program"]["map_ids"] == [3]
    assert (True, ["bpftool", "-j", "prog", "show", "id", "12"]) in fake.commands
    assert p.show_program("31")["said"] == "program 31: liminal_drop, xdp"  # an id as a form's text gives it
    with pytest.raises(CommandError, match="can't get prog by id"):
        p.show_program(99)
    dumped = plain(p.dump(3, 10))
    assert dumped["said"] == "map 3: 2 entries" and dumped["ok"] is True
    assert dumped["lines"] == ['["0x01","0x00","0x00","0x00"] → ["0x2a","0x00","0x00","0x00","0x00","0x00","0x00",'
                               '"0x00"]', '2 → {"hits":5,"rate":null}']
    assert dumped["entries"][1] == {"key": 2, "value": {"hits": 5, "rate": None}}  # plain JSON, whatever it printed
    assert (True, ["sh", "-c", "bpftool -j map dump id 3 2>&1 | head -c 8000000"]) in fake.commands
    assert p.dump(3, 1)["said"] == "map 3: 1 entry, the first 1"
    assert p.dump(3, None)["said"] == "map 3: 2 entries"  # a form left empty: the default
    for bad in ((-1,), ("x",), (3, 0), (3, 1001), (True,), (1.5,)):
        with pytest.raises(ValueError):
            p.dump(*bad)
    with pytest.raises(CommandError, match="can't get map by id"):
        p.dump(4)


def test_on_windows_a_dump_is_empty_and_says_why(windows):
    p, _, _ = windows()
    p.status()
    with pytest.raises(ValueError, match="^eBPF for Windows is not installed here: there is no program to show$"):
        p.show_program(1)
    assert plain(p.dump(3)) == {"said": "eBPF for Windows is not installed here: there is no map to dump", "lines": [],
                                "ok": True, "entries": []}
    q, qfake, _ = windows(installed=True)
    q.status()
    # the plugin's own limit, said as its own: it reads eBPF for Windows through netsh (the bpftool port can dump)
    assert q.dump(3)["said"] == ("the plugin reads eBPF for Windows through netsh, which lists maps but cannot read "
                                 "one's entries (its bpftool port can): nothing is dumped on Windows")
    assert qfake.ran("map dump") == 0
    assert offered(q.functions())["Dump or read a map"] == {"text": "not offered here", "sub": plugin.NETSH_DUMP}
    assert disabled(q.functions())["dump"] == plugin.NETSH_DUMP


# -- the watch service -----------------------------------------------------------------------------------------------

def test_the_watch_hooks_hand_on_to_the_service_and_the_detach_stops_every_watch(linux):
    p, _, factory = linux()
    a = plain(p.watch_start(["process", "file"], {"pid": 4242}))
    assert a["kinds"] == ["file", "process"] and a["system"] == "linux" and re.fullmatch(r"[0-9a-f]{16}", a["id"])
    assert factory.asked == [(frozenset({"process", "file"}), {"pid": 4242})]
    factory.made[0].feed("process", "exec", pid=7, ppid=1, program="sh", path="/bin/sh")
    r = plain(p.watch_read(a["id"]))
    assert r["seq"] == 1 and r["events"][0]["path"] == "/bin/sh" and isinstance(r["events"][0]["at"], float)
    b = plain(p.watch_start(["net"]))
    assert b["id"] != a["id"] and len(factory.made) == 2  # each caller a watch of its own
    copy = p.with_(origin="registry")
    assert plain(copy.watch_read(b["id"]))["seq"] == 0  # the registry's copy reads the same watches
    with pytest.raises(ValueError, match="a watch's kinds are a list"):
        p.watch_start("net")
    assert plain(p.watch_stop(a["id"])) == {"id": a["id"], "stopped": True, "error": ""} and factory.made[0].stopped
    with pytest.raises(LookupError):
        p.watch_read(a["id"])
    p.attach(App())
    p.detach()  # every live watch stopped, never raising; and none started until it is attached again
    assert all(w.stopped for w in factory.made)
    # and the app let go, as every plugin's detach does: the platform attaches again only a plugin whose app is none
    assert p.app is None and p.login is None and p.interface()["attached"] is False
    made = len(factory.made)
    with pytest.raises(ValueError, match=f"^{plugin.DETACHED}$"):
        p.watch_start(["net"])
    assert len(factory.made) == made  # none made at all: on Linux a bpftrace would have been started
    p.attach(App())
    c = p.watch_start(["file"])
    assert not c["stopped"] and p.watch_stop(c["id"])["stopped"]
    settled()


def test_a_watch_started_as_the_plugin_is_detached_is_stopped_too(linux, monkeypatch):
    p, _, factory = linux()
    started = p._rt.service.start

    def detached_meanwhile(kinds, spec=None):
        answer = started(kinds, spec)
        p.detach()  # the detach lands while this start is under way
        return answer
    monkeypatch.setattr(p._rt.service, "start", detached_meanwhile)
    with pytest.raises(ValueError, match=f"^{plugin.DETACHED}$"):
        p.watch_start(["net"])
    assert factory.made[0].stopped


def test_the_plugin_runs_at_most_eight_watches_at_once(linux, windows):
    """The plugin's own service holds the cap (8), through its hooks, on Linux and on Windows (process watches there:
    a net one would ask for the route), and its facts say it out of that cap."""
    for p, card, label in ((linux()[0], "bpftrace", "Watches running"),
                           (windows()[0], "Event Tracing for Windows (ETW)", "Watches running")):
        kinds = ["process"]
        ids = [p.watch_start(kinds)["id"] for _ in range(8)]
        assert p.api_facts()[card][label].startswith("8 of 8: process since ")
        with pytest.raises(ValueError, match=r"^8 watches are running, the most at once here"):
            p.watch_start(kinds)
        p.watch_stop(ids[0])
        assert not p.watch_start(kinds)["stopped"]  # one stopped: one more starts


class Closing(Watch):
    """A watch whose source takes its time to close (bpftrace past its SIGTERM grace)."""

    def __init__(self, kinds, spec=None, *, hold, **options):
        super().__init__(kinds, spec, **options)
        self.hold = hold

    def _end(self):
        self.hold.wait(10)


def test_the_plugins_detach_is_quick_whatever_a_watch_takes_to_close(linux, clock):
    """The detach runs in a request thread: it waits STOP_ALL_S at most in all, the close still under way finishing on
    a daemon thread of its own (one that keeps no interpreter from exiting)."""
    hold = threading.Event()
    p, _, _ = linux(factory=lambda kinds, spec: Closing(kinds, spec, hold=hold, clock=clock))
    p.watch_start(["file"])
    began = time.monotonic()
    p.detach()
    took = time.monotonic() - began
    assert took < watch_service.STOP_ALL_S + 1.0, took
    closing = [t for t in threading.enumerate() if t.name == watch_service.STOPPER and t.is_alive()]
    assert closing and all(t.daemon for t in closing)
    hold.set()
    assert all(t.join(5) is None and not t.is_alive() for t in closing)


def test_a_windows_net_watch_reads_this_machines_way_out(windows, monkeypatch):
    monkeypatch.setattr(world, "route_address", lambda: "192.168.1.20")
    p, _, factory = windows()
    a = plain(p.watch_start(["net", "registry"]))
    assert (a["system"], a["address"], a["kinds"]) == ("windows", "192.168.1.20", ["net", "registry"])
    assert factory.asked == [(frozenset({"net", "registry"}), {"address": "192.168.1.20"})]
    # running is reading: a capture lost after it opened ends the watch (liminal-libs 1.60.0's Windows watch)
    assert p.api_facts()["Npcap (packet capture)"]["Net watches running"].startswith("1 of 8: net+registry since ")
    assert "Net watches started" not in p.api_facts()["Npcap (packet capture)"]
    p.watch_stop(a["id"])


def test_the_first_attach_on_the_platform_reclaims_the_etw_sessions_a_killed_platform_left(windows, linux, clock):
    asked = []
    p, _, _ = windows(reclaim=lambda: asked.append("reclaimed") or [])
    for app in (App("charts"), App("platform", once=True)):  # another app; a one-shot platform command
        p.attach(app)
        p.detach()
    assert asked == []
    p.attach(App())
    p.detach()
    p.attach(App())
    assert asked == ["reclaimed"]  # once, at the plugin's first attach on the platform

    def failing():
        raise OSError("advapi32 could not be loaded")
    q, _, _ = windows(reclaim=failing)
    assert q.attach(App())["name"] == "ebpf"  # a reclaim that fails never fails the attach
    lin = EbpfPlugin(linux()[0]._runtime, lambda kinds, spec: None, clock=clock, reclaim=lambda: asked.append("linux"),
                     system="linux")
    lin.attach(App())
    assert asked == ["reclaimed"]  # never on Linux
    settled()


# -- what it learned, asking nothing ------------------------------------------------------------------------------

def test_api_facts_say_what_was_learned_asking_nothing(linux, windows):
    p, fake, _ = linux()
    assert plain(p.api_facts()) == {"bpftrace": {"Watches running": "none running (at most 8 at once)"}}
    assert fake.commands == [] and not any(t.name == plugin.READER for t in threading.enumerate())  # nothing asked
    p.status()
    n = len(fake.commands)
    facts = plain(p.api_facts())
    assert len(fake.commands) == n
    assert set(facts) == {"bpftool", "bpftrace", KERNEL_CARD} <= {a.name for a in p.apis}
    assert facts["bpftool"]["Version"] == "7.4.0 — libbpf 1.4; built with llvm, skeletons"
    assert (facts["bpftool"]["Programs"], facts["bpftool"]["Maps"], facts["bpftool"]["Links"]) == ("2 programs",
                                                                                                  "1 map", "1 link")
    assert facts["bpftrace"]["Version"] == "bpftrace v0.20.2"
    assert facts["bpftrace"]["The watch"].startswith("bpftrace, through sudo -n — sudo -n bpftrace -V answered")
    kernel = facts[KERNEL_CARD]
    assert (kernel["Release"], kernel["bpf_jit_enable"], kernel["Kernel BTF"]) == ("6.8.0-45-generic", "1: on", "yes")
    w = p.watch_start(["net"])
    assert p.api_facts()["bpftrace"]["Watches running"].startswith("1 of 8: net since ")
    p.watch_stop(w["id"])
    assert all(isinstance(v, str) for f in facts_of(p).values() for v in f.values())  # as the platform's card reads it
    q, _, _ = windows()
    q.status()
    f = plain(q.api_facts())
    assert set(f) == {"eBPF for Windows", "Npcap (packet capture)", "Event Tracing for Windows (ETW)"}
    assert (f["eBPF for Windows"]["Installed"], f["eBPF for Windows"]["Test signing"]) == (
        "no", "off, read from the registry (SystemStartOptions: this boot's start options)")
    assert f["eBPF for Windows"]["Services"] == "eBPFCore absent; NetEbpfExt absent; eBPFSvc absent"
    assert f["Npcap (packet capture)"]["Administrators only"] == "no"
    assert f["Npcap (packet capture)"]["Net watches running"] == "none (at most 8 at once)"
    assert f["Event Tracing for Windows (ETW)"]["Watches running"] == "none (at most 8 at once)"
    assert f["Event Tracing for Windows (ETW)"]["Real-time session"].startswith(
        "may start here: in Performance Log Users")


def test_the_windows_backend_is_read_without_opening_anything(monkeypatch, tmp_path):
    """windows_backend (the real one, bound as this module was imported: conftest stands in for it) reads wpcap.dll's
    presence, Npcap's AdminOnly option, the token and ETW's right: never load_pcap, never a session (conftest refuses
    both, and fails the test if either is reached)."""
    (tmp_path / "wpcap.dll").write_bytes(b"")
    monkeypatch.setattr(capture, "NPCAP", str(tmp_path))
    monkeypatch.setattr(capture, "npcap_admin_only", lambda: True)
    monkeypatch.setattr(capture, "administrator", lambda: False)
    monkeypatch.setattr(etw, "available", lambda: (False, "not elevated and not in Performance Log Users"))
    assert windows_backend() == {"npcap": True, "admin_only": True, "administrator": False, "etw": False,
                                 "etw_why": "not elevated and not in Performance Log Users"}


# -- the command line ----------------------------------------------------------------------------------------------

def test_the_command_line_prints_the_pages_and_a_watch(linux, monkeypatch, capsys):
    p, fake, factory = linux()
    factory.events.append(("process", "exec", {"pid": 7, "ppid": 1, "program": "sh", "path": "/bin/sh"}))
    monkeypatch.setattr(cli, "MACHINE", p)
    monkeypatch.setattr(cli, "POLL_S", 0.01)
    assert cli.main(["status"]) == 0 and json.loads(capsys.readouterr().out)["valid"] is True
    assert cli.main([]) == 0 and json.loads(capsys.readouterr().out)["present"] is True  # status, the default
    assert cli.main(["compare"]) == 0 and len(json.loads(capsys.readouterr().out)["tables"]) == 12
    assert cli.main(["functions"]) == 0 and len(json.loads(capsys.readouterr().out)["tables"][0]["rows"]) == 9
    assert cli.main(["watch", "process", "--seconds", "0.05", "--pid", "7"]) == 0
    out = capsys.readouterr()
    assert out.err.startswith("watching process on linux for 0.05 s")
    [line] = out.out.splitlines()
    assert re.fullmatch(r"\d\d:\d\d:\d\d\.\d{3}  process exec  sh\[7\]  /bin/sh", line)
    assert factory.asked[-1] == (frozenset({"process"}), {"pid": 7}) and factory.made[-1].stopped
    # bounded: a refusal that went missing fails here, never hangs the run
    assert cli.main(["watch", "dns", "--seconds", "0.2"]) == 1
    assert "is not a kind a watch follows" in capsys.readouterr().err
    factory.fail = "bpftrace ended (exit code 1): sudo: a password is required"  # its source could not open
    assert cli.main(["watch", "net", "--seconds", "5"]) == 1
    assert capsys.readouterr().err.endswith("the watch ended: bpftrace ended (exit code 1): sudo: a password is "
                                            "required\n")
    with pytest.raises(SystemExit):
        cli.main(["watch", "--help"])
    assert "inside a WSL distribution not the pid ps shows there" in " ".join(capsys.readouterr().out.split())
    q, _, _ = linux(bpftool=False)
    monkeypatch.setattr(cli, "MACHINE", q)
    assert cli.main(["status"]) == 1  # the runtime is not there
    with pytest.raises(SystemExit) as usage:
        cli.main(["nonsense"])
    assert usage.value.code == 2
