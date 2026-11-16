"""What every test here shares.

The machine the tests run on never shows through: not inside WSL (the library's world.under_wsl and machines.linux.wsl,
which a suite run inside a WSL distribution would otherwise find), no /etc/os-release (the plugin's os_release and
os_ids), and no real administrator's token, Npcap install or ETW right read (the plugin's is_elevated and
windows_backend stood in for), so the pages read alike on Windows, inside a WSL distribution and on a Linux of its own.
A test that wants one of these says so itself. The machine's own word for what it is (sys.platform) is the fixtures'
(`where`), never this one's.

Nothing real is reached: no process is started (subprocess.Popen and subprocess.run refuse), no Npcap loaded, no ETW
session, consumer or DLL opened, none reclaimed, no route asked. Each reach is noted, so one inside a reading thread or
a watch's fails the test too, and no reading or watching thread may be left after a test.

The stand-ins the plugin is driven with (the fixtures `linux` and `windows`): the library's own runtimes over a
stand-in machine (FakeLinux answers the commands a Linux runtime runs; FakeWindows answers powershell.exe as the Windows
runtime asks it), and a watch factory of the library's own Watch over sources the test controls, on a clock the test
moves."""
from __future__ import annotations

import json
import re
import subprocess
import threading
import time
import types

import pytest

import plugin_platform_ebpf as plugin
from liminal_libs import capture, netpath
from liminal_libs.ebpf.linux import LinuxRuntime
from liminal_libs.ebpf.watch import Watch
from liminal_libs.ebpf.windows import WindowsRuntime
from liminal_libs.machines import etw, linux as machines_linux, world
from liminal_libs.machines.linux import Shell
from liminal_libs.machines.plugin import CommandError
from liminal_libs.machines.windows import ERROR_MARK, PowerShell, decoded
from plugin_platform_ebpf import EbpfPlugin

THREADS = (plugin.READER, "ebpf-watch", "ebpf-bpftrace", "npcap-etw-watch", "ebpf-watch-stop")
BACKEND = {"npcap": True, "admin_only": False, "administrator": False, "etw": True,
           "etw_why": "in Performance Log Users: a real-time session can be started unelevated"}  # this PC's, as read
BPFFS = "bpf /sys/fs/bpf bpf rw,nosuid,nodev,noexec,relatime,mode=700 0 0\n"
MOUNTS = "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n" + BPFFS
VERSION = {"version": "7.4.0", "libbpf_version": "1.4", "features": {"libbfd": False, "llvm": True, "skeletons": True}}
PROGRAMS = [{"id": 12, "type": "cgroup_device", "tag": "e3dbd137be8d6168", "gpl_compatible": True,
             "loaded_at": 1800000000, "uid": 0, "map_ids": [3], "name": "sd_devices"},
            {"id": 31, "type": "xdp", "tag": "aa01bb02cc03dd04", "loaded_at": 1800000100, "name": "liminal_drop"}]
MAPS = [{"id": 3, "type": "hash", "name": "sd_devices_map", "flags": 0, "bytes_key": 4, "bytes_value": 8,
         "max_entries": 1024}]
LINKS = [{"id": 7, "type": "xdp", "prog_id": 31, "ifindex": 2, "devname": "eth0"}]
ENTRIES = {3: [{"key": ["0x01", "0x00", "0x00", "0x00"], "value": ["0x2a", "0x00", "0x00", "0x00", "0x00", "0x00",
                                                                  "0x00", "0x00"]},
               {"key": 2, "value": {"hits": 5, "rate": float("nan")}}]}
NETSH_PROGRAMS = ("\n    ID  Pins  Links  Mode       Type           Name\n"
                  "======  ====  =====  =========  =============  ====================\n"
                  " 65537     1      1  NATIVE     xdp            dropper\n")
# the kernel's functions the watch scripts' kprobes look for, as a kernel has them: udp_sendmsg and udpv6_sendmsg (the
# library's net script probes both from liminal-libs 1.60.0; before, it probed udp_v6_sendmsg, which no kernel has)
SYMBOLS = ("udp_sendmsg", "udpv6_sendmsg")
NO_SUDO = "sudo could not run on this machine: [Errno 2] No such file or directory: 'sudo'"  # the library's Shell's


class Clock:
    """A clock that moves only when the test moves it."""

    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


class FakeLinux:
    """A Linux machine as the runtime's commands find it: its kernel's files, bpftool and bpftrace when they are
    installed, sudo with or without a password (`password`), its programs, maps, links and map entries. Records every
    command, with whether it ran as root (through sudo -n), and the changes apart. `fail` maps a command's start to the
    (code, stdout, stderr) it answers instead.

    sudo as sudoers makes it: `password`, sudo -n refuses every command but those `nopasswd` names (a least-privilege
    rule: NOPASSWD for bpftool and bpftrace alone); `sudo` False, no sudo installed (the library's Shell says it could
    not run); `user_only`, commands on the platform's user's path that sudo's own path (secure_path) lacks. `symbols`:
    the kernel functions /proc/kallsyms lists, `kallsyms` False where it cannot be read."""

    def __init__(self, release="6.8.0-45-generic", bpftool=True, bpftrace=True, btf=True, mounts=MOUNTS,
                 unprivileged="2", jit="1", password=False, programs=None, maps=None, links=None, entries=None,
                 fail=None, nopasswd=(), sudo=True, user_only=(), symbols=SYMBOLS, kallsyms=True):
        self.release, self.bpftool, self.bpftrace, self.btf, self.mounts = release, bpftool, bpftrace, btf, mounts
        self.unprivileged, self.jit, self.password = unprivileged, jit, password
        self.nopasswd, self.sudo, self.user_only = tuple(nopasswd), sudo, tuple(user_only)
        self.symbols, self.kallsyms = tuple(symbols), kallsyms
        self.programs = list(PROGRAMS if programs is None else programs)
        self.maps = list(MAPS if maps is None else maps)
        self.links = list(LINKS if links is None else links)
        self.entries = dict(ENTRIES if entries is None else entries)
        self.fail = dict(fail or {})
        self.commands: list[tuple[bool, list[str]]] = []
        self.changes: list[tuple[bool, list[str]]] = []

    def __call__(self, args, timeout):
        root = list(args[:2]) == ["sudo", "-n"]
        argv = [str(a) for a in (args[2:] if root else args)]
        self.commands.append((root, argv))
        if root and not self.sudo:  # as the library's Shell says it when subprocess finds no sudo
            raise CommandError(NO_SUDO)
        if root and self.password and argv[0] not in self.nopasswd:
            return 1, "", "sudo: a password is required\n"
        if root and argv[0] in self.user_only:
            return 1, "", f"sudo: {argv[0]}: command not found\n"
        line = " ".join(argv)
        for start, answer in self.fail.items():
            if line.startswith(start):
                return answer
        missing = (127, "", f"{argv[0]}: command not found\n")
        if line == "uname -r":
            return 0, self.release + "\n", ""
        if line == "true":
            return 0, "", ""
        if argv[:2] == ["sh", "-c"] and plugin.KALLSYMS in argv[2]:  # the kprobes' functions, looked for
            if not self.kallsyms:
                return 3, "", ""
            wanted = re.findall(r"-e (\w+)", argv[2])
            return 0, "".join(f"ffffffff8{i:07x} T {s}\n" for i, s in enumerate(self.symbols) if s in wanted), ""
        if line == "bpftool -j version":
            return (0, json.dumps(VERSION), "") if self.bpftool else missing
        if line == "cat /proc/sys/kernel/unprivileged_bpf_disabled":
            return 0, self.unprivileged + "\n", ""
        if line == "cat /proc/sys/net/core/bpf_jit_enable":
            return 0, self.jit + "\n", ""
        if line == "ls /sys/kernel/btf/vmlinux":
            return (0, "/sys/kernel/btf/vmlinux\n", "") if self.btf else (2, "", "ls: cannot access\n")
        if line == "cat /proc/mounts":
            return 0, self.mounts, ""
        if line == "bpftrace -V":
            return (0, "bpftrace v0.20.2\n", "") if self.bpftrace else missing
        if not self.bpftool and argv[0] == "bpftool":
            return missing
        for what, rows in (("prog", self.programs), ("map", self.maps), ("link", self.links)):
            if line == f"bpftool -j {what} show":
                return 0, json.dumps(rows), ""
        found = re.fullmatch(r"bpftool -j prog show id (\d+)", line)
        if found:
            p = next((p for p in self.programs if p["id"] == int(found.group(1))), None)
            refused = {"error": f"can't get prog by id ({found.group(1)}): No such file or directory"}
            return (0, json.dumps(p), "") if p else (255, json.dumps(refused), "")
        if argv[:2] == ["sh", "-c"]:
            found = re.search(r"bpftool -j map dump id (\d+)", argv[2])
            entries = self.entries.get(int(found.group(1))) if found else None
            if entries is None:
                return 0, json.dumps({"error": "can't get map by id: No such file or directory"}), ""
            return 0, json.dumps(entries), ""
        if argv[0] == "bpftool" or argv[:2] == ["rm", "-f"]:
            self.changes.append((root, argv))
            return 0, "", ""
        return missing

    def asked(self, command: str) -> int:
        """How many times a command was run."""
        return sum(1 for _, argv in self.commands if " ".join(argv) == command)


class StandInShell(Shell):
    """The library's Shell on this machine ("local") with a stand-in runner; `root`: whether the platform runs as
    root (the test's word, not this process's)."""

    def __init__(self, runner, root: bool = False):
        super().__init__("local", runner=runner)
        self._as_root = root

    def root(self) -> bool:
        return self._as_root


class FakeWindows:
    """powershell.exe as the Windows runtime asks it: eBPF for Windows' three services and its version, Secure Boot,
    memory integrity and test signing as Windows gives them unelevated (test signing off, read from this boot's start
    options, which any user may read: liminal-libs 1.60.0), and netsh when eBPF for Windows is installed. Records
    every script."""

    def __init__(self, installed=False, running=True, version="1.7.0", secure_boot=True, source="registry", hvci=True,
                 test_signing=False, readable=True, signing_source="boot options", programs=NETSH_PROGRAMS,
                 netsh_denied=False, fail_services="", fail_facts=""):
        self.installed, self.running, self.version = installed, running, version
        self.facts = {"SecureBoot": secure_boot, "SecureBootSource": source, "Hvci": hvci, "TestSigning": test_signing,
                      "TestSigningReadable": readable, "TestSigningSource": signing_source}
        self.programs, self.netsh_denied = programs, netsh_denied
        self.fail_services, self.fail_facts = fail_services, fail_facts
        self.scripts: list[str] = []

    def __call__(self, args, timeout):
        script = decoded(args[6])
        self.scripts.append(script)
        if "Get-Service -Name $n" in script:
            if self.fail_services:
                return 1, ERROR_MARK + self.fail_services + "\r\n", ""
            services = [{"Name": n, "Present": self.installed, "Status": ("Running" if self.running else "Stopped")
                         if self.installed else "", "StartType": "Automatic" if self.installed else ""}
                        for n in ("eBPFCore", "NetEbpfExt", "eBPFSvc")]
            return 0, json.dumps({"Services": services, "Version": self.version if self.installed else ""}), ""
        if "Confirm-SecureBootUEFI" in script:
            if self.fail_facts:
                return 1, ERROR_MARK + self.fail_facts + "\r\n", ""
            return 0, json.dumps(self.facts), ""
        if "netsh ebpf show" in script:
            if self.netsh_denied:
                return 1, ERROR_MARK + "Access is denied.\r\n", ""
            if "show programs" in script:
                return 0, self.programs, ""
            return 0, "", ""
        return 0, "", ""

    def ran(self, words: str) -> int:
        return sum(1 for s in self.scripts if words in s)


class StandIn(Watch):
    """The library's Watch (its ring, its read, its self-stop) over a source that is the test: nothing is opened.
    `feed` hands it an event as a source would; `fail`: its source refuses to open, in those words."""

    def __init__(self, kinds, spec=None, *, fail="", system="linux", **options):
        super().__init__(kinds, spec, **options)
        self.fail, self.system = fail, system

    def _begin(self):
        if self.fail:
            self.error = self.fail
            self._stop.set()

    def feed(self, kind, action, **fields):
        self._emit(kind, action, **fields)


class Factory:
    """ebpf.make_watch as a stand-in: what it was asked and each watch it made, on the test's clock and for the
    test's system; `events` are fed to each watch as it is made (a source's first events)."""

    def __init__(self, clock, system="linux", fail="", events=()):
        self.clock, self.system, self.fail, self.events = clock, system, fail, list(events)
        self.asked: list[tuple[frozenset, dict]] = []
        self.made: list[StandIn] = []

    def __call__(self, kinds, spec):
        self.asked.append((kinds, spec))
        watch = StandIn(kinds, spec, clock=self.clock, fail=self.fail, system=self.system)
        for kind, action, fields in self.events:
            watch.feed(kind, action, **fields)
        self.made.append(watch)
        return watch


def live_threads() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.is_alive() and (t.name in THREADS or t.name.startswith("etw-"))]


def wait_for(condition, seconds: float = 3.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.005)
    return condition()


@pytest.fixture(autouse=True)
def _not_this_machine(monkeypatch):
    monkeypatch.setattr(world, "under_wsl", lambda *args, **kwargs: None)
    monkeypatch.setattr(machines_linux, "wsl", lambda *args, **kwargs: "", raising=False)  # 1.57.0's, else none
    monkeypatch.setattr(plugin, "is_elevated", lambda: False)
    monkeypatch.setattr(plugin, "windows_backend", lambda: dict(BACKEND))
    monkeypatch.setattr(plugin, "os_release", lambda: "")
    monkeypatch.setattr(plugin, "os_ids", lambda: ())


@pytest.fixture(autouse=True)
def _nothing_real_runs(monkeypatch):
    """Each real thing refuses, and the reach is noted; at the end, nothing was reached and no thread is left."""
    reached: list[str] = []

    def refusing(name):
        def refuse(*args, **kwargs):
            reached.append(name)
            raise AssertionError(f"a test reached the real {name}")
        return refuse
    for module, name in ((subprocess, "Popen"), (subprocess, "run"), (capture, "load_pcap"), (etw, "EtwConsumer"),
                         (etw, "WinAdvapi32"), (etw, "WinTdh"), (etw, "reclaim_stale_sessions"),
                         (world, "route_address"), (netpath, "lan_address")):
        monkeypatch.setattr(module, name, refusing(name))
    yield types.SimpleNamespace(reached=reached)
    assert wait_for(lambda: live_threads() == []), f"a thread was left: {live_threads()}"
    assert reached == [], f"a test reached the real {', '.join(reached)}"


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def linux(clock):
    """make(**answers) -> (plugin, fake machine, watch factory): the plugin on a stand-in Linux (FakeLinux's answers;
    `root`: the platform runs as root; `where`: the system the runtime finds itself on, sys.platform's word), its
    watches the factory's. Every plugin made is detached after the test, its watches stopped."""
    made: list[EbpfPlugin] = []

    def make(fake=None, *, root=False, factory=None, where="linux", **answers):
        fake = fake if fake is not None else FakeLinux(**answers)
        runtime = LinuxRuntime(shell=StandInShell(fake, root), system=where, release=fake.release, env={})
        factory = factory if factory is not None else Factory(clock, "linux")
        p = EbpfPlugin(runtime, factory, clock=clock, system="linux", where=where)
        made.append(p)
        return p, fake, factory
    yield make
    for p in made:
        p.detach()


@pytest.fixture
def windows(clock, monkeypatch):
    """make(**answers) -> (plugin, fake powershell.exe, watch factory): the plugin on a stand-in Windows (FakeWindows'
    answers; `elevated`: the platform runs as an administrator; `backend`: what the Windows watch finds, over this PC's;
    `reclaim`: the stand-in for etw.reclaim_stale_sessions). Detached after the test."""
    made: list[EbpfPlugin] = []

    def make(fake=None, *, elevated=False, backend=None, factory=None, reclaim=None, **answers):
        fake = fake if fake is not None else FakeWindows(**answers)
        monkeypatch.setattr(plugin, "is_elevated", lambda: elevated)
        monkeypatch.setattr(plugin, "windows_backend", lambda: {**BACKEND, **(backend or {})})
        factory = factory if factory is not None else Factory(clock, "windows")
        p = EbpfPlugin(WindowsRuntime(PowerShell(runner=fake, env={})), factory, clock=clock, reclaim=reclaim,
                       system="windows", where="win32")
        made.append(p)
        return p, fake, factory
    yield make
    for p in made:
        p.detach()
