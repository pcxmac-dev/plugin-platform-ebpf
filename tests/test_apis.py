"""What the eBPF plugin attaches to (plugin API 2.2): its seven cards are sound (problems()==[]); every one of the
library's 65 capability rows has a source page, and every source key is a real row, so the Compare tab's source links
are complete; each card's "used" calls are the ones the library's code actually makes (read from the library's source,
the way the model plugin checks its Npcap card); and the cards' pages answer only under LIMINAL_VENDOR_PAGES=1, the one
test that reaches the makers' pages. Nothing here runs a process or reaches the network otherwise: it reads card data
and library source text."""
from __future__ import annotations

import inspect
import os
import re

import pytest

from liminal_libs import capture
from liminal_libs.ebpf import linux as ebpf_linux
from liminal_libs.ebpf import watch as ebpf_watch
from liminal_libs.ebpf import windows as ebpf_windows
from liminal_libs.ebpf.capabilities import CAPABILITIES, by_area, rows
from liminal_libs.machines import etw
from liminal_libs.sources.apis import dead_links, is_https, problems

import plugin_platform_ebpf as plugin
from plugin_platform_ebpf import apis as cards


def _norm(src: str) -> str:
    """Library source with the quotes, commas and brackets dropped and the whitespace collapsed, so a command the
    library builds as separate string arguments (["bpftool", "prog", "show"]) reads as one phrase ("prog show")."""
    return re.sub(r"\s+", " ", re.sub(r"""["',\[\]]""", " ", src))


LINUX_SRC = _norm(inspect.getsource(ebpf_linux))
WATCH_SRC = _norm(inspect.getsource(ebpf_watch))
WIN_SRC = inspect.getsource(ebpf_windows)
ETW_SRC = inspect.getsource(etw)


def test_the_cards_are_sound_and_each_says_where_its_documentation_is():
    assert problems(cards.APIS) == []
    assert [a.name for a in cards.APIS] == [
        "bpftool", "bpftrace", "The Linux kernel — bpf(2) and BTF", "libbpf", "eBPF for Windows",
        "Npcap (packet capture)", "Event Tracing for Windows (ETW)"]
    # the eBPF and ETW cards were read on the capability-research day; the Npcap card keeps the firewall plugin's day
    assert all(a.verified == "2026-11-14" for a in cards.APIS if a is not cards.NPCAP)
    assert cards.NPCAP.verified == "2026-11-15"
    assert all(a.docs.startswith("https://") for a in cards.APIS)  # each names its documentation (problems enforces it)
    assert not any(c.costs for a in cards.APIS for c in a.calls)  # nothing here costs money


def test_every_capability_row_has_a_source_and_every_source_is_a_real_row():
    caps = {(c.area, c.item) for c in CAPABILITIES}
    assert set(cards.SOURCES) == caps  # a bijection: no row without a source, no source without a row
    assert len(cards.SOURCES) == len(CAPABILITIES) == 65
    assert all(is_https(url) for url in cards.SOURCES.values())  # the library holds no host; every source lives here
    # the Compare tab passes SOURCES to capabilities.by_area, which puts each row's source beside it
    assert all(row["source"] for row in rows(cards.SOURCES))
    for group in by_area(cards.SOURCES):
        assert all(row["source"] for row in group["rows"])


# -- the cards' "used" calls are the ones the library's code makes -----------------------------------------------------
# bpftool: the object-and-verb phrase each used call carries, and where it reads in ebpf/linux.py.
BPFTOOL_USED = {
    "bpftool -j version": "bpftool -j version",
    "bpftool -j prog show": "prog show",
    "bpftool -j map show": "map show",
    "bpftool -j link show": "link show",
    "bpftool -j prog show id <id>": "prog show id",
    "bpftool -j map dump id <id>": "map dump id",
    "bpftool prog load <path> <pin> [type T] [pinmaps DIR]": "prog load",
    "bpftool net attach <kind> <prog> dev <dev> [overwrite]": "net attach",
    "bpftool prog attach <prog> <kind> [id <map>]": "prog attach",
    "bpftool cgroup attach <cgroup> <kind> <prog> [multi|override]": "cgroup attach",
    "bpftool link detach id <id>": "link detach",
    "bpftool net detach <kind> dev <dev>": "net detach",
    "bpftool prog detach <prog> <kind>": "prog detach",
    "bpftool cgroup detach <cgroup> <kind> <prog>": "cgroup detach",
    "rm -f <pin>": "rm -f",
}


def test_the_bpftool_card_names_the_commands_the_library_runs():
    assert {c.name for c in cards.BPFTOOL.used} == set(BPFTOOL_USED)  # the used calls are exactly these
    for name, phrase in BPFTOOL_USED.items():
        assert phrase in LINUX_SRC, name  # and each is a command LinuxRuntime builds and runs
    # the unused calls are the parts of bpftool the plugin does not reach (more of the API than it uses)
    assert {c.name for c in cards.BPFTOOL.calls if not c.used} == {
        "bpftool feature probe", "bpftool net show", "bpftool prog dump xlated id <id>"}


def test_the_bpftrace_card_names_the_watch_command_and_the_version_read():
    assert {c.name for c in cards.BPFTRACE.used} == {
        "sudo -n bpftrace -f json -e <script> [pid]", "bpftrace -V", "sudo -n bpftrace -V"}
    assert "sudo -n bpftrace -f json -e" in WATCH_SRC  # how BpftraceWatch spawns bpftrace
    assert "bpftrace -V" in LINUX_SRC  # how LinuxRuntime reads the version
    assert plugin.WATCH_PROBE == ("sudo", "-n", "bpftrace", "-V")  # the plugin's own: the watch's command, its version


def test_the_kernel_card_names_the_proc_and_sys_reads_of_the_status():
    assert {c.name for c in cards.KERNEL.used} == {
        "uname -r", "cat /proc/sys/kernel/unprivileged_bpf_disabled", "cat /proc/sys/net/core/bpf_jit_enable",
        "ls /sys/kernel/btf/vmlinux", "cat /proc/mounts", "grep -w -F -e <function> /proc/kallsyms"}
    for token in ("uname -r", "/proc/sys/kernel/unprivileged_bpf_disabled", "/proc/sys/net/core/bpf_jit_enable",
                  "/sys/kernel/btf/vmlinux", "/proc/mounts"):
        assert token in LINUX_SRC, token
    # the plugin's own read: the functions the watch scripts' kprobes need, looked for as the platform's user
    assert plugin.KALLSYMS == "/proc/kallsyms" and "grep -w -F " in inspect.getsource(plugin.EbpfPlugin._kernel_lacks)


# what holds of one machine alone: said by api_facts, from what was read, never on a card (the platform draws every
# card on every machine: on Windows, on a Linux of its own and inside WSL)
ONE_MACHINES = ("this PC", "this account", "build 26300", "1.88", "Wireshark 4.6.9", "blocked here",
                "read from this machine", "is installed here", "not installed on")


def card_words(api) -> list[str]:
    return [api.about, api.base, api.version, api.auth, api.limits, api.costs,
            *(x for a in api.areas for x in (a.about, a.covered)), *(x for c in api.calls for x in (c.about, c.used))]


def test_the_cards_say_what_holds_on_any_machine_and_nothing_of_one_machines_own():
    for api in cards.APIS:
        for words in card_words(api):
            assert not any(phrase in (words or "") for phrase in ONE_MACHINES), (api.name, words)
    # this machine's own state is api_facts', from what was read: the cards point at it
    assert "the facts beside say what it read" in cards.EBPF_WINDOWS.about
    assert "AdminOnly 0" in cards.NPCAP.auth and "where Npcap was installed without" in cards.NPCAP.auth


def test_the_kernel_card_says_its_column_is_linux_in_general_and_the_here_column_this_kernels():
    assert "The comparison's Linux column is Linux in general, as researched on 2026-11-14; its Here column is this " \
           "kernel's, read from these files." in cards.KERNEL.about
    assert "this kernel's;" not in cards.KERNEL.about  # never: the Linux column is this kernel's
    assert cards.KERNEL.version.startswith("the kernel's own eBPF: this machine's release read with uname -r")
    assert "on 2026-11-14: mainline 7.4-rc2" in cards.KERNEL.version


def test_the_windows_card_names_the_reads_the_library_makes():
    used = {c.name for c in cards.EBPF_WINDOWS.used}
    assert used == {
        "Get-Service eBPFCore / NetEbpfExt / eBPFSvc",
        "(Get-Item EbpfApi.dll).VersionInfo.ProductVersion",
        "netsh ebpf show programs | maps | links",
        "netsh ebpf show programs id=<id> level=verbose",
        "Confirm-SecureBootUEFI",
        r"HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State UEFISecureBootEnabled",
        "Get-CimInstance Win32_DeviceGuard",
        r"HKLM:\SYSTEM\CurrentControlSet\Control SystemStartOptions",
        "bcdedit /enum {current}"}
    for token in ("Get-Service", "EbpfApi.dll", "netsh ebpf show programs", "level=verbose", "Confirm-SecureBootUEFI",
                  "UEFISecureBootEnabled", "Win32_DeviceGuard", "SystemStartOptions", "bcdedit"):
        assert token in WIN_SRC, token


def test_the_npcap_card_names_every_libpcap_call_the_capture_makes_on_windows():
    made = set(re.findall(r"lib\.(pcap_\w+)\(", inspect.getsource(capture.PcapSource)))
    # every Windows libpcap call (pcap_setnonblock and pcap_get_selectable_fd are Linux's alone)
    assert {c.name for c in cards.NPCAP.used if c.name.startswith("pcap_")} == made - {
        "pcap_setnonblock", "pcap_get_selectable_fd"}
    # and before any of them, Npcap's option for administrators only, read where Npcap keeps it
    assert cards.NPCAP_ADMIN_ONLY == "HKLM\\" + capture.NPCAP_OPTIONS + "\\AdminOnly"
    [option] = [c for c in cards.NPCAP.used if not c.name.startswith("pcap_")]
    assert option.name == cards.NPCAP_ADMIN_ONLY and "IsUserAnAdmin" in option.used and not option.writes
    assert 'winreg.QueryValueEx(key, "AdminOnly")' in inspect.getsource(capture.npcap_admin_only)
    assert capture.NPCAP.replace("\\", "/").endswith("/System32/Npcap")
    assert r"%SystemRoot%\System32\Npcap" in cards.NPCAP.base


def test_the_etw_card_names_the_trace_control_and_decode_calls():
    used = {c.name for c in cards.ETW.used}
    assert used == {
        "StartTraceW", "EnableTraceEx2", "OpenTraceW", "ProcessTrace", "ControlTraceW", "QueryAllTracesW",
        "TdhGetEventInformation / TdhGetProperty"}
    for token in ("StartTraceW", "EnableTraceEx2", "OpenTraceW", "ProcessTrace", "ControlTraceW", "QueryAllTracesW",
                  "TdhGetEventInformation", "TdhGetProperty"):
        assert token in ETW_SRC, token


@pytest.mark.skipif(os.environ.get("LIMINAL_VENDOR_PAGES") != "1",
                    reason="reaches the makers' pages: LIMINAL_VENDOR_PAGES=1")
def test_the_cards_pages_answer():
    assert dead_links(cards.APIS) == []
