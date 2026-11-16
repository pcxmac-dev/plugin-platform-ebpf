"""What the eBPF plugin attaches to (plugin API 2.2, liminal_libs.sources.apis; the user, 2026-11-11: "each plugin
should reflect the the API its attached to, and present links that provide documentation ... it should also expose
more of what the API is about"): on Linux, the kernel's own eBPF through bpftool and a few /proc and /sys files, and
bpftrace for the watch; on Windows, eBPF for Windows (a pre-release, test-signed download) read through PowerShell,
and, since that runtime cannot load here, Npcap and ETW, which the Windows watch uses instead. libbpf is named as the
yardstick the comparison measures eBPF for Windows against. Every address was read from the maker's own pages on
2026-11-14, when the capability research was done (`VERIFIED`); the Npcap card keeps the day the firewall plugin read
it (2026-11-15, `VERIFIED_NPCAP`). The cards say what holds on any machine (the platform draws every card, on
Windows, on Linux and inside WSL alike): this machine's own state (what is installed, whether it can load, this
account's rights) is what the last status and watch learned, said by the plugin's api_facts beside them.

The comparison's rows live in the library (liminal_libs.ebpf.capabilities): it holds no outside host, so the source
page for each of its 65 rows lives here, in `SOURCES`, keyed by the row's (area, item). The Compare tab passes SOURCES
to capabilities.by_area, which puts each row's source beside it (the user, 2026-11-14: "we need an ebpf api plugin,
that shows the difference between windows and linux capabilities as well as basic functionality"). `APIS` is the tuple
of cards, last in the module.
"""
from __future__ import annotations

from liminal_libs.sources.apis import Api, Area, Call, Link

VERIFIED = "2026-11-14"  # the eBPF capability research: every address on the eBPF and ETW cards read this day
VERIFIED_NPCAP = "2026-11-15"  # the Npcap card, as the firewall-windows plugin read it (its World Wide Web tab)

# -- the maker's pages, as prefixes (every outside host the plugin names lives here) ----------------------------------
KDOC = "https://docs.kernel.org/"
PROGRAM_TYPES = KDOC + "bpf/libbpf/program_types.html"  # the Linux program and attach types, one page
MAN7 = "https://man7.org/linux/man-pages/man7/"
RFC9669 = "https://www.rfc-editor.org/rfc/rfc9669.html"  # the BPF instruction set, standardised
EBPF_IO = "https://ebpf.io/what-is-ebpf/"
LIBBPF_DOCS = "https://libbpf.readthedocs.io/en/latest/"

BT = "https://github.com/libbpf/bpftool"  # bpftool's source
BTD = BT + "/blob/main/docs/"  # its man pages (reStructuredText), by object
BPFTRACE_REPO = "https://github.com/bpftrace/bpftrace"
BPFTRACE_MAN = BPFTRACE_REPO + "/blob/master/man/adoc/bpftrace.adoc"  # the bpftrace manual
BPFTRACE_TUT = BPFTRACE_REPO + "/blob/master/docs/tutorial_one_liners.md"
LIBBPF_REPO = "https://github.com/libbpf/libbpf"

MSE_REPO = "https://github.com/microsoft/ebpf-for-windows"
MSE = MSE_REPO + "/blob/main/docs/"  # its documentation files
DOX = "https://microsoft.github.io/ebpf-for-windows/"  # the Doxygen reference (the headers)
XDPW_REPO = "https://github.com/microsoft/xdp-for-windows"
XDPW = XDPW_REPO + "/blob/main/docs/"
NTOS_REPO = "https://github.com/microsoft/ntosebpfext"
NTOS = NTOS_REPO + "/blob/main/docs/"
PREVAIL = "https://github.com/vbpf/prevail"  # the user-mode verifier eBPF for Windows runs

LEARN = "https://learn.microsoft.com/en-us/"
HVCI_DOC = LEARN + "windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity"
TESTSIGNING_DOC = LEARN + "windows-hardware/drivers/install/the-testsigning-boot-configuration-option"
EVNTRACE = LEARN + "windows/win32/api/evntrace/"  # the trace-control calls (advapi32)
TDH = LEARN + "windows/win32/api/tdh/"  # the property decode
ETW_DOC = LEARN + "windows/win32/etw/"

# Npcap, where the library's capture keeps its install option (read, never written): the model plugin's own constant.
NPCAP_SITE = "https://npcap.com/"
NPCAP_GUIDE = NPCAP_SITE + "guide/"
NPCAP_ADMIN_ONLY = r"HKLM\SYSTEM\CurrentControlSet\Services\npcap\Parameters\AdminOnly"
PCAP = "https://www.tcpdump.org/manpages/"

# ----------------------------------------------------------------------------------------------------------------------
BPFTOOL = Api(
    name="bpftool",
    maker="the libbpf / bpftool project",
    about=("The Linux kernel's own tool for eBPF: it shows and manages programs, maps, links, cgroup and network "
           "attachments. The plugin reads this machine's eBPF state through `bpftool -j` (JSON) as the platform's user "
           "where it can, and through sudo -n where root is needed, and builds the load, attach, detach and unload "
           "commands the Functions tab confirms before they run; it never asks for a password."),
    kind="command",
    base="bpftool -j <object> <command>, as the platform's user or through sudo -n (liminal_libs.machines.linux.Shell)",
    version="bpftool 7 (7.8.1, 2026-10-20, is the newest); the kernel's own tool, versioned alongside libbpf",
    auth=("reading the versions needs no root; listing, showing, dumping, loading, attaching, detaching and unloading "
          "run as root through sudo -n, never a password asked (a refusal says how to grant the right)"),
    limits="",
    costs="",
    links=(
        Link("bpftool", BT, "source"),
        Link("bpftool-prog(8)", BTD + "bpftool-prog.rst", "reference"),
        Link("bpftool-map(8)", BTD + "bpftool-map.rst", "reference"),
        Link("bpftool-net(8)", BTD + "bpftool-net.rst", "reference"),
        Link("bpftool-cgroup(8)", BTD + "bpftool-cgroup.rst", "reference"),
        Link("bpftool-link(8)", BTD + "bpftool-link.rst", "reference"),
        Link("bpftool-feature(8)", BTD + "bpftool-feature.rst", "reference"),
        Link("bpftool's releases", BT + "/releases", "changelog"),
    ),
    areas=(
        Area("Programs", "the loaded programs, shown, loaded, attached and detached", BTD + "bpftool-prog.rst",
             covered="listed (prog show), one shown (prog show id), loaded (prog load) and attached or detached"),
        Area("Maps", "the maps, shown and dumped", BTD + "bpftool-map.rst",
             covered="listed (map show) and the first entries dumped (map dump id)"),
        Area("Links", "the links (attachments), shown and detached", BTD + "bpftool-link.rst",
             covered="listed (link show) and detached by id (link detach)"),
        Area("Network attachments", "XDP and tcx on a device", BTD + "bpftool-net.rst",
             covered="attached (net attach) and detached (net detach)"),
        Area("cgroup attachments", "a program on a cgroup v2 hook", BTD + "bpftool-cgroup.rst",
             covered="attached (cgroup attach) and detached (cgroup detach)"),
        Area("Feature probe", "what the kernel supports (bpftool feature probe)", BTD + "bpftool-feature.rst"),
        Area("Skeletons and BTF", "gen skeleton, btf dump", BTD + "bpftool-gen.rst"),
    ),
    calls=(
        Call("bpftool -j version", "the bpftool and libbpf versions and the built-in features", "Programs",
             used="the Linux status", docs=BTD + "bpftool-prog.rst"),
        Call("bpftool -j prog show", "every loaded program", "Programs", used="the programs listing",
             docs=BTD + "bpftool-prog.rst"),
        Call("bpftool -j map show", "every map", "Maps", used="the maps listing", docs=BTD + "bpftool-map.rst"),
        Call("bpftool -j link show", "every link", "Links", used="the links listing", docs=BTD + "bpftool-link.rst"),
        Call("bpftool -j prog show id <id>", "one program's detail", "Programs", used="Show a program's info",
             docs=BTD + "bpftool-prog.rst"),
        Call("bpftool -j map dump id <id>", "a map's first entries", "Maps", used="Dump a map (its first entries)",
             docs=BTD + "bpftool-map.rst"),
        Call("bpftool prog load <path> <pin> [type T] [pinmaps DIR]", "a pre-built program loaded and pinned",
             "Programs", used="Load… (asked twice)", docs=BTD + "bpftool-prog.rst", writes=True),
        Call("bpftool net attach <kind> <prog> dev <dev> [overwrite]", "a program attached to a device (XDP, tcx)",
             "Network attachments", used="Attach… (an XDP overwrite asked twice)", docs=BTD + "bpftool-net.rst",
             writes=True),
        Call("bpftool prog attach <prog> <kind> [id <map>]", "a sk_msg / sk_skb / flow_dissector attach",
             "Programs", used="Attach…", docs=BTD + "bpftool-prog.rst", writes=True),
        Call("bpftool cgroup attach <cgroup> <kind> <prog> [multi|override]", "a program on a cgroup v2 hook",
             "cgroup attachments", used="Attach… (a cgroup attach asked twice)", docs=BTD + "bpftool-cgroup.rst",
             writes=True),
        Call("bpftool link detach id <id>", "a link-based attachment detached", "Links", used="Detach…",
             docs=BTD + "bpftool-link.rst", writes=True),
        Call("bpftool net detach <kind> dev <dev>", "an XDP or tcx attachment detached", "Network attachments",
             used="Detach…", docs=BTD + "bpftool-net.rst", writes=True),
        Call("bpftool prog detach <prog> <kind>", "a prog-attach detached", "Programs", used="Detach…",
             docs=BTD + "bpftool-prog.rst", writes=True),
        Call("bpftool cgroup detach <cgroup> <kind> <prog>", "a cgroup attachment detached", "cgroup attachments",
             used="Detach…", docs=BTD + "bpftool-cgroup.rst", writes=True),
        Call("rm -f <pin>", "a program unloaded by removing its pin (its last reference)", "Programs",
             used="Unload… (a pin that is not Liminal's asked twice)", docs=BTD + "bpftool-prog.rst", writes=True),
        Call("bpftool feature probe", "what the kernel supports", "Feature probe", docs=BTD + "bpftool-feature.rst"),
        Call("bpftool net show", "every network attachment", "Network attachments", docs=BTD + "bpftool-net.rst"),
        Call("bpftool prog dump xlated id <id>", "a program's instructions", "Programs",
             docs=BTD + "bpftool-prog.rst"),
    ),
    verified=VERIFIED,
)

BPFTRACE = Api(
    name="bpftrace",
    maker="the bpftrace project",
    about=("A high-level tracer that compiles small scripts to eBPF. The watch service runs it, as root through "
           "sudo -n, with the library's scripts (ebpf/scripts/ net.bt, process.bt, file.bt), reading its JSON output "
           "into events while a Filter tab or trapdoor is watching; it loads nothing that outlives the watch, and "
           "nothing runs once no one is reading. The plugin also reads its version for the Linux status."),
    kind="command",
    base="sudo -n bpftrace -f json -e <script> [pid] (ebpf.watch.BpftraceWatch); bpftrace -V reads the version",
    version="bpftrace 0.20+ (0.20.2 in Ubuntu 24.04's package); the scripts use its JSON output and its struct access",
    auth="root through sudo -n (never a password); the version (bpftrace -V) needs none",
    limits=("a watch stops itself about 20 s after the last read, and on the plugin's detach, so no bpftrace runs "
            "unwatched; the scripts are low-rate by construction (a line per connection change, not per packet)"),
    costs="",
    links=(
        Link("bpftrace", BPFTRACE_REPO, "source"),
        Link("The bpftrace manual", BPFTRACE_MAN, "reference"),
        Link("bpftrace one-liner tutorial", BPFTRACE_TUT, "guide"),
        Link("bpftrace's tools", BPFTRACE_REPO + "/blob/master/tools/README.md", "guide"),
        Link("bpftrace's releases", BPFTRACE_REPO + "/releases", "changelog"),
    ),
    areas=(
        Area("Scripts and probes", "tracepoints, kprobes and the builtins the scripts use", BPFTRACE_MAN,
             covered="net.bt, process.bt and file.bt: TCP, UDP, exec, exit and file opens, low-rate"),
        Area("JSON output", "one JSON object per event (-f json), and lost-event lines", BPFTRACE_MAN,
             covered="read line by line into events; its lost-events count surfaced"),
        Area("The version", "bpftrace -V", BPFTRACE_MAN, covered="read for the Linux status"),
        Area("Launch under watch", "run a child and trace it (-c)", BPFTRACE_MAN),
        Area("The language", "maps, aggregations and the full probe set", BPFTRACE_TUT),
    ),
    calls=(
        Call("sudo -n bpftrace -f json -e <script> [pid]", "the watch's scripts run, their JSON read into events",
             "Scripts and probes", used="the net, process and file watch (the Filter tabs and trapdoor)",
             docs=BPFTRACE_MAN, writes=True),
        Call("bpftrace -V", "the installed version", "The version", used="the Linux status", docs=BPFTRACE_MAN),
        Call("sudo -n bpftrace -V", "the version, through sudo -n as the watch runs bpftrace", "The version",
             used="whether the watch can run here: sudo lets it, and finds bpftrace on its path", docs=BPFTRACE_MAN),
        Call("bpftrace -l", "the probes the running kernel offers", "Scripts and probes", docs=BPFTRACE_MAN),
    ),
    verified=VERIFIED,
)

KERNEL = Api(
    name="The Linux kernel — bpf(2) and BTF",
    maker="the Linux kernel",
    about=("On Linux, eBPF is part of the kernel: the bpf() syscall, the in-kernel verifier and JIT, the program and "
           "map types, the helpers, BTF and CO-RE. The plugin reads the kernel's eBPF state from its own files — the "
           "kernel release, the unprivileged-BPF and JIT sysctls, kernel BTF and the BPF filesystem's mounts — none "
           "of which needs root, and looks up in /proc/kallsyms the functions the watch scripts' kprobes attach to. "
           f"The comparison's Linux column is Linux in general, as researched on {VERIFIED}; its Here column is this "
           "kernel's, read from these files."),
    kind="kernel",
    base=("/proc and /sys (uname -r, /proc/sys/kernel, /proc/sys/net/core, /sys/kernel/btf/vmlinux, /proc/mounts, "
          "/proc/kallsyms)"),
    version=("the kernel's own eBPF: this machine's release read with uname -r (the Release fact); the release lines "
             f"on {VERIFIED}: mainline 7.4-rc2, stable 7.3.4, longterm 6.18 and 6.12"),
    auth=("the kernel release, the two sysctls, the BTF check, the mounts and /proc/kallsyms are world-readable: no "
          "root needed"),
    limits="",
    costs="",
    links=(
        Link("BPF documentation", KDOC + "bpf/index.html", "docs"),
        Link("Program types and ELF sections (libbpf)", PROGRAM_TYPES, "reference"),
        Link("BPF maps", KDOC + "bpf/maps.html", "reference"),
        Link("BPF Type Format (BTF)", KDOC + "bpf/btf.html", "reference"),
        Link("The eBPF verifier", KDOC + "bpf/verifier.html", "reference"),
        Link("BPF ring buffer", KDOC + "bpf/ringbuf.html", "reference"),
        Link("BPF program signing", KDOC + "bpf/signing.html", "reference"),
        Link("BPF LSM programs", KDOC + "bpf/prog_lsm.html", "reference"),
        Link("BPF kernel functions (kfuncs)", KDOC + "bpf/kfuncs.html", "reference"),
        Link("bpf-helpers(7)", MAN7 + "bpf-helpers.7.html", "reference"),
        Link("capabilities(7): CAP_BPF and CAP_PERFMON", MAN7 + "capabilities.7.html", "reference"),
        Link("Kernel sysctls (unprivileged_bpf_disabled)", KDOC + "admin-guide/sysctl/kernel.html", "reference"),
        Link("Net sysctls (bpf_jit_enable)", KDOC + "admin-guide/sysctl/net.html", "reference"),
        Link("Kernel Probes (kprobes)", KDOC + "trace/kprobes.html", "reference"),
        Link("The BPF instruction set (RFC 9669)", RFC9669, "spec"),
        Link("What is eBPF?", EBPF_IO, "guide"),
    ),
    areas=(
        Area("The kernel release", "uname -r, the runtime's version (eBPF is the kernel's)", KDOC + "bpf/index.html",
             covered="read for the Linux status and the comparison's heading"),
        Area("Privilege sysctls", "unprivileged_bpf_disabled, bpf_jit_enable", KDOC + "admin-guide/sysctl/kernel.html",
             covered="both read (world-readable), for the status and the Here column"),
        Area("Kernel BTF", "/sys/kernel/btf/vmlinux, needed for CO-RE and fentry/LSM", KDOC + "bpf/btf.html",
             covered="its presence read, for the status and the Here column"),
        Area("The BPF filesystem", "where pins live (/sys/fs/bpf), from /proc/mounts", KDOC + "bpf/maps.html",
             covered="its mount points read, for the status and the Here column"),
        Area("The kernel's functions", "/proc/kallsyms: every kernel function, a kprobe's place to attach",
             KDOC + "trace/kprobes.html",
             covered=("the functions the watch scripts' kprobes need, looked for: one missing keeps bpftrace from "
                      "starting")),
        Area("The bpf() syscall", "every eBPF operation goes through it", MAN7 + "bpf-helpers.7.html"),
        Area("The verifier", "it checks every program at load", KDOC + "bpf/verifier.html"),
        Area("Helpers and kfuncs", "the in-kernel functions a program may call", MAN7 + "bpf-helpers.7.html"),
    ),
    calls=(
        Call("uname -r", "the kernel release", "The kernel release", used="the Linux status (the version)"),
        Call("cat /proc/sys/kernel/unprivileged_bpf_disabled", "whether unprivileged BPF is off", "Privilege sysctls",
             used="the Linux status", docs=KDOC + "admin-guide/sysctl/kernel.html"),
        Call("cat /proc/sys/net/core/bpf_jit_enable", "the JIT setting", "Privilege sysctls",
             used="the Linux status", docs=KDOC + "admin-guide/sysctl/net.html"),
        Call("ls /sys/kernel/btf/vmlinux", "whether kernel BTF is present", "Kernel BTF",
             used="the Linux status", docs=KDOC + "bpf/btf.html"),
        Call("cat /proc/mounts", "the BPF filesystem's mount points", "The BPF filesystem",
             used="the Linux status", docs=KDOC + "bpf/maps.html"),
        Call("grep -w -F -e <function> /proc/kallsyms", "whether the kernel has a function", "The kernel's functions",
             used="the watch's row: the functions the watch scripts' kprobes attach to",
             docs=KDOC + "trace/kprobes.html"),
        Call("bpf(2)", "load, attach and query programs and maps", "The bpf() syscall",
             docs=MAN7 + "bpf-helpers.7.html"),
    ),
    verified=VERIFIED,
)

LIBBPF = Api(
    name="libbpf",
    maker="the libbpf project",
    about=("The reference user-space loader for eBPF: it opens an ELF object, loads its programs and maps, attaches "
           "them, and relocates them across kernel versions with BTF and CO-RE. The plugin does not call it directly "
           "(it drives bpftool, which is built on libbpf); it is named here because libbpf's API is the yardstick the "
           "comparison measures eBPF for Windows' EbpfApi.dll against — source-compatible, not ABI-compatible."),
    kind="sdk",
    base="libbpf (the C library); the plugin reaches it only through bpftool",
    version="libbpf v1.8.0 (2026-10-05) is the newest; the comparison is against its documented API",
    auth="",
    limits="",
    costs="",
    links=(
        Link("libbpf API reference", LIBBPF_DOCS, "reference"),
        Link("libbpf overview (CO-RE, skeletons, lifecycle)", KDOC + "bpf/libbpf/libbpf_overview.html", "guide"),
        Link("libbpf", LIBBPF_REPO, "source"),
        Link("libbpf's releases", LIBBPF_REPO + "/releases", "changelog"),
    ),
    areas=(
        Area("Object lifecycle", "bpf_object__open, load, close", KDOC + "bpf/libbpf/libbpf_overview.html"),
        Area("Attaching programs", "bpf_program__attach_* and links", KDOC + "bpf/libbpf/libbpf_overview.html"),
        Area("CO-RE and skeletons", "relocations and generated loaders", KDOC + "bpf/libbpf/libbpf_overview.html"),
        Area("Maps and events", "bpf_map__*, ring_buffer__* and perf_buffer__*", LIBBPF_DOCS),
    ),
    calls=(
        Call("bpf_object__open / load", "an ELF object opened and loaded", "Object lifecycle", docs=LIBBPF_DOCS),
        Call("bpf_program__attach", "a program attached, a link returned", "Attaching programs", docs=LIBBPF_DOCS),
        Call("ring_buffer__new / poll", "ring-buffer events consumed", "Maps and events", docs=LIBBPF_DOCS),
    ),
    verified=VERIFIED,
)

EBPF_WINDOWS = Api(
    name="eBPF for Windows",
    maker="Microsoft",
    about=("A separate, pre-release download (an MSI), not part of Windows: the eBPFCore and NetEbpfExt kernel "
           "drivers, the eBPFSvc service, EbpfApi.dll (a libbpf subset), a bpftool port and the netsh ebpf helper. "
           "Every public "
           "build is test-signed, so on a Secure Boot machine it needs test-signing mode. The plugin reads the three "
           "services, the installed version and the netsh listings, and reads Secure Boot, memory integrity and test "
           "signing to say whether anything can load on the machine it runs on (the facts beside say what it read)."),
    kind="system",
    base=("Get-Service, the EbpfApi.dll version, netsh ebpf show *, Confirm-SecureBootUEFI or the registry, "
          "Win32_DeviceGuard and bcdedit (liminal_libs.machines.windows.PowerShell, windowless)"),
    version=("eBPF for Windows v1.7.0 (2026-10-16) is the newest release; a v1.7.1 tag and NuGet 1.7.1 (2026-11-10) "
             "without a release page; main is at 1.8.0"),
    auth=("the service states, the EbpfApi.dll version, the Secure Boot registry fallback and memory integrity need no "
          "administrator; netsh ebpf show * needs one (the eBPFCore device's access control), as do "
          "Confirm-SecureBootUEFI and bcdedit; the plugin never elevates for them, and says what it could not read"),
    limits="",
    costs="",
    links=(
        Link("eBPF for Windows", MSE_REPO, "source"),
        Link("Getting started", MSE + "GettingStarted.md", "guide"),
        Link("Installing eBPF for Windows", MSE + "InstallEbpf.md", "guide"),
        Link("API reference (Doxygen)", DOX, "reference"),
        Link("Program, attach and map types (ebpf_structs.h)", DOX + "ebpf__structs_8h.html", "reference"),
        Link("Network hooks and their helpers (ebpf_nethooks.h)", DOX + "ebpf__nethooks_8h.html", "reference"),
        Link("bpf() compatibility with the Linux ABI", MSE + "BpfSyscallCompatibility.md", "reference"),
        Link("Native code generation (bpf2c, signed .sys)", MSE + "NativeCodeGeneration.md", "reference"),
        Link("The release process (test signing)", MSE + "ReleaseProcess.md", "reference"),
        Link("SOCK_OPS hook (WFP flow established/deleted)", MSE + "sock_ops_hook.md", "reference"),
        Link("CONNECT_AUTHORIZATION attach types", MSE + "ConnectAuthorizationAttachTypes.md", "reference"),
        Link("Pin paths", MSE + "PinPaths.md", "reference"),
        Link("Ring buffer", MSE + "RingBuffer.md", "reference"),
        Link("Perf event array", MSE + "PerfEventArray.md", "reference"),
        Link("Releases", MSE_REPO + "/releases", "changelog"),
        Link("XDP for Windows", XDPW_REPO, "source"),
        Link("ntosebpfext (process and netevent hooks)", NTOS_REPO, "source"),
        Link("The PREVAIL verifier", PREVAIL, "source"),
        Link("Loading test-signed code (TESTSIGNING)", TESTSIGNING_DOC, "guide"),
        Link("Memory integrity (HVCI) and Win32_DeviceGuard", HVCI_DOC, "guide"),
    ),
    areas=(
        Area("The services and version", "eBPFCore, NetEbpfExt, eBPFSvc, and EbpfApi.dll's version",
             MSE + "InstallEbpf.md", covered="all three read (Get-Service) and the version read, for the status"),
        Area("Listing (netsh ebpf)", "programs, maps and links as text tables", MSE + "GettingStarted.md",
             covered="read when the core service is present (an administrator is needed); a note otherwise"),
        Area("Can it load here", "Secure Boot, memory integrity and test signing", TESTSIGNING_DOC,
             covered="all three read, and the verdict said for the Main tab"),
        Area("libbpf compatibility", "EbpfApi.dll's documented libbpf subset", MSE + "BpfSyscallCompatibility.md"),
        Area("Program types and hooks", "XDP, sock_addr, sock_ops, bind, netevent, process",
             DOX + "ebpf__structs_8h.html"),
        Area("Loading and signing", "native .sys through bpf2c, the JIT, the eBPF store",
             MSE + "NativeCodeGeneration.md"),
        Area("Pinning", "pins in the kernel namespace (BPF:\\...)", MSE + "PinPaths.md"),
        Area("Events to user space", "ring buffer and perf event array", MSE + "RingBuffer.md"),
    ),
    calls=(
        Call("Get-Service eBPFCore / NetEbpfExt / eBPFSvc", "the three services' presence and state",
             "The services and version", used="the Windows status", docs=MSE + "InstallEbpf.md"),
        Call("(Get-Item EbpfApi.dll).VersionInfo.ProductVersion", "the installed version", "The services and version",
             used="the Windows status", docs=MSE + "InstallEbpf.md"),
        Call("netsh ebpf show programs | maps | links", "the loaded programs, maps and links", "Listing (netsh ebpf)",
             used="the listings, when the core service is present", docs=MSE + "GettingStarted.md"),
        Call("netsh ebpf show programs id=<id> level=verbose", "one program's detail", "Listing (netsh ebpf)",
             used="Show a program's info", docs=MSE + "GettingStarted.md"),
        Call("Confirm-SecureBootUEFI", "whether Secure Boot is on (else the registry)", "Can it load here",
             used="the Main tab's verdict", docs=TESTSIGNING_DOC),
        Call(r"HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State UEFISecureBootEnabled",
             "Secure Boot from the registry, when the firmware query needs an administrator", "Can it load here",
             used="the Main tab's verdict (the fallback)", docs=TESTSIGNING_DOC),
        Call("Get-CimInstance Win32_DeviceGuard", "memory integrity (SecurityServicesRunning contains 2)",
             "Can it load here", used="the Main tab's verdict", docs=HVCI_DOC),
        Call("bcdedit /enum {current}", "test signing on or off", "Can it load here",
             used="the Main tab's verdict (needs an administrator to read)", docs=TESTSIGNING_DOC),
        Call("bpf_object__load / bpf_program__attach (EbpfApi.dll)", "a program loaded and attached in code",
             "libbpf compatibility", docs=MSE + "BpfSyscallCompatibility.md"),
        Call("netsh ebpf add program filename=<f>", "a native .sys loaded and attached", "Loading and signing",
             docs=MSE + "NativeCodeGeneration.md", writes=True),
    ),
    verified=VERIFIED,
)

# -- Npcap: from plugin-platform-firewall-windows's card (the library's capture is the same), the about and limits
# adjusted for the Windows watch (the net kind), which is what this plugin uses it for, and nothing of one PC's own
# install said: that card is drawn on Windows alone, this one on Linux and inside WSL too (api_facts says this one's) --
NPCAP = Api(
    name="Npcap (packet capture)",
    maker="Nmap Software",
    about=("A packet capture driver and library for Windows from the Nmap Project, with libpcap's API (wpcap.dll): an "
           "adapter opened, a filter compiled and set, each packet read as it arrives at the adapter, before Windows "
           "Firewall decides. The library calls wpcap.dll by ctypes, no package between. The Windows watch "
           "(NpcapEtwWatch) reads packets with it for the net kind, joins them into flows and names each flow's "
           "process from an ETW record; it reads only while a watch is reading, keeps no packet, and stops when the "
           "watch does."),
    kind="sdk",
    base=r"wpcap.dll in %SystemRoot%\System32\Npcap, through ctypes (liminal-libs capture.py)",
    version="Npcap 1.90, of 2026-10-21, is the newest; its wpcap.dll carries libpcap's API",
    auth=("any user, where Npcap was installed without \"Restrict Npcap driver's access to Administrators only\" "
          "(AdminOnly 0 in the npcap service's Parameters): watching then needs no administrator and no UAC. Installed "
          "for administrators only, Npcap has its NpcapHelper ask for elevation (a UAC prompt) as soon as a process "
          "that is no administrator lists or opens an adapter; so that option is read from the registry first (read "
          "access alone, nothing started), and then a platform that is no administrator asks Npcap nothing, not even "
          "loading it: the watch says to install Npcap again with the option unticked, or to run the platform as an "
          "administrator, and never asks for an administrator or a password itself. A platform run as an administrator "
          "watches as it is, with no prompt"),
    limits=("a net watch reads while a Filter tab or trapdoor is reading, and stops itself about 20 s after the last "
            "read and on the plugin's detach; the headers alone are kept of each packet, folded into flows (not kept), "
            "and the packet queue and the flow tables are bounded, so a flood drops the oldest and is counted"),
    costs=("Npcap's free license covers five computers (virtual machines and containers count among them). Copies "
           "installed and used only with Nmap, Wireshark or Microsoft Defender for Identity do not count; one Liminal "
           "uses directly, through wpcap.dll, does, Wireshark's install included. More computers, or redistributing "
           "it, need a paid Npcap OEM license"),
    links=(
        Link("Npcap", NPCAP_SITE, "docs"),
        Link("The Npcap guide", NPCAP_GUIDE, "guide"),
        Link("Npcap Users' Guide (installing it; its options, administrators only among them)",
             NPCAP_GUIDE + "npcap-users-guide.html", "guide"),
        Link("Developing software with Npcap (where its install options are kept: AdminOnly among them)",
             NPCAP_GUIDE + "npcap-devguide.html", "reference"),
        Link("Npcap's API (pcap)", NPCAP_GUIDE + "wpcap/pcap.html", "reference"),
        Link("Npcap internals", NPCAP_GUIDE + "npcap-internals.html", "reference"),
        Link("pcap-filter(7)", PCAP + "pcap-filter.7.html", "reference"),
        Link("Npcap's changes", NPCAP_SITE + "changelog", "changelog"),
        Link("Npcap OEM", NPCAP_SITE + "oem/", "pricing"),
        Link("Npcap's license", "https://github.com/nmap/npcap/blob/master/LICENSE", "terms"),
    ),
    areas=(
        Area("Adapters", "the devices packets can be read from, and their addresses",
             PCAP + "pcap_findalldevs.3pcap.html",
             covered=("the adapter holding the address a net watch is given, and every adapter's addresses, "
                      "which tell what comes in from what goes out")),
        Area("Opening a capture", "an adapter opened, how much of each packet kept", PCAP + "pcap_open_live.3pcap.html",
             covered="the headers alone (a payload prefix when a name is wanted), not promiscuous, 150 ms reads"),
        Area("Filters", "BPF filters compiled from words and set", PCAP + "pcap-filter.7.html",
             covered="(tcp or udp): every TCP and UDP packet, IPv4 and IPv6, at the watched adapter"),
        Area("Reading packets", "each packet as it arrives, with its time", PCAP + "pcap_next_ex.3pcap.html",
             covered="each packet's addresses, ports, TCP flags and size on the wire, folded into flows, never kept"),
        Area("Administrators only", ("an install option that keeps capture to administrators (AdminOnly): any other "
                                     "process that opens a capture has NpcapHelper ask for elevation (UAC)"),
             NPCAP_GUIDE + "npcap-users-guide.html",
             covered=("read first, from the registry (the facts say it for the machine read): off, watching runs as "
                      "the platform's user; on, Npcap is opened only by a platform run as an administrator, and asked "
                      "nothing by one that is none, the watch saying to install it again without the option or to run "
                      "the platform as an administrator")),
        Area("Loopback capture", "a machine's traffic to itself, on the NPF_Loopback adapter",
             NPCAP_GUIDE + "npcap-devguide.html"),
        Area("Raw 802.11", "Wi-Fi frames in monitor mode, with their radiotap headers", NPCAP_SITE),
        Area("Writing a capture", "packets saved to a file Wireshark reads", PCAP + "pcap_dump_open.3pcap.html"),
        Area("The newer way to open", "pcap_create, then options, then pcap_activate", PCAP + "pcap_create.3pcap.html"),
    ),
    calls=(
        # read before any pcap_ call below: Npcap installed for administrators only asks for UAC otherwise
        Call(NPCAP_ADMIN_ONLY, "Npcap's option for administrators only, a REG_DWORD: 1 when it was ticked",
             "Administrators only",
             used=("read, with read access alone, before Npcap is asked for its adapters or to open one, with whether "
                   "the platform is an administrator (IsUserAnAdmin): when the option is on and it is none, Npcap is "
                   "asked nothing"),
             docs=NPCAP_GUIDE + "npcap-devguide.html"),
        Call("pcap_findalldevs", "every capture device and its addresses", "Adapters",
             used="the adapter to watch, and the machine's addresses (again every 30 s while it is watched)",
             docs=PCAP + "pcap_findalldevs.3pcap.html"),
        Call("pcap_freealldevs", "the device list freed", "Adapters", used="after each listing",
             docs=PCAP + "pcap_findalldevs.3pcap.html"),
        Call("pcap_open_live", "a device opened for capture", "Opening a capture",
             used="a net watch's capture: the headers of each packet, not promiscuous, handed on within 150 ms",
             docs=PCAP + "pcap_open_live.3pcap.html"),
        Call("pcap_compile", "a filter compiled", "Filters", used="(tcp or udp)",
             docs=PCAP + "pcap_compile.3pcap.html"),
        Call("pcap_setfilter", "the filter set", "Filters", used="the same", docs=PCAP + "pcap_setfilter.3pcap.html"),
        Call("pcap_freecode", "the compiled filter freed", "Filters", used="once it is set",
             docs=PCAP + "pcap_freecode.3pcap.html"),
        Call("pcap_datalink", "the link layer's type", "Reading packets", used="where each packet's IP header starts",
             docs=PCAP + "pcap_datalink.3pcap.html"),
        Call("pcap_next_ex", "the next packet", "Reading packets", used="each packet while a net watch is reading",
             docs=PCAP + "pcap_next_ex.3pcap.html"),
        Call("pcap_geterr", "the last error in words", "Reading packets", used="why packets could not be watched",
             docs=PCAP + "pcap_geterr.3pcap.html"),
        Call("pcap_close", "the capture closed", "Opening a capture",
             used="when a watch ends: about 20 s after its last read, or the plugin detached",
             docs=PCAP + "pcap_close.3pcap.html"),
        Call("pcap_loop", "packets handed to a callback", "Reading packets", docs=PCAP + "pcap_loop.3pcap.html"),
        Call("pcap_dump_open", "a capture file opened for writing", "Writing a capture",
             docs=PCAP + "pcap_dump_open.3pcap.html"),
        Call("pcap_create", "a capture handle made, not yet active", "The newer way to open",
             docs=PCAP + "pcap_create.3pcap.html"),
    ),
    verified=VERIFIED_NPCAP,
)

ETW = Api(
    name="Event Tracing for Windows (ETW)",
    maker="Microsoft",
    about=("Windows' own kernel-level event tracing. eBPF for Windows' public builds are test-signed, so the "
           "library's Windows watch does not use them: it reads process, file, registry and network-attribution events "
           "from the kernel providers through a private real-time session (the library's machines/etw.py, ctypes over "
           "advapi32 and tdh). A member of Performance Log Users starts a real-time session without an administrator; "
           "a session runs only while a watch is reading and is torn down on stop (a session a killed platform left is "
           "reclaimed at attach)."),
    kind="system",
    base=("advapi32 (StartTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, ControlTraceW, QueryAllTracesW) and tdh "
          "(TdhGetEventInformation, TdhGetProperty), through ctypes (liminal_libs.machines.etw)"),
    version=("the Microsoft-Windows-Kernel-Process, -Kernel-File, -Kernel-Network and -Kernel-Registry manifest "
             "providers, as Windows ships them"),
    auth=("a real-time session needs an administrator or membership in Performance Log Users (whether the platform's "
          "account may start one is read, asking for no UAC); the modern system-provider path, not the NT Kernel "
          "Logger; the plugin never elevates"),
    limits=("a session is opened on a watch's start and stopped on its stop (and about 20 s after the last read); the "
            "record queue is bounded and drops the oldest, counting the drops, and the registry provider at verbose "
            "can be loud, so a caller asks with narrow kinds and reads often"),
    costs="",
    links=(
        Link("Event Tracing for Windows", ETW_DOC + "event-tracing-portal", "docs"),
        Link("About Event Tracing", ETW_DOC + "about-event-tracing", "guide"),
        Link("Configuring and starting a SystemTraceProvider session",
             ETW_DOC + "configuring-and-starting-a-systemtraceprovider-session", "guide"),
        Link("StartTraceW", EVNTRACE + "nf-evntrace-starttracew", "reference"),
        Link("EnableTraceEx2", EVNTRACE + "nf-evntrace-enabletraceex2", "reference"),
        Link("OpenTraceW", EVNTRACE + "nf-evntrace-opentracew", "reference"),
        Link("ProcessTrace", EVNTRACE + "nf-evntrace-processtrace", "reference"),
        Link("ControlTraceW", EVNTRACE + "nf-evntrace-controltracew", "reference"),
        Link("QueryAllTracesW", EVNTRACE + "nf-evntrace-queryalltracesw", "reference"),
        Link("TdhGetEventInformation", TDH + "nf-tdh-tdhgeteventinformation", "reference"),
        Link("TdhGetProperty", TDH + "nf-tdh-tdhgetproperty", "reference"),
        Link("The TCPIP ETW provider", ETW_DOC + "tcpip", "reference"),
    ),
    areas=(
        Area("Starting a session", "a private real-time session opened and torn down",
             EVNTRACE + "nf-evntrace-starttracew",
             covered="opened on a watch's start, stopped on its stop; a stale session reclaimed at attach"),
        Area("Enabling providers", "the four kernel providers, by GUID and keyword",
             EVNTRACE + "nf-evntrace-enabletraceex2",
             covered="process, file, network and registry enabled for the kinds a watch asks"),
        Area("Consuming records", "ProcessTrace on a daemon thread, records decoded",
             EVNTRACE + "nf-evntrace-processtrace",
             covered="each record decoded and turned into an event (or into a connection's attribution)"),
        Area("Decoding properties", "the handful of properties per provider", TDH + "nf-tdh-tdhgeteventinformation",
             covered="pids, image and file names, a connection's addresses and ports, a registry key"),
        Area("Reclaiming sessions", "stale Liminal sessions a killed process left",
             EVNTRACE + "nf-evntrace-queryalltracesw",
             covered="listed and stopped at attach and on every start, by the owner's liveness"),
        Area("Loss counters", "a session's own dropped and lost counts", EVNTRACE + "nf-evntrace-controltracew",
             covered="read at stop, so losses are not silent"),
        Area("The provider manifests", "the events each kernel provider raises", ETW_DOC + "tcpip"),
    ),
    calls=(
        Call("StartTraceW", "a private real-time session opened", "Starting a session", used="each watch's ETW session",
             docs=EVNTRACE + "nf-evntrace-starttracew", writes=True),
        Call("EnableTraceEx2", "a kernel provider enabled on the session", "Enabling providers",
             used="the process, file, network and registry providers (and a capture-state rundown for process)",
             docs=EVNTRACE + "nf-evntrace-enabletraceex2", writes=True),
        Call("OpenTraceW", "the session opened for consuming, a callback registered", "Consuming records",
             used="each watch's ETW session", docs=EVNTRACE + "nf-evntrace-opentracew"),
        Call("ProcessTrace", "records delivered on a daemon thread", "Consuming records",
             used="each watch's ETW session", docs=EVNTRACE + "nf-evntrace-processtrace"),
        Call("ControlTraceW", "the session stopped, and its loss counters queried", "Starting a session",
             used="stopping the session, and reading its losses", docs=EVNTRACE + "nf-evntrace-controltracew",
             writes=True),
        Call("QueryAllTracesW", "the running real-time sessions, by name", "Reclaiming sessions",
             used="finding the stale Liminal sessions to stop at attach",
             docs=EVNTRACE + "nf-evntrace-queryalltracesw"),
        Call("TdhGetEventInformation / TdhGetProperty", "a record's schema and the properties read",
             "Decoding properties", used="decoding each kept record's handful of properties",
             docs=TDH + "nf-tdh-tdhgeteventinformation"),
    ),
    verified=VERIFIED,
)

# The source page for each of the library's 65 capability rows (capabilities.CAPABILITIES), keyed by (area, item):
# the Compare tab passes it to capabilities.by_area, which puts each row's source beside it. The library holds no
# outside host, so these pages live here. Read on 2026-11-14 (the capability research).
SOURCES: dict[tuple[str, str], str] = {
    ('Install and status', 'Where it comes from'): MSE + "InstallEbpf.md",
    ('Install and status', 'Current version'): MSE_REPO + "/releases",
    ('Install and status', 'Production or preview'): MSE + "ReleaseProcess.md",
    ('Install and status', 'Supported OS and extension model'): MSE + "GettingStarted.md",
    ('Program types', 'Count and numbering'): DOX + "ebpf__structs_8h.html",
    ('Program types', 'XDP'): XDPW + "ebpf.md",
    ('Program types', 'sched_cls / tc (tcx)'): PROGRAM_TYPES,
    ('Program types', 'cgroup_skb'): PROGRAM_TYPES,
    ('Program types', 'cgroup_sock'): PROGRAM_TYPES,
    ('Program types', 'cgroup_sock_addr: connect4/6 (and connect_authorization)'):
        MSE + "ConnectAuthorizationAttachTypes.md",
    ('Program types', 'cgroup_sock_addr: recv_accept4/6'): PROGRAM_TYPES,
    ('Program types', 'cgroup_sock_addr: bind4/6 and listen'): MSE + "ConnectAuthorizationAttachTypes.md",
    ('Program types', 'cgroup_sock_addr: other attach points'): PROGRAM_TYPES,
    ('Program types', 'sock_ops'): MSE + "sock_ops_hook.md",
    ('Program types', 'kprobe / tracepoint / fentry'): PROGRAM_TYPES,
    ('Program types', 'LSM'): KDOC + "bpf/prog_lsm.html",
    ('Program types', 'struct_ops'): PROGRAM_TYPES,
    ('Program types', 'Windows BIND'): DOX + "ebpf__nethooks_8h.html",
    ('Program types', 'Windows SAMPLE'): DOX + "ebpf__structs_8h.html",
    ('Program types', 'Windows NETEVENT'): NTOS + "neteventebpfext.md",
    ('Program types', 'Windows PROCESS'): NTOS + "ntosebpfext.md",
    ('Attach types', 'Count and names'): DOX + "ebpf__structs_8h.html",
    ('Attach types', 'Targets, links, multi-attach'): BTD + "bpftool-cgroup.rst",
    ('Map types', 'Count and numbering'): KDOC + "bpf/maps.html",
    ('Map types', 'hash'): KDOC + "bpf/map_hash.html",
    ('Map types', 'array'): KDOC + "bpf/map_array.html",
    ('Map types', 'percpu'): KDOC + "bpf/maps.html",
    ('Map types', 'lru'): KDOC + "bpf/map_hash.html",
    ('Map types', 'lpm_trie'): KDOC + "bpf/map_lpm_trie.html",
    ('Map types', 'prog_array'): KDOC + "bpf/maps.html",
    ('Map types', 'array_of_maps / hash_of_maps'): KDOC + "bpf/map_of_maps.html",
    ('Map types', 'queue / stack'): KDOC + "bpf/map_queue_stack.html",
    ('Map types', 'ringbuf'): KDOC + "bpf/ringbuf.html",
    ('Map types', 'perf_event_array'): MSE + "PerfEventArray.md",
    ('Map types', 'Linux-only map types'): KDOC + "bpf/maps.html",
    ('Helpers', 'Count'): MAN7 + "bpf-helpers.7.html",
    ('Helpers', 'Notable gaps and Windows-only helpers'): MAN7 + "bpf-helpers.7.html",
    ('Helpers', 'kfuncs / BTF-resolved functions'): KDOC + "bpf/kfuncs.html",
    ('Verifier', 'Where and when it runs'): KDOC + "bpf/verifier.html",
    ('Verifier', 'Instruction set coverage'): RFC9669,
    ('Execution', 'Interpreter / JIT / native'): KDOC + "admin-guide/sysctl/net.html",
    ('Execution', 'HVCI (memory integrity)'): HVCI_DOC,
    ('Execution', 'Signing and test signing'): TESTSIGNING_DOC,
    ('Loading', 'libbpf API compatibility'): MSE + "BpfSyscallCompatibility.md",
    ('Loading', 'bpftool'): BT,
    ('Loading', 'netsh ebpf'): MSE + "GettingStarted.md",
    ('Loading', 'Pinning'): MSE + "PinPaths.md",
    ('Loading', 'BTF and CO-RE'): KDOC + "bpf/btf.html",
    ('Loading', 'Program files and registration'): MSE + "NativeCodeGeneration.md",
    ('Events to user space', 'Ring buffer consumer'): MSE + "RingBuffer.md",
    ('Events to user space', 'Perf buffer consumer'): MSE + "PerfEventArray.md",
    ('Events to user space', 'Debug output (bpf_printk)'): BTD + "bpftool-prog.rst",
    ('Privileges', 'Load and attach'): MAN7 + "capabilities.7.html",
    ('Privileges', 'List and read'): KDOC + "admin-guide/sysctl/kernel.html",
    ('Process attribution', 'In the network hooks'): MAN7 + "bpf-helpers.7.html",
    ('Process attribution', 'Two-way and one-off connection tracking (firewall use)'): MSE + "sock_ops_hook.md",
    ('Basic functions', 'Runtime status and version'): KDOC + "bpf/index.html",
    ('Basic functions', 'List programs, maps and links'): BTD + "bpftool-prog.rst",
    ('Basic functions', "Show a program's info"): BTD + "bpftool-prog.rst",
    ('Basic functions', 'Dump or read a map'): BTD + "bpftool-map.rst",
    ('Basic functions', 'Load and attach a pre-built program'): BTD + "bpftool-prog.rst",
    ('Basic functions', 'Detach and unload'): BTD + "bpftool-net.rst",
    ('Basic functions', 'Feature probe'): BTD + "bpftool-feature.rst",
    ('Basic functions', 'Watch events (ring buffer, perf buffer, printk)'): KDOC + "bpf/ringbuf.html",
    ('Basic functions', 'Check a program file before loading'): MSE + "NativeCodeGeneration.md",
}

APIS = (BPFTOOL, BPFTRACE, KERNEL, LIBBPF, EBPF_WINDOWS, NPCAP, ETW)
