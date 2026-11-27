# plugin-platform-ebpf

The eBPF API plugin for Liminal: this machine's eBPF runtime, read and shown; eBPF on Linux and on Windows compared,
point by point; the basic functions, each change confirmed; and the watch service that the firewalls' Filter tabs and
trapdoor ask through the platform.

The user's words: "we need an ebpf api plugin, that shows the difference between windows and linux capabilities as well
as basic functionality"; "trap door uses the ebpf API" / "plugin" (2026-11-14); "wsl and firewall linux should always
work under linux, if wsl prevents or misses some capability this should reflect in the plugin" (2026-11-15).

## What it does

A machine plugin of the platform (`liminal_libs.machines.plugin.MachinePlugin`, plugin API 2.2) on the library's eBPF
layer (`liminal_libs.ebpf` and `machines/etw.py`, since liminal-libs 1.54.0). The runtime is chosen by the system the
platform runs on: on Linux the kernel's own (`ebpf.LinuxRuntime`), on Windows eBPF for Windows (`ebpf.WindowsRuntime`).
Its page has Main and API, as every plugin's, and two tabs of its own, Compare and Functions (liminal-platform 0.27.0
or newer draws them). It is drawn under the platform's OS plugins section (`SECTION = "os"`; the user, 2026-11-15: "then
OS plugins"), after the two firewalls (`order = 712`).

**Valid wherever it serves anything**, and it serves everywhere: the comparison needs nothing of the machine, and the
watch needs only its backend. Whether the runtime is there, and why it cannot load, are facts on its page, never a
reason to be invalid: the platform detaches a plugin that is not valid, and its tabs and its watch service would go
with it. `present()`, which the platform's tray asks, agrees with that (True wherever the plugin serves, asking
nothing), so its icon stays in the tray while the list says it is active; whether this machine's eBPF runtime is there
is the status' own `present`. The one place it serves nothing is a liminal-libs older than its floor, 1.60.0
(`LIBS_FLOOR`): the platform loads a plugin from its folder whatever its pyproject says, so the plugin checks for
itself (`libs_too_old`). There its status is not valid and says which library it needs, `present()` is False, its API
facts say only that, and every hook refuses in the same words, the command line too.

The runtime is read on a thread when the platform attaches the plugin, so the page's first look waits on nothing; a
one-shot platform command's attach (`once`) reads nothing, as the platform asks of every plugin, and its status reads
for itself.

**Its icon** is eBPF's bee (`ICON = "ebpf"`), its maker's mark, in liminal-libs' icons.js from 1.60.0.

### On Linux

The runtime is the kernel's, on the Linux the platform runs on: a machine of its own, or a WSL distribution it runs
inside (below). It is read with bpftool's JSON (`bpftool -j`) and a few /proc and /sys files, through the library's
`machines.linux.Shell`: as root through `sudo -n` when the platform is not root, never asking for a password.

- Without root: the kernel's release (`uname -r`); bpftool's and libbpf's versions (`bpftool -j version`, as the
  platform's user, then through `sudo -n`); `unprivileged_bpf_disabled` and `bpf_jit_enable`; kernel BTF
  (/sys/kernel/btf/vmlinux); where the BPF filesystem is mounted (/proc/mounts); bpftrace's version (`bpftrace -V`);
  and, in /proc/kallsyms, the kernel functions the watch scripts' kprobes attach to.
- As root, through `sudo -n`: the programs, maps and links (`bpftool -j prog show`, `map show`, `link show`), a
  program by its id and the changes (bpftool), a map's entries (`sh -c "bpftool -j map dump ..."`: through sh) and an
  unload (`rm -f`). Root's rights are read from what each of these runs, never from one check: `sudo -n true` says
  whether sudo runs any command without a password, the listing is asked whenever bpftool answered (a refusal comes
  back in sudo's words: run the platform as root, or let sudo run it without a password), and the watch's own command
  is asked as the watch runs it (below). A sudoers rule letting the platform's user run bpftool and bpftrace alone
  without a password, the least this plugin needs to list, load, attach, detach and watch, leaves `sudo -n true`
  asking for one: the page says so, and what each command was given. A dump and an unload then need sh and rm too (or
  the platform run as root).
- The watch's own command, `sudo -n bpftrace -V`: the library's watch runs bpftrace through sudo whether the platform
  is root or not, so that command, not root and not bpftrace on the platform's user's path, says whether a watch can
  run here (a platform run as root needs sudo installed all the same). The functions its scripts' kprobes attach to
  (`udp_sendmsg` and `udpv6_sendmsg`) are looked for in /proc/kallsyms: where the kernel lacks one, a watch with `net`
  ends at its start, and the watch's row says so. (Before liminal-libs 1.60.0 the net script probed
  `udp_v6_sendmsg`, a name no kernel has, so every net watch ended at its start.)
- What is missing is said: bpftool not answering, bpftrace not found, no kernel BTF, the BPF filesystem not mounted.

### On Windows

The runtime is eBPF for Windows, Microsoft's separate download, read unelevated through the library's windowless
PowerShell: its three services (the eBPFCore and NetEbpfExt drivers, the eBPFSvc service), the version of its
EbpfApi.dll and, when the core service is there, `netsh ebpf show programs` (an administrator's). Then whether a
test-signed driver can load: Secure Boot (Confirm-SecureBootUEFI, else the registry), memory integrity
(Win32_DeviceGuard) and test signing (this boot's start options, the registry's `SystemStartOptions`, which any user
may read; bcdedit only where that cannot be read).

On this PC it cannot load. Every public eBPF for Windows build is test-signed pre-release (its maintainers have no plans
for production-signed builds), and Secure Boot with memory integrity keeps a test-signed driver from loading. It is not
installed here either. So Main says: not installed; no programs, maps or links, since there are none (not that they
could not be read); and the verdict, each fact with where it was read. Test signing is off, read without an
administrator from this boot's start options (before liminal-libs 1.60.0 it came from bcdedit, which refuses without
one). The comparison serves all the same, and so does the watch, through Npcap and ETW.

## The tabs

**Main** is the plugin's status, read on a thread and kept a short while, so the page waits on nothing (the platform
asks it again every 30 s while the plugin is shown):

- on Linux, the kernel's eBPF: its release, bpftool and libbpf, unprivileged BPF and the JIT, BTF, the BPF filesystem,
  bpftrace, root's rights (what `sudo -n true` answered, or the platform's user id) and the watch (what its own command
  answered, and any kprobe its scripts need that the kernel lacks), each row naming where it was read; the programs,
  maps and links; inside WSL, the Under WSL table (below);
- on Windows, the runtime (installed or not, its version, its three services) and whether it can load here (Secure
  Boot and where it was read, memory integrity, test signing, the verdict in words); the programs, maps and links (or
  why they were not listed: never "none" where the services could not be read).

**Compare** (`compare()`, asked every 30 s while it is shown): the library's comparison (`ebpf.CAPABILITIES`), read on
2026-11-14 from the maintainers' own documentation, headers and release notes. 65 points in 12 areas (Install and
status, Program types, Attach types, Map types, Helpers, Verifier, Execution, Loading, Events to user space,
Privileges, Process attribution, Basic functions), Linux beside Windows, each with its source (the plugin's
`apis.SOURCES`, by area and item). The Linux column is Linux in general, as researched; its heading says which side is
this machine, by what the machine is (sys.platform, and the WSL distribution read): Windows, Linux, or WSL 2 and the
distribution's name; neither on macOS, or under WSL 1, which has no Linux kernel. Its Here column holds only what this
machine's status read, each naming the read it came from: the JIT (`bpf_jit_enable`; on Windows, memory integrity),
pins (the BPF filesystem's mounts), BTF, unprivileged BPF and root's rights, the listing (the commands actually asked),
the watch, the Windows verdict. Nothing is claimed there that was not read, and where nothing was (a read that failed,
a runtime that does not apply here) the heading says why.

**Functions** (`functions()`, asked every 5 s while it is shown): the comparison's nine basic functions, how each is
done on Linux and on Windows and the rights it needs, and the forms of those offered here (below). What the last read
says cannot run here is said so, its button disabled with why, as the user asked of what WSL lacks (2026-11-15): on
Windows every change; on Linux all six where the runtime does not apply or under WSL 1, what runs bpftool (show, dump,
load, attach, detach) where bpftool did not answer or was refused as root, and an unload where no BPF filesystem is at
/sys/fs/bpf (no pin can be there). Not from `sudo -n true` alone: a sudoers rule may let bpftool run without a
password while it asks for one.

## The functions

Reads:

- **Status and version**: Main.
- **List programs, maps and links**: Main's tables.
- **Show a program**: by its id (`bpftool -j prog show id <id>`; on Windows `netsh ebpf show programs id=<id>
  level=verbose`).
- **Dump a map**: `dump(map_id, limit=1000)`, its first `limit` entries (`bpftool -j map dump id <id>`, at most 8 MB of
  its output read). On Windows netsh lists maps but cannot read one, so a dump there is empty and says why.

Changes, each a form confirmed on the page and run as root through `sudo -n`, each answering what it did (`said`,
`lines`, `ok`):

- **Load a pre-built program**: `load_program(path, pin=None, type=None, accept_load=False)`. `bpftool prog load`, the
  program pinned under /sys/fs/bpf: by default at `/sys/fs/bpf/liminal_<the file's stem>`; a pin is a plain path there,
  with no `..`. Always asked twice. Where the BPF filesystem is not mounted at /sys/fs/bpf, bpftool mounts it there
  first, as root (its own rule, without `--nomount`): the second ask says so, from what was read.
- **Attach**: `attach_program(kind, target=None, pin=None, prog_id=None, map_id=None, flags=None, overwrite=False,
  accept_attach=False)`, the program named by its pin or its id. XDP and tcx (`xdp`, `xdpgeneric`, `xdpdrv`,
  `xdpoffload`, `tcx_ingress`, `tcx_egress`) go on a network device; `sk_msg_verdict`, `sk_skb_verdict`,
  `sk_skb_stream_verdict` and `sk_skb_stream_parser` with the sockmap's `map_id`, and `flow_dissector`; any other kind
  is a cgroup attach type (`connect4`, `sendmsg4`, `sock_ops`...) on a cgroup v2 folder under /sys/fs/cgroup, its
  `flags` `multi` or `override`. Asked twice for an XDP or cgroup attach, and for one that replaces a program already
  attached (`overwrite`).
- **Detach**: `detach_program(link_id=None, kind=None, target=None, pin=None, prog_id=None, map_id=None)`: a link by its
  id, else the attach type with its target, the way it was attached. Confirmed once.
- **Unload**: `unload_program(pin, accept_unload=False)`. Its pin is removed (`rm -f`, as root), so the kernel frees the
  program once nothing else holds it. Asked twice for a pin that is not Liminal's own (`/sys/fs/bpf/liminal_*`).

Asked twice: the hook refuses until its `accept_load`, `accept_attach` or `accept_unload` is exactly true (a
`ValueError` whose `accept` names that argument, as the Windows firewall's `RiskRefused`; "yes" or 1 is not true); the
platform's page then asks a second time and sends the form again with it true. That is how the page asks twice, not a
right: whoever asks, the commands still need root, through `sudo -n`. The confirmation's words name no field shown
for some kinds alone (an attach's device or folder): the page keeps a hidden field's value, so the list under the
words says what the change uses.

Asked only from the page (0.1.2; the sweep after the independent review's finding PLT-H1, 2026-11-25): `load_program`,
`attach_program`, `detach_program` and `unload_program` are the plugin's `PAGE_ONLY_HOOKS` (liminal-libs 1.66.0's
word). Another plugin's ask of one is refused, and liminal-platform 0.34.0 refuses one over HTTP unless its login shows
that you are at the page. Before, any program on this PC could ask them with two headers and send the second
confirmation itself: where sudo runs bpftool without a password, that loaded a program into the kernel as root. Since
0.1.3 the two reads as root are the page's too: `show_program` and `dump` (the Functions tab's forms; the user's choice
of 2026-11-25), which gave any asker every field of a loaded program and the entries of any map. Since 0.1.4 Read
again (`refresh`) is the page's as well: it reads the runtime again at once, as root on Linux (the user, 2026-11-26:
"Page-only"). The other reads (the status, the tabs) are asked by anyone, as before. The
platform's check rests on its login's word that your browser is signed in, and a local login signs `secret` and
`default` in with no password: it does not stop a program on this PC that signs itself in.

On Windows every change is refused, in words: eBPF for Windows' public builds are all test-signed, and on this PC Secure
Boot and memory integrity keep them from loading. It also loads only native, signed .sys drivers, and only for an
administrator. Under WSL 1, which has no Linux kernel, every function is refused in words. A program netsh would not
show without an administrator is said not read, never missing.

Not offered in 0.1.0, since the library has no call for them yet: the feature probe (`bpftool feature probe`), checking
a program file before it is loaded, a map's lookup, its event pipe and ring buffers, and the attachments beyond the
links (`bpftool net show`, `cgroup tree`). Watching events is the service below, not a form.

## The watch service, for other plugins

The user's words (2026-11-14): "the filter allows (uses ebpf) tracking one off connections"; "both windows and linux use
ebpf for the filter tab"; "trapdoor will monitor all processes"; "trap door uses the ebpf API" / "plugin".

Three hooks for the firewalls' Filter tabs and trapdoor, asked through the platform (plugins never import each other):
`watch_start`, `watch_read` and `watch_stop`. The page never draws them: no tab, form, action or option names them. One
`WatchService` (`watch_service.py`) per plugin holds the watches.

Asked only by another plugin (0.1.2): the three are the plugin's `PLUGIN_ONLY_HOOKS` (liminal-libs 1.66.0's word). The
platform asks them for a plugin's `self.app.ask` alone, and refuses them over HTTP (403), from its page too, and to an
ask that names no one. Before, any program on this PC could start a watch with two headers (on Linux bpftrace as root,
on Windows a capture and ETW's sessions) and read every process, connection and file open it saw. The command line
calls the service in its own process, not through an ask.

- `watch_start(kinds, spec=None)` starts a watch of the caller's own and answers
  `{"id", "kinds", "system", "address", "timeout", "stopped", "error"}`: its id (16 hex characters, not one another
  caller can guess), the kinds it watches (a sorted list), `linux` or `windows`, the address of the adapter a Windows
  `net` watch reads ("" otherwise), the seconds it lives after its last read (20), and whether it has stopped already
  and why: a watch whose source could not open is still given, stopped, with its words in `error` (one that cannot
  even be made or started is refused, in its words).
  - `kinds` is a non-empty list of `net`, `process`, `file` and `registry`, the registry on Windows alone (Linux has
    none). Anything else is refused in words, a bare string included (it would be read letter by letter).
  - `spec` is a dict, or none, handed on as given; anything else is refused. On Linux only `pid` is read: the process
    whose file opens are followed, with the children it forks while watched (every process's without it; only digits
    reach bpftrace). It is matched against bpftrace's pid, the kernel's numbering: inside a WSL distribution (a pid
    namespace of its own) that is not the pid ps shows there, so give one an event showed (a process watch's `exec`).
    On Windows: `address` (the adapter's, for `net`), `ports`, `udp`, `payloads`, `host`, `tag`, `poll`, `flow_idle`,
    `attr_hold` and `queue`; `pid` is not read there. A Windows `net` watch that names no address reads the adapter of
    this PC's way out (`world.route_address`), and is refused when there is none.
- `watch_read(watch_id, since=0)` answers `{"id", "seq", "events", "lost", "stopped", "error", "stats"}`: the events
  after `since` (the `seq` the last read gave, a whole number; 0 for all the watch keeps; a watch numbers its own from
  1, and a `since` past its `seq` is taken for another watch's, so all it keeps is given), what the source said it
  dropped (`lost`), whether the watch has stopped and why (`error`: bpftrace missing, sudo asking for a password, a
  kprobe the kernel lacks, Npcap or ETW not open here), and what the backend says it dropped (`stats`: on Windows the
  packets, ETW's records and the open flows; {} on Linux). Each read keeps the watch going. A watch that ended (its
  source could not open, it ended on its own, nobody read it) still answers for 60 s, with what it kept and why it
  ended; after that, or once stopped, its id names nothing and a read is refused: start another. On Windows a capture
  or an ETW session lost after it opened (an adapter removed, a session stopped from outside) ends the watch, its
  `error` in the source's own words ("the capture stopped: ...", "the ETW session ended: ..."), as bpftrace ending
  does on Linux (liminal-libs 1.60.0's `NpcapEtwWatch`), so a watch running is a watch reading.
- `watch_stop(watch_id)` ends it now and lets its id go: `{"id", "stopped": true, "error"}` (`error`: what its stop
  said, when it raised). A second stop, or an id that names no watch, answers the same and stops nothing.

Each event is the library's `Event.as_dict()` (`seq`, `time`, `kind`, `action`, `pid`, `ppid`, `program`, `path`,
`local`, `remote`, `proto`, `bytes`, `extra`) with `at` beside it. `time` is the watch's monotonic clock
(`time.monotonic`), for order and intervals; `at` is the same moment as wall time, in seconds since the epoch (null
when it cannot be told).

Bounds, so nothing runs while nobody reads:

- each caller gets a watch of its own, never shared, so one caller's stop never ends another's;
- at most 8 run at once, a start under way holding its place; the next is refused, in words, until one ends;
- a watch stops itself 20 s after its last read (the library's `Watch`);
- the plugin's detach stops every live watch, each on a short thread of its own, waiting 3 s at most in all and never
  raising; and an exit guard stops what is left as the interpreter exits: on Linux bpftrace runs as root, in a session
  of its own, and could outlive the platform.

A watch keeps its last 2000 events, all its kinds together (the library's `DEFAULT_RING`); a reader that falls further
behind loses the oldest, and `seq` jumps. Ask for the kinds you need and read every few seconds: on Windows `process`
includes every DLL loaded and `registry` every registry operation, either enough to fill it in seconds.

What watches:

- **Linux**: bpftrace (`sudo -n bpftrace -f json -e <script>`) with the library's `net`, `process` and `file` scripts;
  it needs bpftrace through `sudo -n`: sudo installed, letting the platform's user run bpftrace without a password
  (the platform root or not), and bpftrace on sudo's own path. A kprobe on a function the kernel lacks ends the watch
  at its start (all its kinds' scripts run as one program): Main's watch row says which, read from /proc/kallsyms. The
  scripts are low-rate: TCP one event per connection change (`connect`,
  `accept`, `close`), UDP one per socket and peer a minute, each path a program opens once a minute for each way it is
  opened, `exec` and `exit` per process. What a budget held back comes as one `skipped` event a second, with its
  `count`.
- **Windows**: Npcap for `net` (packets folded into flows: a start by its direction, `in`, `out` or `local`, then a
  `close` with the bytes and packets; the program from ETW's Kernel-Network records), and ETW's Kernel-Process,
  Kernel-File and Kernel-Registry providers for the rest. On this PC both run unelevated: Npcap is installed without its
  administrators-only option, and the account is in Performance Log Users. Not eBPF: eBPF for Windows cannot load here,
  and this backend stands behind the same interface until signed builds exist.

On the platform the arguments go as one list (`PlatformApp.ask(name, hook, args)`):

```python
started = self.app.ask("ebpf", "watch_start", [["net", "process"], {}])
got = self.app.ask("ebpf", "watch_read", [started["id"], since])
self.app.ask("ebpf", "watch_stop", [started["id"]])
```

The frame's form, `self.app.ask("ebpf", "watch_read", watch_id, since)`, is a TypeError there. Every refusal is a
`liminal_libs.apps.Refused` (its `status` and `reason`): the platform's own when the eBPF plugin is not loaded (404) or
is disabled (409), where the caller says that the eBPF plugin is off; and the plugin's (a bad kind, spec or `since`,
the cap, an id that names no watch: a `ValueError` or a `LookupError` in its words) as the platform's `HookRefused`, a
`Refused` whose `words` are the plugin's.

Each of these asks is logged, and noted as an ask: `PlatformApp.ask` keeps only the plain reads and a tab's hooks out
of its log, and a plugin cannot mark a hook of its own as a read without drawing it on the page. So every
`watch_start`, `watch_read` and `watch_stop` writes a line to the platform's log (`platform: ebpf asked watch_read (2
arguments)`, in logs/platform.log: the hook's name and how many arguments, never their values), and Connections
shows the platform asking, not the caller. Read no more often than needed: every few seconds, never in a tight loop.
The fix is a deferred platform and library change (`MachinePlugin.SERVICE_READS` in the library, and `PlatformApp.ask`
renamed `ask_page` with the frame's signature), which would also let Connections name the caller.

## Inside WSL

The user's words (2026-11-15): "wsl and firewall linux should always work under linux, if wsl prevents or misses some
capability this should reflect in the plugin".

Inside a WSL distribution the platform runs in, the Linux runtime applies (liminal-libs 1.57.0 or newer) and reads that
distribution's kernel as any other's: what WSL lacks shows in what is read. Main then ends with an Under WSL table of
the plugin's own, from the library's `machines.linux.wsl`, `wsl_generation` and `systemd_runs` (reached through
getattr; not the library's `wsl_table`, whose rows are the admin plugins' and the firewalls'). A library before 1.57.0
refused a WSL kernel, in its own words, and had no helpers; the plugin needs 1.60.0 in any case. The table says:

- **This Linux**: WSL 2 (or 1) and the distribution's name, and whether systemd runs (as read; "not read" where the
  library cannot say). A WSL 2 kernel whose release names Microsoft (`...-microsoft-standard-WSL2`) is Microsoft's:
  WSL updates it, not the distribution's packages, and every WSL 2 distribution on the PC shares it. One that does not
  (a kernel of the user's own, `.wslconfig`'s `kernel=`) is said not to be Microsoft's build.
- **What is seen**: the whole WSL virtual machine's programs, maps, links and events, every running distribution's and
  WSL's own. An event's pid is the kernel's, not the one this distribution's own pid namespace shows (`ps`, /proc), and
  a watch's spec `pid` is matched against the kernel's too: give it one an event showed, not one `ps` shows. The
  network is WSL's, behind Windows (NAT by default), so Windows' own traffic is not seen here.
- **bpftool**: whether it answered. On Ubuntu, and a distribution like it (/etc/os-release's ID or ID_LIKE), the
  `bpftool` command is linux-tools-common's wrapper, which wants a build for the running kernel, and there is none for
  a WSL kernel: the usual advice (the distribution's bpftool package) does not hold there, and a bpftool built from its
  own source does. Elsewhere (Fedora, Debian, Gentoo) the distribution's own bpftool package is a plain binary, and that
  is the advice given.
- **bpftrace**: from the distribution (`sudo apt install bpftrace` on Ubuntu); the watch runs it through `sudo -n`.
- **The BPF filesystem**: mounted at /sys/fs/bpf or not, from /proc/mounts. In this PC's Ubuntu it is not, though
  systemd runs there; a load pins its program there, and bpftool mounts it first, as root (the load's second ask says
  so); an unload is not offered while it is not mounted (no pin can be there).
- **Root**: what needs root goes through `sudo -n`, each command saying what it was given. In this PC's Ubuntu sudo
  asks for a password for every command, so listing, dumping, loading and watching are refused until sudo lets the
  platform's user run them without one: bpftool and bpftrace alone are enough to list, load, attach, detach and watch;
  a dump also runs sh, and an unload rm.
- **Lifetime**: everything loaded ends when WSL stops the virtual machine.

Under WSL 1 there is no Linux kernel, and no eBPF: whatever its tools answer, no runtime is there; nothing that needs
root is asked; Compare marks neither column this machine's; and every function is refused, in words. The table then
says that, and the command that makes the distribution WSL 2 (`wsl --set-version "<its name>" 2`, from Windows: WSL's
own name for it where WSL gave one).

A platform on Windows never reaches into a WSL distribution from outside: the Linux eBPF of this PC's distributions is
the eBPF plugin's on the platform running inside one (linux::liminal-platform, at 9775).

## Its API

The user's words (2026-11-11): "each plugin should reflect the the API its attached to, and present links that provide
documentation, the plugin interface should more or less contain what it already has, BUT, it should also expose more of
what the API is about". The plugin declares what it attaches to (`apis.py`), and the platform's page draws each card:
what the API is, its links, every part of it (those the plugin uses first, the rest under "more of the API") and every
call the plugin makes, with the API's other notable calls beside them. Every outside address the plugin knows is there,
the comparison's sources included (`SOURCES`, by area and item): the library names no outside host. The platform draws
every card on every machine (Windows, a Linux of its own, inside WSL), so the cards say what holds anywhere; this
machine's own state (what is installed, whether it can load, this account's rights) is what `api_facts()` says, from
what was read.

Seven cards, in this order:

- **bpftool** (the libbpf / bpftool project): [bpftool](https://github.com/libbpf/bpftool) and its manual pages,
  [bpftool-prog(8)](https://github.com/libbpf/bpftool/blob/main/docs/bpftool-prog.rst),
  [bpftool-map(8)](https://github.com/libbpf/bpftool/blob/main/docs/bpftool-map.rst),
  [bpftool-net(8)](https://github.com/libbpf/bpftool/blob/main/docs/bpftool-net.rst),
  [bpftool-cgroup(8)](https://github.com/libbpf/bpftool/blob/main/docs/bpftool-cgroup.rst),
  [bpftool-link(8)](https://github.com/libbpf/bpftool/blob/main/docs/bpftool-link.rst) and
  [bpftool-feature(8)](https://github.com/libbpf/bpftool/blob/main/docs/bpftool-feature.rst). The calls it makes:
  `bpftool -j version`, `prog show`, `map show`, `link show`, `prog show id <id>` and `map dump id <id>`; the changes
  (`prog load`, `net attach`, `prog attach`, `cgroup attach`, `link detach`, `net detach`, `prog detach`, `cgroup
  detach`, and `rm -f <pin>` to unload); `feature probe`, `net show` and `prog dump xlated` beside them, unused.
- **bpftrace** (the bpftrace project): [bpftrace](https://github.com/bpftrace/bpftrace),
  [its manual](https://github.com/bpftrace/bpftrace/blob/master/man/adoc/bpftrace.adoc) and
  [its one-liner tutorial](https://github.com/bpftrace/bpftrace/blob/master/docs/tutorial_one_liners.md). The calls:
  `sudo -n bpftrace -f json -e <script> [pid]`, the watch on Linux; `bpftrace -V`, its version; and `sudo -n bpftrace
  -V`, the watch's own command asked whether it can run here; `bpftrace -l` beside them.
- **The Linux kernel — bpf(2) and BTF** (the Linux kernel):
  [its BPF documentation](https://docs.kernel.org/bpf/index.html),
  [program types](https://docs.kernel.org/bpf/libbpf/program_types.html), [maps](https://docs.kernel.org/bpf/maps.html),
  [BTF](https://docs.kernel.org/bpf/btf.html), [the verifier](https://docs.kernel.org/bpf/verifier.html),
  [the ring buffer](https://docs.kernel.org/bpf/ringbuf.html), [signing](https://docs.kernel.org/bpf/signing.html),
  [LSM programs](https://docs.kernel.org/bpf/prog_lsm.html), [kfuncs](https://docs.kernel.org/bpf/kfuncs.html),
  [bpf-helpers(7)](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html),
  [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html), the
  [kernel's](https://docs.kernel.org/admin-guide/sysctl/kernel.html) and the
  [network's](https://docs.kernel.org/admin-guide/sysctl/net.html) sysctls,
  [RFC 9669](https://www.rfc-editor.org/rfc/rfc9669.html) (the instruction set) and
  [What is eBPF?](https://ebpf.io/what-is-ebpf/). Its reads, none needing root: `uname -r`,
  /proc/sys/kernel/unprivileged_bpf_disabled, /proc/sys/net/core/bpf_jit_enable, /sys/kernel/btf/vmlinux, /proc/mounts,
  and /proc/kallsyms (the functions the watch scripts' kprobes attach to). The comparison's Linux column is Linux in
  general, as researched; its Here column is this kernel's.
- **libbpf** (the libbpf project): [its API reference](https://libbpf.readthedocs.io/en/latest/),
  [its overview](https://docs.kernel.org/bpf/libbpf/libbpf_overview.html) and
  [libbpf](https://github.com/libbpf/libbpf). No call is made (the plugin drives bpftool, which is built on it):
  libbpf's API is what the comparison measures eBPF for Windows' EbpfApi.dll against.
- **eBPF for Windows** (Microsoft): [eBPF for Windows](https://github.com/microsoft/ebpf-for-windows), its pages on
  [getting started](https://github.com/microsoft/ebpf-for-windows/blob/main/docs/GettingStarted.md),
  [installing it](https://github.com/microsoft/ebpf-for-windows/blob/main/docs/InstallEbpf.md),
  [bpf() compatibility](https://github.com/microsoft/ebpf-for-windows/blob/main/docs/BpfSyscallCompatibility.md),
  [native code](https://github.com/microsoft/ebpf-for-windows/blob/main/docs/NativeCodeGeneration.md),
  [the release process](https://github.com/microsoft/ebpf-for-windows/blob/main/docs/ReleaseProcess.md) (test signing),
  [pin paths](https://github.com/microsoft/ebpf-for-windows/blob/main/docs/PinPaths.md),
  [the ring buffer](https://github.com/microsoft/ebpf-for-windows/blob/main/docs/RingBuffer.md) and
  [the perf event array](https://github.com/microsoft/ebpf-for-windows/blob/main/docs/PerfEventArray.md) among them,
  [its API reference](https://microsoft.github.io/ebpf-for-windows/) and
  [its releases](https://github.com/microsoft/ebpf-for-windows/releases);
  [XDP for Windows](https://github.com/microsoft/xdp-for-windows),
  [ntosebpfext](https://github.com/microsoft/ntosebpfext) and [PREVAIL](https://github.com/vbpf/prevail), its verifier;
  Microsoft Learn's [TESTSIGNING](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option)
  and [memory integrity](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity)
  pages. Its reads: `Get-Service` for eBPFCore, NetEbpfExt and eBPFSvc, EbpfApi.dll's version, `netsh ebpf show
  programs`, `maps` and `links`, a program's `level=verbose`, `Confirm-SecureBootUEFI`, the SecureBoot registry key,
  `Win32_DeviceGuard`, the start options (`SystemStartOptions`), `bcdedit /enum {current}` where those cannot be read;
  loading in code (EbpfApi.dll) and `netsh ebpf add program` beside them, unused.
- **Npcap (packet capture)** (Nmap Software), the Windows firewall plugin's card fitted to the Windows watch's `net`
  kind: [Npcap](https://npcap.com/), [its users' guide](https://npcap.com/guide/npcap-users-guide.html),
  [where its install options are kept](https://npcap.com/guide/npcap-devguide.html) (AdminOnly among them),
  [its API](https://npcap.com/guide/wpcap/pcap.html) and
  [pcap-filter(7)](https://www.tcpdump.org/manpages/pcap-filter.7.html). The calls, through wpcap.dll: the AdminOnly
  option read first, then `pcap_findalldevs`, `pcap_open_live`, `pcap_compile`, `pcap_setfilter`, `pcap_next_ex`,
  `pcap_close` and the rest of what the library's capture calls. Npcap's free license covers five computers. Copies
  installed and used only with Nmap, Wireshark or Microsoft Defender for Identity do not count; one Liminal uses
  directly counts, Wireshark's install included (this PC's is). More computers, or redistributing it, need Npcap
  OEM. The card says nothing of one machine's install: that it is installed, and for whom, are the facts.
- **Event Tracing for Windows (ETW)** (Microsoft), for the Windows watch's other kinds and the program behind each
  flow: [Event Tracing for Windows](https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal),
  [About Event Tracing](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing), and the reference page
  of each call: `StartTraceW`, `EnableTraceEx2`, `OpenTraceW`, `ProcessTrace`, `ControlTraceW`, `QueryAllTracesW` (the
  sessions a killed platform left, stopped at attach), `TdhGetEventInformation` and `TdhGetProperty`. Its providers
  are Microsoft-Windows-Kernel-Process, -Kernel-File, -Kernel-Network and -Kernel-Registry, in a real-time session of
  Liminal's own that Performance Log Users may start unelevated.

`api_facts()` says what the last status and the watches learned, asking nothing: the runtime there and its version,
the watch's own command and the kernel functions its kprobes need, whether Npcap and ETW can watch here, and the
watches running, out of the service's cap.

Every address on the cards was read from its maker's pages on 2026-11-14, with the comparison's research (`VERIFIED`);
the Npcap card keeps the day the Windows firewall plugin read its pages, 2026-11-15 (`VERIFIED_NPCAP`). The test
`test_the_cards_pages_answer` asks each address again when `LIMINAL_VENDOR_PAGES=1` is set (it is skipped otherwise).

## From the command line

```
python -m plugin_platform_ebpf status
python -m plugin_platform_ebpf compare
python -m plugin_platform_ebpf functions
python -m plugin_platform_ebpf watch net process
```

`status` (the default) prints the status as JSON, `compare` and `functions` the tabs' pages, and `watch KINDS...` starts
a watch of those kinds through the same service, prints its events as they come and stops it. The platform's page
drives the same hooks.

## Tests

No test starts bpftool, bpftrace, PowerShell, ETW, Npcap, sudo or wsl.exe, opens a port or reaches the network: the
runtimes and the watches are stand-ins, and a test that reaches the real thing fails. `tests/conftest.py` stands in for
`world.under_wsl` and `linux.wsl`, so the suite reads alike on Windows, inside WSL and on a Linux of its own.

- `test_contract.py`: the plugin contract at plugin API 2.2, a platform machine plugin, `SECTION` "os" and `ICON`
  "ebpf", which liminal-libs' icons.js draws.
- `test_apis.py`: the cards sound (`problems` finds nothing); every point of the comparison with its source, and every
  source a real point; each card's calls the ones the library's or the plugin's code makes (read from its source
  text); and no card saying anything of one machine's own state.
- `test_plugin.py`: the runtime by system; valid on both, never a bare problem, `present()` agreeing; on a library
  older than the floor not valid, saying which it needs, and nothing read or run; every page plain
  JSON; root's rights read from each command (a least-privilege sudoers rule among them) and the watch's from its own
  command; Main, Compare and Functions on Linux, inside WSL 2 and WSL 1, on macOS, with a library that refuses WSL,
  and on Windows; the Here column holding exactly what was read, each naming its read; the forms' fields are the
  hooks' arguments, and their words name no field a kind hides; what cannot run disabled with why; the second
  confirmations, accepted only by exactly true, every XDP mode and any cgroup; Windows' and WSL 1's refusals and the
  verdict's words (stand-in facts, no PowerShell); the cap through the hooks; a quick detach that lets the app go; a
  one-shot command's attach reading nothing; no watch thread left behind.
- `test_watch_service.py`: a watch and an id of its own for each caller; the kinds and the spec checked, the registry
  Windows' own, a Windows `net` watch's adapter; a source that cannot open; reads as plain JSON, with wall time and
  `since`; an id that names no watch; the self-stop; a stop and a second stop; the cap of 8, a start under way holding
  its place and one refused giving it back; an ended watch saying why for a while; the detach stopping every watch
  within its bound, on daemon threads; the exit guard, which holds no service alive; and the library's own Linux and
  Windows backends driven through the service over stand-in bpftrace, ETW and capture. `subprocess.Popen`, the
  capture's `load_pcap`, ETW's real consumer and the route lookups fail a test that reaches them, and no watch's thread
  may be left after one.
- `test_who_asks.py`: who may ask, through the library's own App (skipped on a liminal-libs before 1.66.0): the four
  changes refused to another plugin and to an ask that names no one, every confirmation said, nothing run or read;
  each run as root when the page asks it; the reads answered to a plugin; the watch service started, read and stopped
  by another plugin alone, on Linux and on Windows, the page's ask and no one's making no watch.

Run them from this folder, with the library installed or on the path:

```
PYTHONPATH=src python -m pytest -q -p no:cacheprovider
```

CI runs them on Ubuntu and Windows, with Python 3.12 and 3.15, against liminal-libs' `release/0.2.0`.
