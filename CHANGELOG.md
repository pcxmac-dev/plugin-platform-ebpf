# Changelog

## 0.1.5 (2026-11-26)

A status or a tab another plugin asks starts no read as root: Liminal's complete review (Monday-list item 14, finding
P2-2). 0.1.4 made Read again (`refresh`, the runtime read at once through `sudo -n` on Linux) page-only, yet any
`status` asked once the last read was over 60 s old (READ_S) started the same read on a thread and returned the
programs, maps and links it listed. Making `refresh` page-only had only limited how often an asker could start it.

- **Another plugin's `status`, `compare` and `functions`** (the asker the library hands over, `asking.asker()`, names a
  plugin: the MCP plugin for an agent you granted it, or any plugin through the app) start no read and wait for none:
  they answer from the read kept. The status holds no programs, maps or links table, no forms and no Read again, and a
  `lists` line says they are on its page alone; its kernel table and facts stay. All three stay open to anyone.
- **The page's `status`** (asked as `asking.PAGE`) reads again when the last read is old and holds everything, as
  before. So does a status that names no one: liminal-platform 0.42.1 draws the page from `GET /api/machines/ebpf`,
  which asks it naming no one, as does the platform's own attach, so the page cannot be told apart there. A program on
  this PC reading that route still starts the read until the platform names its page on that route; this plugin then
  needs one word changed (`for_its_page`).
- On a library older than 1.66.0, which hands no asker over, every ask is the page's, as before.

Tests: with the last read old, another plugin's status and two tabs make no reading thread (each counted as it is made,
no timing relied on) and run nothing, and its status lists no program; the page's status makes one and lists them, as
does one naming no one. Starting the read for every asker again fails it, and so does handing out the listing. No new
requirement.

## 0.1.4 (2026-11-26)

Read again is asked only from the page too. The user, 2026-11-26: "Yes, closed by default" (liminal-libs 1.107.0: a
hook a plugin declares for no one is its page's alone), and of the reads made with a key or with rights: "Page-only".

- **`refresh` is page-only** (`PAGE_ONLY_HOOKS`, beside the four changes and the two reads as root). It reads the
  runtime again at once, through `sudo -n` on Linux. Until now any plugin, and any program on this machine through the
  platform, could ask it. Another plugin's ask and an ask that names no one are refused (403) in words, and
  liminal-platform asks its login whether you are at the page (401 otherwise).
- `present`, `status` and the two tabs (`compare`, `functions`) stay reads anyone here may ask: they answer from what
  was read last. The watch service stays another plugin's alone.
- Every hook now says who may ask it, so the library's `conformance.warnings` is empty.

Tests: Read again refused to another plugin and to no one with nothing run, and answered for the page; a test that no
hook is left undeclared. They fail when `refresh` is taken out of `PAGE_ONLY_HOOKS`, on liminal-libs 1.106.0 and on
1.107.0 alike. No new requirement: the word is liminal-libs 1.66.0's.

## 0.1.3 (2026-11-26)

Its two reads as root are asked only from the page (the user's choice of 2026-11-25, "Root reads and Namecheap").

- **`show_program` and `dump` are page-only** (`PAGE_ONLY_HOOKS`, beside the four changes). On Linux both run bpftool
  as root through `sudo -n` (on Windows a program is shown through netsh, an administrator's), and answered anyone who
  asked: another plugin, or a program on this PC over HTTP with two headers, read every field of a loaded program and
  the first thousand entries of any map, whoever's it was. Now another
  plugin's ask is refused (403), and so is one that names no one; liminal-platform 0.34.0 refuses one over HTTP (401)
  unless its login shows that you are at the page. The Functions tab's two forms ask them as before. The same caveat
  as 0.1.2's: a local login signs `secret` and `default` in with no password, so a program that signs itself in asks
  them still.
- Asked by anyone, as before: `present`, `status`, `refresh`, `compare` and `functions`. Main's listing of programs,
  maps and links is read as root too, through the status every reader is given; it stays as it was (the page and the
  tray read it).
- Tests: `tests/test_who_asks.py` names the two reads among the page's hooks, so taking either out fails it: each
  refused to another plugin and to no one with nothing run, and answered when the page asks it.
- `__version__` is 0.1.3, as pyproject says.

Needs liminal-libs>=1.60.0.

## 0.1.2 (2026-11-25)

Who may ask its hooks (the sweep after the independent review's finding PLT-H1; the user's choice, 2026-11-25: plugin
releases, each plugin declaring its change actions page-only). The platform hands an ask over HTTP
(`POST /api/machines/ebpf/ask`, two headers and no sign-in) straight to a hook, so any program on this PC asked every
hook this plugin has.

- **The changes are asked only from the page** (`PAGE_ONLY_HOOKS`, liminal-libs 1.66.0's word): `load_program`,
  `attach_program`, `detach_program` and `unload_program`. Another plugin's ask of one is refused (403), and
  liminal-platform 0.34.0 refuses one over HTTP (401) unless its login shows that you are at the page. Before, where
  sudo runs bpftool without a password, a program of any account on this PC had a program loaded into the kernel as
  root and attached to every packet (XDP) or every process (a cgroup hook), an attachment detached, or any pin under
  /sys/fs/bpf removed: the second confirmation (`accept_load`, `accept_attach`, `accept_unload`) is an argument the
  asker sets. On Windows and under WSL 1 every change was refused in words already, and still is. A platform that
  holds no login asks them as before. The 401 rests on the login's word that your browser is signed in, and a local
  login signs `secret` and `default` in with no password, so a program on this PC can sign itself in and ask them
  still: a proof that a program cannot make is the login's and the platform's to give.
- **The watch service is asked only by another plugin** (`PLUGIN_ONLY_HOOKS`): `watch_start`, `watch_read` and
  `watch_stop`, for the firewalls' Filter tabs and trapdoor, as it was built. The platform asks them for a plugin's
  `self.app.ask` alone: over HTTP they are refused (403), from the page too, which never drew them, and so is an ask
  that names no one. Before, the same program started a watch (on Linux bpftrace as root; on Windows a capture and
  ETW's sessions, which this PC opens unelevated) and read every process, connection and file open it saw, and on
  Windows every registry operation, whoever's they were. They are not page-only: no page asks them, and a page-only
  hook is refused to the plugins they are for. Nothing asks them yet (no plugin's code names them, 2026-11-25).
- Asked by anyone, as before: `present`, `status`, `refresh`, `compare`, `functions`, `show_program` and `dump`
  (reads; the last two as root, as Main's listing is). The command line calls the plugin's code in its own process,
  not through an ask, so `watch KINDS...` works as before.
- No new floor: a liminal-libs before 1.66.0 holds no hook to who asks it, and liminal-platform 0.34.0 then reads the
  two words from the plugin itself.
- Tests: `tests/test_who_asks.py`, through the library's own App over the stand-in machines and watches (skipped on a
  liminal-libs before 1.66.0): each of the four changes refused to another plugin and to an ask that names no one,
  every confirmation said, nothing run or read; each run as root when the page asks it; the reads answered to a
  plugin; the watch service started, read and stopped by another plugin alone, on Linux and on Windows, the page's ask
  and no one's making no watch. Taking a hook out of either word fails them.
- `__version__` is 0.1.2, as pyproject says.

Needs liminal-libs>=1.60.0.

## 0.1.1 (2026-11-16)

On liminal-libs 1.60.0, which fixes what building 0.1.0 found in the library:

- **Test signing is said as read, elevated or not.** The library reads it from this boot's start options (the
  registry's `SystemStartOptions`), which any user may read, and from bcdedit only where that cannot be read, and names
  which (`test_signing_source`). Main's table row, Compare's Here column and the API facts name that place. "off
  (could not be confirmed without an administrator)" is gone, and a read naming no place is said as not read.
  `signing_words` and `verdict_words` no longer take whether the platform is elevated.
- **A lost Windows source ends its watch.** A capture or an ETW session lost after it opened stops the watch, its
  `error` in the source's own words, so a watch running is a watch reading: the facts say "Net watches running" and
  "Watches running", as on Linux (`LOST_SAID` in place of `LOST_UNSAID`).
- The net watch's kprobes are the kernel's own (`udpv6_sendmsg`), so the /proc/kallsyms check finds them.
- Its bee is drawn (icons.js), and the contract's icon check runs.
- The eBPF for Windows card names the start options read, with bcdedit as the fallback.
- **It checks its own floor.** The platform loads a plugin from its folder whatever its pyproject says, so on a
  liminal-libs older than 1.60.0 the plugin would word that library's facts as 1.60.0's. There its status says which
  library it needs and is not valid, `present()` is False, the attach reads and reclaims nothing, the API facts say
  only that, and every hook and the command line refuse in the same words (`LIBS_FLOOR`, `libs_too_old`).
- `__version__` is 0.1.1, as pyproject says.

Needs liminal-libs>=1.60.0.

## 0.1.0 (2026-11-16)

The first release: the eBPF API plugin (the user, 2026-11-14: "we need an ebpf api plugin, that shows the difference
between windows and linux capabilities as well as basic functionality"; "trap door uses the ebpf API" / "plugin";
2026-11-15: "wsl and firewall linux should always work under linux, if wsl prevents or misses some capability this
should reflect in the plugin"). A machine plugin at plugin API 2.2 on liminal-libs' eBPF layer, under the platform's OS
plugins section (`SECTION = "os"`, `order = 712`), its icon eBPF's bee (`ICON = "ebpf"`: drawn once liminal-libs 1.60.0
carries the mark, the plug until then). Valid wherever it serves anything, and `present()` agrees: the runtime's
absence is a fact on its page (the status' own `present`), never a reason to be invalid or out of the tray.

- Main: this machine's runtime. On Linux the kernel's own, read with bpftool and a few /proc and /sys files, as root
  through `sudo -n` where it must be (never a password): its release, bpftool and libbpf, unprivileged BPF, the JIT,
  BTF, the BPF filesystem, bpftrace; the programs, maps and links. Root's rights are read from each command it runs:
  `sudo -n true` for sudo as a whole, the listing asked whenever bpftool answered (a least-privilege sudoers rule for
  bpftool lists, though `true` asks for a password), and the watch's own command (`sudo -n bpftrace -V`, as the
  library's watch runs it, the platform root or not), with the kernel functions its scripts' kprobes need looked for
  in /proc/kallsyms. On Windows eBPF for Windows: its three services and its version, and whether it can load here
  (Secure Boot, memory integrity, test signing). On this PC it cannot: every public build is test-signed pre-release,
  and Secure Boot with memory integrity keeps a test-signed driver from loading. Test signing is said off, not
  confirmed without an administrator. A one-shot command's attach reads nothing.
- Compare: the library's 65 points in 12 areas, Linux (in general) beside Windows, each with its source
  (`apis.SOURCES`); which side is this machine, by what it is (neither on macOS or under WSL 1), and a Here column
  filled only from what was read, each naming the read it came from.
- Functions: the nine basic functions and the rights each needs; show a program and dump a map (reads);
  `load_program`, `attach_program`, `detach_program` and `unload_program` (confirmed). A load, the unload of a pin that
  is not Liminal's, and an XDP, cgroup or overwriting attach are asked twice (`accept_load`, `accept_unload`,
  `accept_attach`: exactly true). A load where the BPF filesystem is not mounted at /sys/fs/bpf says bpftool mounts it
  first. What the last read says cannot run here is disabled, with why. On Windows every change is refused in words,
  and under WSL 1 every function. The feature probe and checking a file before loading wait on the library.
- The watch service, for the firewalls' Filter tabs and trapdoor, asked through the platform with the arguments as one
  list (`self.app.ask("ebpf", "watch_read", [watch_id, since])`): `watch_start(kinds, spec=None)`,
  `watch_read(watch_id, since=0)` and `watch_stop(watch_id)` (`WatchService`, `watch_service.py`). A watch of its own
  for each caller under an id of its own, at most 8 at once (a start under way holding its place), each stopping itself
  20 s after its last read, all stopped by the detach and at exit; one that ended still answers a read for 60 s, saying
  why. Events as the library's `Event.as_dict()`, `time` the watch's monotonic clock and `at` the same moment in epoch
  seconds; what was dropped in `lost` and `stats`. bpftrace on Linux (a spec's `pid` the kernel's numbering), Npcap and
  ETW on Windows (a source lost after it opened not said yet: the library's). Never drawn on the page; each ask logged
  by the platform until its deferred `SERVICE_READS` change.
- Inside WSL (liminal-libs 1.57.0 or newer): the Linux runtime applies, and Main ends with an Under WSL table of the
  plugin's own: the distribution and whether systemd runs; the kernel, Microsoft's where its release says so, shared
  by the distributions; the whole virtual machine seen, its pids the kernel's (a watch's spec pid too); on Ubuntu,
  bpftool with no build for a WSL kernel; bpftrace to install; the BPF filesystem; `sudo -n`; what is loaded ending
  with WSL. Under WSL 1 no eBPF, on every page. A platform on Windows never reaches into WSL.
- Its API: seven cards (`apis.py`): bpftool; bpftrace; The Linux kernel — bpf(2) and BTF; libbpf (no call made: what
  the comparison measures EbpfApi.dll against); eBPF for Windows; Npcap (packet capture), the Windows firewall's card
  fitted to the watch; Event Tracing for Windows (ETW). Each says what holds on any machine (the platform draws every
  card everywhere); this machine's state is `api_facts()`'s, from what the last status and the watches learned,
  asking nothing. Every address read on 2026-11-14, the Npcap card's on 2026-11-15. The comparison's sources are here
  too (`SOURCES`), since the library names no outside host.
- The command line: `python -m plugin_platform_ebpf status | compare | functions | watch KINDS...`.

Tests (`tests/`): the contract (the icons.js check skipped before liminal-libs 1.60.0, failing from it on without
the mark); the cards, every point's source, and nothing of one machine on them; the runtime by system, valid on both,
the pages plain JSON, root's and the watch's rights read from each command, Linux, WSL 2, WSL 1, macOS and Windows,
the Here column exactly what was read, the forms' fields the hooks' arguments and their words naming no hidden field,
what cannot run disabled, the second confirmations, Windows' refusals and verdict; the watch service over stand-in
watches, and over the library's own backends with stand-in bpftrace, ETW and capture (the kinds, the ids, the cap,
the self-stop, an ended watch, the detach, the exit guard). Nothing real is started: no bpftool, bpftrace,
PowerShell, ETW, Npcap, sudo or wsl.exe, no port, no network. `tests/conftest.py` keeps the machine they run on from
showing through, so the suite reads alike on Windows, inside WSL and on Linux. CI stops a job after 15 minutes. Needs
liminal-libs>=1.57.0 (from there the Linux runtime applies inside WSL too), and liminal-platform 0.27.0 or newer to
draw its tabs.
