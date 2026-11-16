# Changelog

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
