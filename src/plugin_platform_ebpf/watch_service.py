"""The eBPF plugin's watch service (the user, 2026-11-14: "trap door uses the ebpf API"; the design of that day:
"every watcher stops itself after its viewing timeout and on the plugin's detach; no threads are left behind"): what
trapdoor and the firewalls' Filter tabs ask, through the platform, to see this machine's network, process, file and
registry events while their tabs are looked at. The plugin's hooks watch_start, watch_read and watch_stop are this
service's start, read and stop; no tab, form, action or option of the plugin's page names them.

- One watch for each caller. Each start is a library Watch of its own (`factory`: ebpf.make_watch, which runs bpftrace
  on Linux and Npcap with ETW on Windows) under an id of its own (secrets.token_hex: short, and not one another caller
  can guess), so one caller's stop never ends another's watch. At most `cap` (CAP, 8) run at once; the next is refused,
  in words, until one ends.
- Nothing runs while nobody reads. A read keeps its watch going; a watch nobody reads stops itself `timeout` seconds
  (20) after its last read (the library's Watch does it); a stop ends it at once; the plugin's detach stops every one
  (stop_all, which waits STOP_ALL_S at most in all); and what is still running when the interpreter exits is stopped
  then (an atexit guard holding the services by weak reference only).
- Asked as it is asked: the kinds a non-empty list of net, process, file and registry (the registry is Windows' own);
  the spec a dict, or none, handed on as given. One thing is filled in: on Windows a net watch reads the packets at an
  adapter, and when the spec names no address it is the adapter of this machine's way out (world.route_address).
- Answers are plain JSON. An event is the library's Event.as_dict(), its "time" the watch's clock (monotonic) and its
  "at" the same moment as wall time (epoch seconds). A watch that ended (its source could not open, it ended on its
  own, or nobody read it) still says so, and why, on a read for ENDED_S after; then its id names nothing. A watch's end
  is what the library's Watch says (`stopped`, `error`): on Linux bpftrace ending says it; on Windows a capture or an
  ETW session lost after it opened is not said yet (the library's NpcapEtwWatch does not notice it), so such a watch
  answers on with nothing new until it is stopped.

One lock guards what the service holds. A watch's own threads (its self-stop, its reader, its pump) are the watch's,
and a watch is made, started, read and stopped outside the lock, so a source slow to open or to close holds up no
other caller."""
from __future__ import annotations

import atexit
import math
import secrets
import threading
import time
import weakref
from collections import OrderedDict
from collections.abc import Mapping

from liminal_libs.ebpf.watch import DEFAULT_TIMEOUT, KINDS, watch_system
from liminal_libs.machines import world

CAP = 8  # watches running at once, at most: each a bpftrace process (Linux) or an ETW session and a capture (Windows)
ID_BYTES = 8  # an id's random bytes: 16 hex characters
ENDED_S = 60.0  # a watch that ended still answers a read (what it kept, and why it ended) this long after
STOP_ALL_S = 3.0  # stop_all waits this long at most in all, each watch stopped on a short thread of its own
STOPPER = "ebpf-watch-stop"  # the name of those threads
WINDOWS_ONLY = frozenset({"registry"})  # kinds only Windows has (ETW's Kernel-Registry): Linux has no registry
SHOWN = 60  # characters of a value shown back in the words
PLAIN_DEPTH = 8  # how deep an answer's values are made plain; anything deeper is said as text
CLOSED = "the platform is exiting: no watch is started now"
LANDED_LATE = ("every watch was stopped while this one was starting (the eBPF plugin was detached), so it was stopped "
               "too: start it again once the plugin is attached")
NO_WAY_OUT = ("a net watch reads the packets at the adapter of this machine's way out, and this machine has none "
              "(no default route): name the adapter's address in spec[\"address\"], or watch process, file or registry")


class WatchService:
    """The watches of one eBPF plugin, by id. `factory(kinds: frozenset, spec: dict)` makes a library Watch, not yet
    started (ebpf.make_watch; a stand-in in tests). `clock` is the watches' clock (time.monotonic, as the library's
    Watch has it): the time a watch gives each event is turned into wall time with it and `wall` (time.time). `cap`:
    the watches running at once, at most. `system`: "linux" or "windows", the machine the watches are for (by default
    this one's, as make_watch picks it)."""

    def __init__(self, factory, clock=time.monotonic, cap: int = CAP, *, wall=time.time, system: str | None = None):
        self._factory = factory
        self._clock = clock
        self._wall = wall
        self._cap = max(1, int(cap))
        self.system = watch_system(system=system)
        self._lock = threading.Lock()
        self._live: dict[str, _Held] = {}  # running, or ended and not yet reaped
        self._ended: OrderedDict[str, _Held] = OrderedDict()  # ended, oldest first: still read for ENDED_S
        self._starting: set[str] = set()  # ids given to starts under way: each holds a place under the cap
        self._generation = 0  # one more at each stop_all: a start under way from before it is stopped as it lands
        self._closed = False  # the interpreter is exiting: nothing is started again
        _keep(self)

    # -- the service's three asks ----------------------------------------------------------------------------------
    def start(self, kinds, spec=None) -> dict:
        """A watch of its own for this caller, started: {"id", "kinds", "system", "address", "timeout", "stopped",
        "error"}. A watch whose source could not open is still given (stopped, with why in "error"), and its id read.
        ValueError, in words, for kinds that are not a non-empty list of this machine's kinds, a spec that is not a
        dict, a Windows net watch with no adapter to watch, and while `cap` watches run."""
        wanted = self._kinds(kinds)
        given = self._spec(spec)
        net_here = self.system == "windows" and "net" in wanted
        if net_here and _blank(given.get("address")):
            given["address"] = self._way_out()
        with self._lock:
            self._reap()
            if self._closed:
                raise ValueError(CLOSED)
            running = len(self._live) + len(self._starting)
            if running >= self._cap:
                raise ValueError(f"{running} watches are running, the most at once here: stop one (watch_stop), or "
                                 f"let one end by itself ({DEFAULT_TIMEOUT:g} s after its last read)")
            wid = self._new_id()
            self._starting.add(wid)
            generation = self._generation
        watch = None
        try:
            watch = self._factory(wanted, given)
            watch.start()
        except Exception as e:  # noqa: BLE001 - no watch is given: the caller is told why, in words
            if watch is not None:
                _stop_quietly(watch)
            with self._lock:
                self._starting.discard(wid)
            raise ValueError(f"the watch could not {'start' if watch is not None else 'be made'}: {_words(e)}") from e
        address = given.get("address") if net_here and isinstance(given.get("address"), str) else ""
        system = getattr(watch, "system", "")
        held = _Held(watch, wanted, system if system in ("linux", "windows") else self.system, address, self._clock())
        with self._lock:
            self._starting.discard(wid)
            landed = generation == self._generation and not self._closed
            if landed:
                self._live[wid] = held
        if not landed:
            _stop_quietly(watch)
            raise ValueError(CLOSED if self._closed else LANDED_LATE)
        return _plain({"id": wid, "kinds": sorted(wanted), "system": held.system, "address": address,
                       "timeout": getattr(watch, "timeout", DEFAULT_TIMEOUT), "stopped": _stopped(watch),
                       "error": _text(getattr(watch, "error", ""))})

    def read(self, watch_id, since=0) -> dict:
        """What a watch saw after `since` (the seq the caller's last read gave; 0 for all it keeps), and the watch kept
        going: {"id", "seq", "events", "lost", "stopped", "error", "stats"}. Each event is Event.as_dict() and "at", its
        time as wall time. A since past the watch's seq came from another watch (seq starts again at 1 for each), so
        all this one keeps is given. "stats" is what the backend says it dropped (Windows': stats()), {} when it says
        nothing. LookupError, in words, for an id that names no watch here."""
        after = _since(since)
        held = self._held(watch_id)
        watch = held.watch
        seq, events = watch.read(after)
        if after > seq:  # a since from another watch, whose seq ran further: everything this one keeps is new
            seq, events = watch.read(0)
        mono, wall = self._clock(), self._wall()  # after the read: no event is later than now
        with self._lock:
            held.touched = mono
        return _plain({"id": watch_id, "seq": _count(seq), "events": [_event(e, mono, wall) for e in events],
                       "lost": _count(getattr(watch, "lost", 0)), "stopped": _stopped(watch),
                       "error": _text(getattr(watch, "error", "")), "stats": _stats(watch)})

    def stop(self, watch_id) -> dict:
        """End a watch now and let its id go: {"id", "stopped": True, "error"} ("error": what its stop said, when it
        raised; "" otherwise). Idempotent: an id stopped already, or that names no watch here, answers the same and
        stops nothing. LookupError for an id that is not text."""
        if not isinstance(watch_id, str):
            raise LookupError(f"a watch's id is the text watch_start gave: {_shown(watch_id)} is not one")
        with self._lock:
            self._reap()
            held = self._live.pop(watch_id, None) or self._ended.pop(watch_id, None)
        error = _stop_quietly(held.watch) if held is not None else ""
        return {"id": watch_id, "stopped": True, "error": error}

    # -- for the plugin --------------------------------------------------------------------------------------------
    @property
    def cap(self) -> int:
        """The watches running at once, at most, here."""
        return self._cap

    def stop_all(self, wait: float = STOP_ALL_S) -> int:
        """Stop every watch (the plugin's detach): each on a short daemon thread of its own, all waited for `wait`
        seconds at most in all, so a detach is quick whatever a source takes to close (one still closing then finishes
        on its thread). A start under way is stopped as it lands. The service stays usable for a later attach. Never
        raises; answers how many watches were running."""
        try:
            with self._lock:
                self._generation += 1
                held = list(self._live.values())
                self._live.clear()
                self._ended.clear()
            watches = [h.watch for h in held]
            running = sum(1 for w in watches if not _stopped(w))
            _stop_together(watches, wait)
            return running
        except Exception:  # noqa: BLE001 - a detach is never failed by its watches
            return 0

    def live(self) -> list[dict]:
        """The watches running now, oldest first, each {"kinds", "system", "address", "started", "idle", "timeout",
        "lost", "error"} ("started" as wall time, "idle" the seconds since its last read): what the plugin's facts may
        say of them. Asking keeps none of them going, and no id is given: a watch's id is its caller's."""
        with self._lock:
            self._reap()
            held = list(self._live.values())
        mono, wall = self._clock(), self._wall()
        return [_plain({"kinds": sorted(h.kinds), "system": h.system, "address": h.address,
                        "started": wall - (mono - h.started), "idle": max(0.0, mono - h.touched),
                        "timeout": getattr(h.watch, "timeout", DEFAULT_TIMEOUT),
                        "lost": _count(getattr(h.watch, "lost", 0)), "error": _text(getattr(h.watch, "error", ""))})
                for h in held]

    # -- inside ------------------------------------------------------------------------------------------------------
    def _kinds(self, kinds) -> frozenset:
        """The kinds asked, checked: a list (a text would be read letter by letter, and watch nothing), not empty, of
        the kinds a watch has on this machine."""
        here = KINDS if self.system == "windows" else tuple(k for k in KINDS if k not in WINDOWS_ONLY)
        if not isinstance(kinds, (list, tuple)):
            raise ValueError(f"a watch's kinds are a list, such as [\"process\", \"file\"]: {_shown(kinds)} is not one")
        if not kinds:
            raise ValueError(f"no kind was asked: a watch follows one at least of {_listed(here, 'or')}")
        for kind in kinds:
            if isinstance(kind, str) and kind in WINDOWS_ONLY and kind not in here:
                raise ValueError(f"the {kind} is Windows' own (Linux has none): a watch here follows "
                                 f"{_listed(here, 'and')}")
            if not isinstance(kind, str) or kind not in here:
                raise ValueError(f"{_shown(kind)} is not a kind a watch follows: they are {_listed(here, 'and')}")
        return frozenset(kinds)

    @staticmethod
    def _spec(spec) -> dict:
        """The spec asked, as a dict of the service's own (the caller's is never changed): none is {}."""
        if spec is None:
            return {}
        if not isinstance(spec, Mapping):
            raise ValueError(f"a watch's spec is a dict of its options, or none: {_shown(spec)} is not one")
        return dict(spec)

    @staticmethod
    def _way_out() -> str:
        """The address of this machine's way out, the adapter a Windows net watch reads: ValueError when it has none."""
        try:
            address = world.route_address()
        except OSError:
            address = None
        if _blank(address):
            raise ValueError(NO_WAY_OUT)
        return str(address)

    def _new_id(self) -> str:
        """A fresh id, under the lock: none held, ended or being started has it."""
        while True:
            wid = secrets.token_hex(ID_BYTES)
            if wid not in self._live and wid not in self._ended and wid not in self._starting:
                return wid

    def _held(self, watch_id) -> _Held:
        """The watch an id names, running or ended a short while ago: LookupError, in words, for none."""
        held = None
        with self._lock:
            self._reap()
            if isinstance(watch_id, str):
                held = self._live.get(watch_id) or self._ended.get(watch_id)
        if held is None:
            if not isinstance(watch_id, str):
                raise LookupError(f"a watch's id is the text watch_start gave: {_shown(watch_id)} is not one")
            raise LookupError(f"no watch here has the id {_cut(repr(watch_id))}: it was stopped, it ended over "
                              f"{ENDED_S:g} s ago, or it was never started; start another (watch_start)")
        return held

    def _reap(self) -> None:
        """Under the lock, on every call: a watch that ended leaves the running ones (its place under the cap is free),
        and is kept ENDED_S for a read to say so; at most `cap` of those, the oldest let go first."""
        now = self._clock()
        for wid, held in list(self._live.items()):
            if _stopped(held.watch):
                del self._live[wid]
                held.ended = now
                self._ended[wid] = held
        for wid, held in list(self._ended.items()):
            if now - held.ended >= ENDED_S:
                del self._ended[wid]
        while len(self._ended) > self._cap:
            self._ended.popitem(last=False)

    def _shut(self) -> int:
        """Stop every watch and start none after: the interpreter is exiting."""
        with self._lock:
            self._closed = True
        return self.stop_all()


class _Held:
    """A watch the service holds: the watch, what it was asked for, and when (on the service's clock) it was started,
    last read and found ended."""

    __slots__ = ("watch", "kinds", "system", "address", "started", "touched", "ended")

    def __init__(self, watch, kinds: frozenset, system: str, address: str, now: float):
        self.watch, self.kinds, self.system, self.address = watch, kinds, system, address
        self.started = self.touched = now
        self.ended = now


# -- stopping ------------------------------------------------------------------------------------------------------
def _stopped(watch) -> bool:
    try:
        return bool(watch.stopped)
    except Exception:  # noqa: BLE001 - a watch that cannot say is taken for one that ended
        return True


def _stop_quietly(watch) -> str:
    """Stop a watch, never raising: "" when it stopped, else what its stop said."""
    try:
        watch.stop()
    except Exception as e:  # noqa: BLE001 - its stop flag is set first: it ends whatever its source said
        return f"its stop said: {_words(e)}"
    return ""


def _stop_together(watches, wait: float) -> None:
    """Stop the watches each on a daemon thread of its own and wait for them `wait` seconds at most in all. Where no
    thread can be started (an interpreter that is exiting), a watch is stopped here instead."""
    threads = []
    for watch in watches:
        thread = threading.Thread(target=_stop_quietly, args=(watch,), name=STOPPER, daemon=True)
        try:
            thread.start()
        except RuntimeError:
            _stop_quietly(watch)
            continue
        threads.append(thread)
    deadline = time.monotonic() + max(0.0, float(wait))
    for thread in threads:
        thread.join(max(0.0, deadline - time.monotonic()))


# -- answers as plain JSON -----------------------------------------------------------------------------------------
def _event(event, mono: float, wall: float) -> dict:
    """One event as plain JSON: Event.as_dict(), and "at", the wall time of its "time" (the watch's clock)."""
    out = _plain(event.as_dict())
    t = out.get("time")
    at = None
    if isinstance(t, (int, float)) and not isinstance(t, bool):
        try:
            at = float(wall) - (float(mono) - float(t))
        except (TypeError, ValueError, OverflowError):
            at = None
    out["at"] = at if at is not None and math.isfinite(at) else None
    return out


def _stats(watch) -> dict:
    """What a backend says it dropped (Windows': packets, ETW records, open flows), {} when it says nothing."""
    stats = getattr(watch, "stats", None)
    if not callable(stats):
        return {}
    try:
        got = stats()
    except Exception:  # noqa: BLE001 - its counters are a nicety
        return {}
    return _plain(got) if isinstance(got, Mapping) else {}


def _plain(value, depth: int = 0):
    """`value` as plain JSON, whatever a source put in it: a number that is no number (NaN, infinity) is null, a set a
    sorted list, bytes text, a key text, and anything else (or deeper than PLAIN_DEPTH) said as text."""
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        return float(value) if math.isfinite(value) else None
    if depth >= PLAIN_DEPTH:
        return _text(value)
    if isinstance(value, Mapping):
        return {_text(k): _plain(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v, depth + 1) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_plain(v, depth + 1) for v in value), key=lambda v: (type(v).__name__, str(v)))
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    return _text(value)


def _count(value) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError, OverflowError):
        return 0


def _text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return str(value)
    except Exception:  # noqa: BLE001
        return type(value).__name__


def _since(value) -> int:
    """A read's since: the seq a read gave, a whole number from 0 (none is 0)."""
    if value is None:
        return 0
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"since is the seq a read gave (a whole number, 0 for all a watch keeps): "
                         f"{_shown(value)} is not one")
    return value


def _blank(value) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def _words(e: BaseException) -> str:
    return str(e) or type(e).__name__


def _shown(value) -> str:
    """A value as the words show it, short: the text 'net', list [1, 2], none."""
    if value is None:
        return "none"
    try:
        said = _cut(repr(value))
    except Exception:  # noqa: BLE001
        said = "?"
    return f"the text {said}" if isinstance(value, str) else f"{type(value).__name__} {said}"


def _cut(said: str) -> str:
    return said if len(said) <= SHOWN else said[:SHOWN - 1] + "…"


def _listed(names, last: str) -> str:
    """net, process, file and registry."""
    names = list(names)
    return names[0] if len(names) == 1 else f"{', '.join(names[:-1])} {last} {names[-1]}"


# -- what the interpreter's exit stops ------------------------------------------------------------------------------
# The services alive now, held weakly: when the interpreter exits, what their watches left running is stopped (on
# Linux a bpftrace runs as root in a session of its own, and could outlive the platform), and no service is kept
# alive for it. One lock guards the set, so a service made in another thread never changes it while it is read.
_SERVICES: "weakref.WeakSet[WatchService]" = weakref.WeakSet()
_SERVICES_LOCK = threading.Lock()


def _keep(service: WatchService) -> None:
    with _SERVICES_LOCK:
        _SERVICES.add(service)


def _stop_left_at_exit() -> None:
    """Stop every watch still running as the interpreter exits, and start none after (the design: nothing is left
    running)."""
    with _SERVICES_LOCK:
        services = list(_SERVICES)
    for service in services:
        try:
            service._shut()
        except Exception:  # noqa: BLE001 - one service's trouble keeps no other's watches running
            pass


atexit.register(_stop_left_at_exit)
