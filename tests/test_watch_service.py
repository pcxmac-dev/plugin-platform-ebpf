"""The watch service (watch_service.py; the user, 2026-11-14: "trap door uses the ebpf API"): what trapdoor and the
firewalls' Filter tabs ask through the platform, as the plugin's watch_start, watch_read and watch_stop hand it on.
Each caller gets a watch of its own under an id of its own; at most eight run at once; kinds and spec are checked and
handed on as given, the one thing filled in being a Windows net watch's adapter; a read gives what is new as plain
JSON, each event's time as wall time too; a watch nobody reads stops itself; a stop is idempotent; a watch that ended
says why on its next read; the plugin's detach stops every watch within its bound and never raises; and the
interpreter's exit stops what is left, holding no service alive for it.

Nothing real is reached: the watches are the library's Watch over stand-in sources (or the library's own backends
over stand-in bpftrace, ETW and capture), on a stand-in clock. No process is started, no ETW session, no capture, no
route asked: subprocess.Popen, capture.load_pcap, etw's real consumer and the route lookups fail the test if reached
(each reach is noted, so one inside a thread is seen too), and no watch's thread is left after a test."""
from __future__ import annotations

import atexit
import functools
import gc
import importlib.util
import inspect
import json
import queue
import re
import secrets
import subprocess
import threading
import time
import types
import weakref

import pytest

from liminal_libs import capture, netpath
from liminal_libs.capture import Flags, Packet
from liminal_libs.ebpf.watch import Event, Watch, make_watch
from liminal_libs.machines import etw, world
from liminal_libs.machines.etw import EtwRecord
from plugin_platform_ebpf import watch_service
from plugin_platform_ebpf.watch_service import CAP, ENDED_S, NO_WAY_OUT, STOP_ALL_S, WatchService

WALL = 1_800_000_000.0  # the stand-in wall clock's now (epoch seconds)
WAY_OUT = "192.168.1.20"  # this machine's way out, as a stand-in route says it
THREADS = ("ebpf-watch", "ebpf-bpftrace", "npcap-etw-watch", watch_service.STOPPER)
PASSWORD = "bpftrace ended (exit code 1): sudo: a password is required"


# -- stand-ins ------------------------------------------------------------------------------------------------------
class Clock:
    """A clock that moves only when the test moves it."""

    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


class StandIn(Watch):
    """The library's Watch (its ring, its read, its self-stop) over a source that is the test: nothing is opened.
    `feed` hands it an event as a source would. `fail`: the source refuses to open, in those words (as a backend says
    it, stopping at once). `opening`/`release`: its open waits for the test. `hold`: its close waits for the test.
    `raises`: its close raises."""

    system = "linux"

    def __init__(self, kinds, spec=None, *, fail="", opening=None, release=None, hold=None, raises=False, **options):
        super().__init__(kinds, spec, **options)
        self.fail, self.opening, self.release, self.hold, self.raises = fail, opening, release, hold, raises
        self.begun = self.ended = 0

    def _begin(self):
        self.begun += 1
        if self.opening is not None:
            self.opening.set()
            assert self.release.wait(5)
        if self.fail:
            self.error = self.fail
            self._stop.set()

    def _end(self):
        self.ended += 1
        if self.hold is not None:
            self.hold.wait(10)
        if self.raises:
            raise RuntimeError("its source would not close")

    def feed(self, kind, action, **fields):
        self._emit(kind, action, **fields)

    def end_on_its_own(self, words):
        """The source ended while the watch was wanted (as bpftrace's reader finds it): said, and stopped."""
        self.error = words
        self.stop()


class Factory:
    """ebpf.make_watch as a stand-in: what it was asked (kinds, spec) and each watch it made, on the test's clock and
    for the test's system."""

    def __init__(self, clock, system="linux", **options):
        self.clock, self.system, self.options = clock, system, options
        self.asked: list[tuple[frozenset, dict]] = []
        self.made: list[StandIn] = []

    def __call__(self, kinds, spec):
        self.asked.append((kinds, spec))
        watch = StandIn(kinds, spec, clock=self.clock, **self.options)
        watch.system = self.system
        self.made.append(watch)
        return watch


def service(system="linux", cap=CAP, **options):
    """A service over a stand-in factory and clocks: (the service, the factory, the clock, the wall clock)."""
    clock, wall = Clock(), Clock(WALL)
    factory = Factory(clock, system, **options)
    return WatchService(factory, clock=clock, cap=cap, wall=wall, system=system), factory, clock, wall


def plain(answer):
    """The answer, checked to be plain JSON: it round-trips json.dumps with no NaN and no default."""
    assert json.loads(json.dumps(answer, allow_nan=False)) == answer
    return answer


def wait_for(condition, seconds: float = 3.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.005)
    return condition()


def watch_threads() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.is_alive() and (t.name in THREADS or t.name.startswith("etw-"))]


@pytest.fixture(autouse=True)
def _nothing_real(monkeypatch):
    """Nothing real is reached: no process started, no Npcap loaded, no ETW session or its DLLs, no route asked (each
    reach is noted, so one in a watch's thread is seen too). Every service a test makes is stopped after it, and no
    watch's thread is left."""
    reached: list[str] = []

    def refusing(name):
        def refuse(*args, **kwargs):
            reached.append(name)
            raise AssertionError(f"a test reached the real {name}")
        return refuse
    for module, name in ((subprocess, "Popen"), (capture, "load_pcap"), (etw, "EtwConsumer"), (etw, "WinAdvapi32"),
                         (etw, "WinTdh"), (etw, "reclaim_stale_sessions"), (world, "route_address"),
                         (netpath, "lan_address")):
        monkeypatch.setattr(module, name, refusing(name))
    made: list[WatchService] = []
    init = WatchService.__init__

    @functools.wraps(init)
    def tracked(self, *args, **kwargs):
        init(self, *args, **kwargs)
        made.append(self)
    monkeypatch.setattr(WatchService, "__init__", tracked)
    yield types.SimpleNamespace(reached=reached, made=made)
    for s in made:
        s.stop_all()
    assert wait_for(lambda: watch_threads() == []), f"a watch's thread was left: {watch_threads()}"
    assert reached == []


def test_the_guards_fail_a_test_that_reaches_the_real_thing(_nothing_real):
    """What the suite stands on: each real thing refuses, and the reach is noted."""
    for call in (lambda: subprocess.Popen(["bpftrace"]), capture.load_pcap, lambda: etw.EtwConsumer("watch"),
                 world.route_address):
        with pytest.raises(AssertionError, match="a test reached the real"):
            call()
    assert _nothing_real.reached == ["Popen", "load_pcap", "EtwConsumer", "route_address"]
    _nothing_real.reached.clear()


# -- start ----------------------------------------------------------------------------------------------------------
def test_each_caller_gets_a_watch_of_its_own_under_an_id_of_its_own():
    s, factory, _, _ = service()
    asked = {"pid": 4242}
    a = plain(s.start(["process", "file"], asked))
    assert a == {"id": a["id"], "kinds": ["file", "process"], "system": "linux", "address": "", "timeout": 20.0,
                 "stopped": False, "error": ""}
    assert re.fullmatch(r"[0-9a-f]{16}", a["id"])  # short
    b = plain(s.start(["process", "file"], asked))  # the same ask again: another watch, never the first one shared
    assert b["id"] != a["id"] and len(factory.made) == 2 and factory.made[0] is not factory.made[1]
    assert all(w.begun == 1 and not w.stopped for w in factory.made)
    # handed on as asked: the kinds as a frozenset, the spec as given, a copy of its own (the caller's never changed)
    assert factory.asked == [(frozenset({"process", "file"}), {"pid": 4242})] * 2
    assert factory.asked[0][1] is not asked and asked == {"pid": 4242}
    s.stop(a["id"])  # one caller's stop ends its own watch alone
    assert factory.made[0].stopped and not factory.made[1].stopped


def test_an_id_comes_from_secrets_and_is_never_one_held(monkeypatch):
    given = iter(["a" * 16, "a" * 16, "b" * 16])
    sizes = []

    def token_hex(n):
        sizes.append(n)
        return next(given)
    monkeypatch.setattr(secrets, "token_hex", token_hex)
    s, _, _, _ = service()
    assert s.start(["net"])["id"] == "a" * 16
    assert s.start(["net"])["id"] == "b" * 16  # the first again was held: another is drawn
    assert sizes == [8, 8, 8]


@pytest.mark.parametrize("kinds, words", [
    ("net", "a watch's kinds are a list, such as [\"process\", \"file\"]: the text 'net' is not one"),
    ("", "a watch's kinds are a list, such as [\"process\", \"file\"]: the text '' is not one"),
    (None, "a watch's kinds are a list, such as [\"process\", \"file\"]: none is not one"),
    ({"net"}, "a watch's kinds are a list, such as [\"process\", \"file\"]: set {'net'} is not one"),
    ({"net": True}, "a watch's kinds are a list, such as [\"process\", \"file\"]: dict {'net': True} is not one"),
    ([], "no kind was asked: a watch follows one at least of net, process or file"),
    ((), "no kind was asked: a watch follows one at least of net, process or file"),
    (["dns"], "the text 'dns' is not a kind a watch follows: they are net, process and file"),
    (["NET"], "the text 'NET' is not a kind a watch follows: they are net, process and file"),
    (["net", 5], "int 5 is not a kind a watch follows: they are net, process and file"),
    (["net", "registry"], "the registry is Windows' own (Linux has none): a watch here follows net, process and file"),
])
def test_kinds_are_a_non_empty_list_of_this_machines_kinds_or_refused_in_words(kinds, words):
    s, factory, _, _ = service()
    with pytest.raises(ValueError) as refused:
        s.start(kinds)
    assert str(refused.value) == words
    assert factory.asked == [] and s.live() == []  # nothing made, no place held


def test_the_registry_is_windows_own():
    s, factory, _, _ = service("windows")
    assert plain(s.start(["registry"]))["kinds"] == ["registry"]
    assert plain(s.start(("registry", "process")))["kinds"] == ["process", "registry"]  # a tuple is a list too
    assert factory.asked == [(frozenset({"registry"}), {}), (frozenset({"registry", "process"}), {})]
    with pytest.raises(ValueError, match=r"^no kind was asked: a watch follows one at least of net, process, file or "
                                         r"registry$"):
        s.start([])


def test_the_spec_is_a_dict_or_none_and_handed_on_as_given():
    s, factory, _, _ = service()
    for bad, shown in (("pid=4242", "the text 'pid=4242'"), ([1], "list [1]"), (4242, "int 4242")):
        with pytest.raises(ValueError) as refused:
            s.start(["file"], bad)
        assert str(refused.value) == f"a watch's spec is a dict of its options, or none: {shown} is not one"
    s.start(["file"])
    s.start(["net", "file"], {"pid": "4242", "tag": "trapdoor", "ports": [443]})
    # nothing filled in on Linux: no address for net (bpftrace watches every socket), no route asked
    assert factory.asked == [(frozenset({"file"}), {}),
                             (frozenset({"net", "file"}), {"pid": "4242", "tag": "trapdoor", "ports": [443]})]


def test_a_windows_net_watch_reads_the_adapter_of_this_machines_way_out(monkeypatch):
    asked = []
    monkeypatch.setattr(world, "route_address", lambda: asked.append(1) or WAY_OUT)
    s, factory, _, _ = service("windows")
    a = plain(s.start(["net"]))
    assert (a["address"], a["system"]) == (WAY_OUT, "windows")
    assert factory.asked[-1] == (frozenset({"net"}), {"address": WAY_OUT}) and len(asked) == 1
    for blank in (None, "", "  "):
        s.start(["net", "process"], {"address": blank, "ports": [443]})
        assert factory.asked[-1][1] == {"address": WAY_OUT, "ports": [443]}
    assert len(asked) == 4
    given = s.start(["net"], {"address": "10.0.0.2"})  # an address given is kept, and no route asked
    assert given["address"] == "10.0.0.2" and factory.asked[-1][1] == {"address": "10.0.0.2"} and len(asked) == 4
    s.start(["process", "file", "registry"])  # no net: nothing filled, no route asked
    assert factory.asked[-1][1] == {} and len(asked) == 4


def test_a_windows_net_watch_with_no_way_out_is_refused_in_words(monkeypatch):
    s, factory, _, _ = service("windows", cap=1)

    def no_route():
        raise OSError("the network is unreachable")
    for route in (lambda: None, lambda: "", no_route):
        monkeypatch.setattr(world, "route_address", route)
        with pytest.raises(ValueError) as refused:
            s.start(["net"])
        assert str(refused.value) == NO_WAY_OUT
        assert "spec[\"address\"]" in NO_WAY_OUT and "no default route" in NO_WAY_OUT
    assert factory.asked == []
    assert not s.start(["process"])["stopped"]  # the refused ones held no place under the cap


def test_a_source_that_cannot_open_is_said_at_once_and_its_id_still_read():
    s, factory, _, _ = service(fail=PASSWORD)
    a = plain(s.start(["net"]))
    assert a["stopped"] and a["error"] == PASSWORD
    r = plain(s.read(a["id"]))
    assert (r["stopped"], r["error"], r["events"]) == (True, PASSWORD, [])
    assert s.live() == []  # it runs nothing, and holds no place under the cap


def test_a_factory_or_a_start_that_raises_is_refused_in_words_and_holds_no_place():
    """Its place under the cap is given back: on a service of one, the next start runs (a place kept for good would
    refuse every start after until the platform restarts, a detach and an attach between)."""
    clock, asked = Clock(), []

    def refusing_once(kinds, spec):
        asked.append(spec)
        if len(asked) == 1:  # NpcapEtwWatch's float() of a poll that is no number, before anything is opened
            raise ValueError("could not convert string to float: 'soon'")
        return StandIn(kinds, spec, clock=clock)
    s = WatchService(refusing_once, clock=clock, cap=1, system="windows")
    with pytest.raises(ValueError, match=r"^the watch could not be made: could not convert string to float: 'soon'$"):
        s.start(["process"], {"poll": "soon"})
    assert s._starting == set() and s.live() == []
    assert not s.start(["process"])["stopped"]  # the place is free: the next one runs
    made = []

    class Raising(StandIn):
        def _begin(self):
            if self is made[0]:
                raise OSError("the scripts could not be read")

    def raising(kinds, spec):
        made.append(Raising(kinds, spec, clock=clock))
        return made[-1]
    s = WatchService(raising, clock=clock, cap=1, system="linux")
    with pytest.raises(ValueError, match=r"^the watch could not start: the scripts could not be read$"):
        s.start(["file"])
    assert made[0].stopped and s.live() == [] and s._starting == set()
    assert not s.start(["file"])["stopped"] and len(s.live()) == 1  # and here too


# -- read -----------------------------------------------------------------------------------------------------------
def test_a_read_gives_what_is_new_as_plain_json_each_time_as_wall_time_too():
    s, factory, clock, wall = service()
    wid = s.start(["process", "file"])["id"]
    watch = factory.made[0]
    clock.t = 1001.5
    watch.feed("process", "exec", pid=7, ppid=1, program="sh", path="/bin/sh")
    clock.t = 1002.0
    watch.feed("file", "open", pid=7, program="sh", path="/etc/hosts", extra={"flags": 0})
    clock.t, wall.t = 1003.0, WALL
    r = plain(s.read(wid))
    assert (r["id"], r["seq"], r["lost"], r["stopped"], r["error"], r["stats"]) == (wid, 2, 0, False, "", {})
    first, second = r["events"]
    assert first == {**Event(1, 1001.5, "process", "exec", 7, 1, "sh", "/bin/sh").as_dict(), "at": WALL - 1.5}
    assert second["seq"] == 2 and second["extra"] == {"flags": 0} and second["at"] == WALL - 1.0
    assert all(type(e) is dict for e in r["events"])  # the events' dicts, never Event objects
    assert plain(s.read(wid, 2))["events"] == []  # nothing new since the last read
    assert [e["seq"] for e in plain(s.read(wid, 1))["events"]] == [2]
    assert [e["seq"] for e in plain(s.read(wid, 1.0))["events"]] == [2]  # a whole number, however JSON gives it
    assert [e["seq"] for e in plain(s.read(wid, None))["events"]] == [1, 2]


def test_a_since_from_another_watch_gives_all_this_one_keeps():
    s, factory, _, _ = service()
    old = s.start(["net"])["id"]
    for pid in (1, 2, 3, 4, 5):
        factory.made[0].feed("net", "connect", pid=pid)
    assert plain(s.read(old))["seq"] == 5
    s.stop(old)
    new = s.start(["net"])["id"]  # started again: a new id, and its seq starts again at 1
    factory.made[1].feed("net", "connect", pid=9)
    r = plain(s.read(new, 5))  # the caller's since from the first watch: past this one's seq, so all of it is new
    assert r["seq"] == 1 and [e["pid"] for e in r["events"]] == [9]
    assert plain(s.read(new, 1))["events"] == []


@pytest.mark.parametrize("since", [-1, "3", True, 1.5, float("nan"), float("inf"), [1]])
def test_a_since_that_is_no_seq_is_refused_in_words(since):
    s, _, _, _ = service()
    wid = s.start(["net"])["id"]
    with pytest.raises(ValueError, match=r"^since is the seq a read gave \(a whole number, 0 for all a watch keeps\)"):
        s.read(wid, since)


def test_an_id_that_names_no_watch_here_is_refused_in_words():
    s, _, _, _ = service()
    with pytest.raises(LookupError) as refused:
        s.read("0123456789abcdef")
    assert str(refused.value) == ("no watch here has the id '0123456789abcdef': it was stopped, it ended over 60 s "
                                  "ago, or it was never started; start another (watch_start)")
    for not_an_id, shown in ((5, "int 5"), (None, "none"), (["x"], "list ['x']")):
        with pytest.raises(LookupError) as refused:
            s.read(not_an_id)
        assert str(refused.value) == f"a watch's id is the text watch_start gave: {shown} is not one"


def test_reading_keeps_a_watch_going_and_one_nobody_reads_stops_itself():
    """The library's Watch stops itself `timeout` seconds after the last read: its own self-stop, on the stand-in
    clock."""
    s, factory, clock, _ = service()
    wid = s.start(["process"])["id"]
    watch = factory.made[0]
    clock.t += 15
    s.read(wid)  # read: kept going
    clock.t += 15  # 30 s since it started, 15 since its last read
    time.sleep(1.2)  # the self-stop looks at least once a second
    assert not watch.stopped and len(s.live()) == 1
    assert s.live()[0]["idle"] == 15.0
    clock.t += 6  # 21 s since its last read: nobody reads it
    assert wait_for(lambda: watch.stopped) and watch.ended == 1
    r = plain(s.read(wid))  # it says so on the next read, and holds no place under the cap
    assert r["stopped"] and r["error"] == "" and s.live() == []


# -- stop -----------------------------------------------------------------------------------------------------------
def test_stop_ends_a_watch_at_once_and_is_idempotent():
    s, factory, _, _ = service()
    wid = s.start(["net", "process"])["id"]
    watch = factory.made[0]
    assert plain(s.stop(wid)) == {"id": wid, "stopped": True, "error": ""}
    assert watch.stopped and watch.ended == 1
    assert plain(s.stop(wid)) == {"id": wid, "stopped": True, "error": ""}  # again: the same, nothing stopped twice
    assert watch.ended == 1
    with pytest.raises(LookupError):
        s.read(wid)  # its id let go
    assert plain(s.stop("0123456789abcdef")) == {"id": "0123456789abcdef", "stopped": True, "error": ""}
    with pytest.raises(LookupError, match=r"^a watch's id is the text watch_start gave: int 5 is not one$"):
        s.stop(5)
    ended = s.start(["file"])["id"]
    factory.made[1].end_on_its_own(PASSWORD)
    assert plain(s.stop(ended)) == {"id": ended, "stopped": True, "error": ""}  # one that ended: let go
    with pytest.raises(LookupError):
        s.read(ended)


def test_a_stop_that_raises_is_said_and_the_watch_still_let_go():
    s, factory, _, _ = service(raises=True)
    wid = s.start(["net"])["id"]
    assert plain(s.stop(wid)) == {"id": wid, "stopped": True, "error": "its stop said: its source would not close"}
    assert factory.made[0].stopped and s.live() == []


# -- the cap, and what ended ----------------------------------------------------------------------------------------
def test_at_most_eight_watches_run_at_once():
    s, factory, _, _ = service()
    assert CAP == 8 and inspect.signature(WatchService).parameters["cap"].default == CAP
    ids = [s.start(["net"])["id"] for _ in range(8)]
    with pytest.raises(ValueError) as refused:
        s.start(["net"])
    assert str(refused.value) == ("8 watches are running, the most at once here: stop one (watch_stop), or let one "
                                  "end by itself (20 s after its last read)")
    assert len(factory.made) == 8 and len(s.live()) == 8
    s.stop(ids[0])
    ids.append(s.start(["net"])["id"])  # one stopped: one more starts
    factory.made[3].end_on_its_own(PASSWORD)  # one ends on its own: its place is free at the next call
    assert not plain(s.start(["process"]))["stopped"]
    with pytest.raises(ValueError, match=r"^8 watches are running"):
        s.start(["process"])


def test_a_start_under_way_holds_its_place_under_the_cap():
    """Starts at the same moment (trapdoor and the Filter tabs, each a root bpftrace or an ETW session and a capture)
    count those still opening their source: the cap holds while they open."""
    opening, release = threading.Event(), threading.Event()
    clock, made = Clock(), []

    def factory(kinds, spec):  # the first watch's source opens slowly; the others' at once
        made.append(StandIn(kinds, spec, clock=clock, **({} if made else {"opening": opening, "release": release})))
        return made[-1]
    s = WatchService(factory, clock=clock, cap=1, system="linux")
    out = []
    starter = threading.Thread(target=lambda: out.append(s.start(["net"])))
    starter.start()
    try:
        assert opening.wait(5)  # the first start is under way, its source still opening
        with pytest.raises(ValueError, match=r"^1 watches are running, the most at once here"):
            s.start(["process"])
        assert len(made) == 1  # none made for the one refused
    finally:
        release.set()
        starter.join(5)
    [started] = out
    assert not started["stopped"] and len(s.live()) == 1


@pytest.mark.parametrize("call", ["start", "read", "stop", "live"])
def test_every_call_reaps_the_watches_that_ended(call):
    """Each of the service's calls moves the watches that ended out of the running ones first: their places under the
    cap are free at once, and their ends are kept to be read."""
    s, factory, _, _ = service(cap=2)
    other = s.start(["file"])["id"]
    wid = s.start(["net"])["id"]
    factory.made[-1].end_on_its_own(PASSWORD)
    assert list(s._live) == [other, wid]  # ended, not reaped yet: still counted
    {"start": lambda: s.start(["process"]),  # fits under the cap of two only once the one that ended is reaped
     "read": lambda: s.read(other), "stop": lambda: s.stop("0" * 16), "live": s.live}[call]()
    assert wid not in s._live and wid in s._ended
    assert plain(s.read(wid))["error"] == PASSWORD


def test_a_watch_that_ended_says_why_on_its_next_reads_for_a_while_then_is_let_go():
    s, factory, clock, _ = service(cap=2)
    wid = s.start(["net"])["id"]
    factory.made[0].feed("net", "connect", pid=900)
    factory.made[0].end_on_its_own(PASSWORD)  # bpftrace ended while the watch was wanted (sudo asked a password)
    for _ in range(2):  # every read in the while says it, so a second look is told too
        r = plain(s.read(wid))
        assert (r["stopped"], r["error"], [e["pid"] for e in r["events"]]) == (True, PASSWORD, [900])
    clock.t += ENDED_S
    with pytest.raises(LookupError, match=r"it ended over 60 s ago"):
        s.read(wid)
    # the ended ones kept are bounded: `cap` of them, the oldest let go first
    ended = []
    for _ in range(3):
        ended.append(s.start(["net"])["id"])
        factory.made[-1].end_on_its_own(PASSWORD)
        s.live()
    with pytest.raises(LookupError):
        s.read(ended[0])
    assert all(plain(s.read(e))["stopped"] for e in ended[1:])


# -- the plugin's detach, and the interpreter's exit ----------------------------------------------------------------
def test_stop_all_stops_every_watch_within_its_bound_and_never_raises():
    hold = threading.Event()
    clock = Clock()
    made = []

    def factory(kinds, spec):
        options = {"slow": {"hold": hold}, "raising": {"raises": True}}.get(spec.get("tag", ""), {})
        made.append(StandIn(kinds, spec, clock=clock, **options))
        return made[-1]
    s = WatchService(factory, clock=clock, system="linux")
    for tag in ("plain", "slow", "raising", "ended"):
        s.start(["net"], {"tag": tag})
    made[3].end_on_its_own(PASSWORD)
    assert STOP_ALL_S == 3.0 and inspect.signature(s.stop_all).parameters["wait"].default == STOP_ALL_S
    began = time.monotonic()
    assert s.stop_all(wait=0.3) == 3  # three were running; the slow one is still closing on its own thread
    assert time.monotonic() - began < 1.5
    assert all(w.stopped for w in made) and s.live() == []
    assert wait_for(lambda: [t.name for t in watch_threads()] == [watch_service.STOPPER])  # the slow one's, alone
    assert all(t.daemon for t in watch_threads())  # one still closing keeps no interpreter from exiting
    hold.set()
    assert wait_for(lambda: watch_threads() == [])
    assert s.stop_all() == 0  # nothing left
    s.start(["net"])  # usable again, for a later attach
    assert len(s.live()) == 1


def test_stop_all_stops_inline_where_no_thread_can_start(monkeypatch):
    s, factory, _, _ = service()
    s.start(["net"])
    s.start(["file"])

    def no_thread(self):
        raise RuntimeError("can't create new thread at interpreter shutdown")
    with monkeypatch.context() as m:
        m.setattr(watch_service.threading.Thread, "start", no_thread)
        assert s.stop_all() == 2
    assert all(w.stopped and w.ended == 1 for w in factory.made)


def test_a_start_under_way_when_every_watch_is_stopped_is_stopped_as_it_lands():
    opening, release = threading.Event(), threading.Event()
    s, factory, _, _ = service(opening=opening, release=release)
    out = []

    def start():
        try:
            out.append(s.start(["net"]))
        except ValueError as e:
            out.append(e)
    starter = threading.Thread(target=start)
    starter.start()
    assert opening.wait(5)  # its source is opening
    assert s.stop_all() == 0  # the plugin is detached meanwhile: nothing running yet
    release.set()
    starter.join(5)
    [refused] = out
    assert isinstance(refused, ValueError) and str(refused) == watch_service.LANDED_LATE
    assert factory.made[0].stopped and factory.made[0].ended == 1 and s.live() == []


def test_the_interpreters_exit_stops_what_is_left_and_holds_no_service_alive(monkeypatch, _nothing_real):
    # the module's own guard holds the services weakly: one let go is collected from it, kept alive by nothing
    assert isinstance(watch_service._SERVICES, weakref.WeakSet)
    dropped, _, _, _ = service()
    assert dropped in watch_service._SERVICES
    let_go = weakref.ref(dropped)
    _nothing_real.made.remove(dropped)  # the suite's own list lets it go too
    del dropped
    gc.collect()
    assert let_go() is None
    monkeypatch.setattr(watch_service, "_SERVICES", weakref.WeakSet())  # this test's services alone
    s, factory, _, _ = service()
    s.start(["net"])
    s.start(["process"])
    gone, _, _, _ = service()
    held = weakref.ref(gone)
    _nothing_real.made.remove(gone)  # the suite's own list lets it go too
    del gone
    gc.collect()
    assert held() is None  # the guard keeps no service alive
    watch_service._stop_left_at_exit()
    assert all(w.stopped for w in factory.made) and s.live() == []
    with pytest.raises(ValueError, match=r"^the platform is exiting: no watch is started now$"):
        s.start(["net"])  # and none starts after


def test_the_guard_is_registered_with_atexit_when_the_module_loads(monkeypatch):
    registered = []
    monkeypatch.setattr(atexit, "register", lambda func, *args, **kwargs: registered.append(func) or func)
    spec = importlib.util.spec_from_file_location("watch_service_copy", watch_service.__file__)
    copy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(copy)
    assert registered == [copy._stop_left_at_exit]


# -- plain JSON, whatever a source says -----------------------------------------------------------------------------
def test_every_answer_is_plain_json_whatever_a_source_puts_in_it():
    clock, made = Clock(), []

    class Counted(StandIn):
        def stats(self):
            return {"packets_dropped": 2, "rate": float("nan")}

    def factory(kinds, spec):
        made.append(Counted(kinds, spec, clock=clock))
        return made[-1]
    s = WatchService(factory, clock=clock, wall=Clock(WALL), system="linux")
    a = plain(s.start(["net"]))
    watch = made[0]
    watch.feed("net", "close", pid=4, program=b"curl", extra={"duration": float("inf"), "ids": {3, 1, 2},
                                                               "raw": b"\xff", "pair": (1, 2), "at": object})
    clock.t = float("nan")
    watch.feed("net", "close", pid=5)
    clock.t = 1001.0
    r = plain(s.read(a["id"]))
    first, second = r["events"]
    assert first["program"] == "curl" and first["at"] == WALL - 1.0
    assert first["extra"] == {"duration": None, "ids": [1, 2, 3], "raw": "\ufffd", "pair": [1, 2],
                              "at": str(object)}
    assert second["time"] is None and second["at"] is None  # a time that is no number is none, never NaN
    assert r["stats"] == {"packets_dropped": 2, "rate": None}
    plain(s.live())
    plain(s.stop(a["id"]))


# -- the library's own backends through the service, over stand-in sources ------------------------------------------
def bpftrace_line(**fields) -> str:
    """One line of bpftrace -f json, a script's printf of one event."""
    return json.dumps({"type": "printf", "data": json.dumps(fields)})


class FakeBpftrace:
    """A stand-in for sudo bpftrace: its lines, then nothing until it is killed (as a live one runs on)."""

    def __init__(self, lines):
        self._lines: queue.Queue = queue.Queue()
        for line in lines:
            self._lines.put(line)
        self.killed = threading.Event()

    @property
    def stdout(self):
        return self

    def __iter__(self):
        return self

    def __next__(self):
        while True:
            try:
                return self._lines.get(timeout=0.02)
            except queue.Empty:
                if self.killed.is_set():
                    raise StopIteration from None

    def kill(self):
        self.killed.set()


class EndedBpftrace:
    """sudo bpftrace that ended on its own: its last words, the end of its stream, its exit code."""

    def __init__(self, lines, code=1):
        self.stdout, self.code = list(lines), code

    def terminate(self):
        pass

    def kill(self):
        pass

    def wait(self, timeout=None):
        return self.code


def test_the_linux_backend_answers_through_the_service():
    clock, argvs = Clock(), []
    procs = [FakeBpftrace([bpftrace_line(evt="process", act="exec", pid=901, ppid=900, comm="sh", path="/bin/sh"),
                           bpftrace_line(evt="file", act="open", pid=901, comm="sh", path="/etc/hosts", flags=0)]),
             EndedBpftrace([b"sudo: a password is required\n"])]

    def runner(argv):
        argvs.append(argv)
        return procs[len(argvs) - 1]
    s = WatchService(lambda kinds, spec: make_watch(kinds, spec, system="linux", runner=runner, clock=clock),
                     clock=clock, wall=Clock(WALL), system="linux")
    a = plain(s.start(["process", "file"], {"pid": 4242}))
    assert a["system"] == "linux" and not a["stopped"]
    assert argvs[0][:6] == ["sudo", "-n", "bpftrace", "-f", "json", "-e"] and argvs[0][-1] == "4242"  # the spec's pid
    assert wait_for(lambda: s.read(a["id"])["seq"] == 2)
    r = plain(s.read(a["id"]))
    assert [(e["kind"], e["action"], e["pid"], e["path"]) for e in r["events"]] == [
        ("process", "exec", 901, "/bin/sh"), ("file", "open", 901, "/etc/hosts")]
    assert r["events"][1]["extra"] == {"flags": 0} and all(e["at"] == WALL for e in r["events"])
    s.stop(a["id"])
    assert procs[0].killed.is_set()
    # sudo wanted a password: bpftrace ended at once, after the start answered; the next read says why
    b = plain(s.start(["net"]))
    assert wait_for(lambda: s.read(b["id"])["stopped"])
    r = plain(s.read(b["id"]))
    assert r["error"] == PASSWORD and s.live() == []


class FakeEtw:
    """A stand-in ETW consumer: `feed` queues records, `drain` hands them over. No session is started."""

    def __init__(self, providers):
        self.providers = tuple(providers)
        self._records: list = []
        self._lock = threading.Lock()
        self.started = self.stopped = False

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True

    def feed(self, *records):
        with self._lock:
            self._records.extend(records)

    def drain(self, limit=None):
        with self._lock:
            out, self._records = self._records, []
        return out


class FakeCapture:
    """A stand-in capture: the watch sets on_packet; `feed` hands it a packet as an adapter would. Nothing opened."""

    def __init__(self):
        self.on_packet = None
        self.started = self.stopped = False

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True

    def feed(self, packet):
        self.on_packet(packet)


def test_the_windows_backend_answers_through_the_service(monkeypatch):
    monkeypatch.setattr(world, "route_address", lambda: "10.0.0.2")
    clock, made = Clock(), {}

    def etw_factory(providers):
        made["etw"] = FakeEtw(providers)
        return made["etw"]

    def capture_factory():
        made["capture"] = FakeCapture()
        return made["capture"]

    def factory(kinds, spec):
        made["spec"] = spec
        return make_watch(kinds, spec, system="windows", etw_factory=etw_factory, capture_factory=capture_factory,
                          clock=clock)
    s = WatchService(factory, clock=clock, wall=Clock(WALL), system="windows")
    a = plain(s.start(["net", "process"], {"poll": 0.05}))
    assert (a["system"], a["address"]) == ("windows", "10.0.0.2") and made["spec"] == {"poll": 0.05,
                                                                                      "address": "10.0.0.2"}
    assert made["etw"].started and made["capture"].started and made["etw"].providers == ("network", "process")
    made["etw"].feed(EtwRecord(at=1.0, provider="process", event_id=1, opcode=0, pid=4,
                               props={"ProcessID": 1000, "ParentProcessID": 4, "ImageName": r"C:\tools\curl.exe"}),
                     EtwRecord(at=1.0, provider="network", event_id=12, opcode=0, pid=1000,
                               props={"PID": 1000, "saddr": "10.0.0.2", "sport": 51000, "daddr": "203.0.113.7",
                                      "dport": 443}))
    assert wait_for(lambda: s.read(a["id"])["seq"] >= 1)
    made["capture"].feed(Packet(1.0, "10.0.0.2", 51000, "203.0.113.7", 443, Flags("SYN"), 4, "tcp", 74, "out"))
    assert wait_for(lambda: any(e["kind"] == "net" for e in s.read(a["id"])["events"]))
    r = plain(s.read(a["id"]))
    start = next(e for e in r["events"] if e["kind"] == "process")
    assert (start["action"], start["pid"], start["program"]) == ("start", 1000, "curl.exe")
    net = next(e for e in r["events"] if e["kind"] == "net")
    assert (net["action"], net["pid"], net["program"], net["local"], net["remote"]) == (
        "out", 1000, "curl.exe", "10.0.0.2:51000", "203.0.113.7:443")
    assert r["stats"] == {"packets_dropped": 0, "etw_dropped": 0, "etw_events_lost": 0, "flows_open": 1}
    s.stop(a["id"])
    assert made["etw"].stopped and made["capture"].stopped
