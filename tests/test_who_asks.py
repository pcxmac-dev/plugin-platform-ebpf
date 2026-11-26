"""Who may ask the plugin's changes, its reads as root and its watch service (0.1.2, the sweep after the review's
PLT-H1, 2026-11-25; 0.1.3, the user's choice of 2026-11-25: show_program and dump, read through sudo -n, the page's
too). Its changes are asked only from its page (PAGE_ONLY_HOOKS, as liminal-libs 1.66.0's apps/asking.py and
liminal-platform 0.34.0 read them): a program loaded into the kernel, attached, detached or unloaded, as root through
sudo -n. Another plugin's ask is refused, and so is an ask that names no one; over HTTP the platform also asks its login
whether you are at the page. Its watch service is asked only by another plugin (PLUGIN_ONLY_HOOKS), as it was built to
be: the page's ask and an ask that names no one are refused. Before, any program on this PC asked either with two
headers: where sudo runs bpftool without a password a program was loaded into the kernel as root, its second
confirmation (accept_load) being only an argument, and on any machine a watch was started and all it saw read. Its other
reads are asked by anyone, as before. Asked through the library's own App (its ask names who asks as the platform's
does), over conftest's stand-in machines and watches: nothing runs."""
from __future__ import annotations

import pytest

pytest.importorskip("liminal_libs.apps.asking", reason="no hook is held to who asks it before liminal-libs 1.66.0")

from liminal_libs import internal  # noqa: E402 - after the skip, as each of these
from liminal_libs.apps import App, asking  # noqa: E402
from liminal_libs.apps.authorization import EnvironmentLogin  # noqa: E402
from liminal_libs.machines.plugin import MachinePlugin  # noqa: E402
from plugin_platform_ebpf import MACHINE  # noqa: E402

CHANGES = ("load_program", "attach_program", "detach_program", "unload_program")
WATCHES = ("watch_start", "watch_read", "watch_stop")
ROOT_READS = ("show_program", "dump")  # reads as root through sudo -n: the page's alone since 0.1.3
READS = ("present", "status", "refresh", "compare", "functions")
LOAD = ("/home/you/drop.o", None, "xdp", True)  # a load with its second confirmation said, as a program would send it
PIN = "/sys/fs/bpf/liminal_drop"
ASKS = {  # each change as an ask, and the command it runs as root when its page asks it
    "load_program": (LOAD, ["bpftool", "prog", "load", "/home/you/drop.o", PIN, "type", "xdp"]),
    "attach_program": (("xdp", "eth0", PIN, None, None, None, False, True),  # XDP on eth0, its confirmation said too
                       ["bpftool", "net", "attach", "xdp", "pinned", PIN, "dev", "eth0"]),
    "detach_program": ((7,), ["bpftool", "link", "detach", "id", "7"]),
    "unload_program": (("/sys/fs/bpf/sd_devices", True),  # a pin that is not Liminal's, its confirmation said
                       ["rm", "-f", "/sys/fs/bpf/sd_devices"]),
}


class Neighbour(MachinePlugin):
    """Another plugin of the platform, asking the eBPF plugin through its app as any plugin may (a firewall's Filter
    tab, trapdoor, or the MCP plugin for a local agent)."""

    name, title = "neighbour", "Neighbour"

    def wants(self, hook, *args):
        """Not a hook: one of the eBPF plugin's asked through the app."""
        return self.app.ask("ebpf", hook, *args)


class Platform(App):
    """The library's App asking as the platform does: from its page's route, the page named in so many words, or from
    its own code, no one named."""

    NAME, TITLE, ICON = "platform", "Platform", "chip"

    def from_page(self, hook, *args):
        """As the page's route asks a hook."""
        with asking.asking(asking.PAGE):
            return self.ask("ebpf", hook, *args)

    def on_its_own(self, hook, *args):
        """As the app's own code asks a hook."""
        return self.ask("ebpf", hook, *args)


@pytest.fixture
def attached():
    """attach(plugin) -> (app, neighbour): the plugin attached with another plugin to an app, the read its attach began
    done; each let go after the test."""
    held: list[tuple[Platform, Neighbour, object]] = []

    def attach(p):
        app, neighbour = Platform(log=lambda m: None, login=EnvironmentLogin(env={})), Neighbour()
        app.attach(p)
        app.attach(neighbour)
        held.append((app, neighbour, p))
        assert p.snapshot(wait=5) is not None
        return app, neighbour
    yield attach
    for app, neighbour, p in held:
        app.detach(neighbour.name)
        app.detach(p.name)


def test_its_changes_are_said_to_be_the_pages_its_watches_another_plugins_and_its_reads_anyones():
    assert set(ASKS) == set(CHANGES)
    assert set(internal.page_only(MACHINE)) == {*CHANGES, *ROOT_READS}  # what the platform reads
    assert set(internal.plugin_only(MACHINE)) == set(WATCHES)
    assert internal.problems(MACHINE) == []  # each a hook of its own, none in both words, no tab's among the watches
    assert set(MACHINE.HOOKS) >= {*CHANGES, *ROOT_READS, *WATCHES, *READS}
    nobody = "This ask names no asker: neither the page nor a plugin."
    for hook in (*CHANGES, *ROOT_READS):
        assert asking.refusal(MACHINE, hook, asking.PAGE) == ""
        assert asking.refusal(MACHINE, hook, "neighbour") == (f"ebpf's {hook} is asked only from its page, never by "
                                                              "another plugin: neighbour asked it.")
        assert asking.refusal(MACHINE, hook, None) == f"ebpf's {hook} is asked only from its page. {nobody}"
    for hook in WATCHES:
        assert asking.refusal(MACHINE, hook, "neighbour") == ""
        assert asking.refusal(MACHINE, hook, asking.PAGE) == (f"ebpf's {hook} is asked only by another plugin, never "
                                                              "from a page or by a program.")
        assert asking.refusal(MACHINE, hook, None) == f"ebpf's {hook} is asked only by another plugin. {nobody}"
        assert asking.refusal(MACHINE, hook, "ebpf") == (f"ebpf's {hook} is asked only by another plugin, not by ebpf "
                                                         "itself.")
    for hook in READS:
        assert {asking.refusal(MACHINE, hook, who) for who in (asking.PAGE, "neighbour", None)} == {""}


def test_another_plugin_or_no_one_asking_a_change_runs_nothing_and_its_page_does(linux, attached):
    """On a Linux where sudo runs bpftool without a password, so a change asked runs as root at once: each of the four,
    asked by another plugin and by no one with every confirmation said, runs and reads nothing; asked from the page,
    it runs."""
    p, fake, _ = linux()
    app, neighbour = attached(p)
    fake.commands.clear()
    for hook in CHANGES:
        args, _ = ASKS[hook]
        for ask in (lambda: neighbour.wants(hook, *args), lambda: app.on_its_own(hook, *args)):
            with pytest.raises(asking.AskRefused, match=f"ebpf's {hook} is asked only from its page") as refused:
                ask()
            assert refused.value.status == 403 and refused.value.hook == hook
    assert fake.commands == [] and fake.changes == []  # nothing run as root, and nothing read
    assert neighbour.wants("present") is True and neighbour.wants("status")["valid"]  # its reads, as before
    assert len(neighbour.wants("functions")["tables"][0]["rows"]) == 9 and neighbour.wants("refresh")["ok"]
    assert fake.changes == []
    for hook in CHANGES:  # its page's form, each confirmation said: run as root, through sudo -n
        args, command = ASKS[hook]
        assert app.from_page(hook, *args)["ok"] is True
        assert fake.changes[-1] == (True, command)
    assert len(fake.changes) == len(CHANGES)


def test_its_reads_as_root_are_the_pages_alone(linux, attached):
    """A program shown and a map dumped, each bpftool as root through sudo -n (0.1.3): asked by another plugin or by no
    one, refused with nothing run; asked from the page (the Functions tab's forms), answered as before."""
    p, fake, _ = linux()
    app, neighbour = attached(p)
    fake.commands.clear()
    asks = {"show_program": (31,), "dump": (3,)}
    for hook, args in asks.items():
        for ask in (lambda: neighbour.wants(hook, *args), lambda: app.on_its_own(hook, *args)):
            with pytest.raises(asking.AskRefused, match=f"ebpf's {hook} is asked only from its page") as refused:
                ask()
            assert refused.value.status == 403 and refused.value.hook == hook
    assert fake.commands == []  # nothing read as root
    assert app.from_page("show_program", 31)["said"] == "program 31: liminal_drop, xdp"
    assert app.from_page("dump", 3)["said"] == "map 3: 2 entries"
    assert fake.commands and any(root for root, _ in fake.commands) and fake.changes == []


@pytest.mark.parametrize("system", ["linux", "windows"])
def test_the_watch_service_is_another_plugins_alone_never_the_pages_or_no_ones(system, linux, windows, attached):
    """On Linux, where a watch is bpftrace as root, and on Windows, where it is a capture and ETW's sessions, which this
    PC opens unelevated: the page's ask and an ask that names no one start, read and stop nothing; another plugin's
    does each, as the firewalls' Filter tabs and trapdoor are to."""
    p, _, factory = linux() if system == "linux" else windows(reclaim=lambda: None)
    app, neighbour = attached(p)
    for ask in (lambda: app.from_page("watch_start", ["process"]), lambda: app.on_its_own("watch_start", ["process"]),
                lambda: app.from_page("watch_start", ["process", "file"], {"pid": 4242})):
        with pytest.raises(asking.AskRefused, match="ebpf's watch_start is asked only by another plugin") as refused:
            ask()
        assert refused.value.status == 403
    assert factory.asked == [] and factory.made == []  # no watch made: on Linux a bpftrace would have been started
    started = neighbour.wants("watch_start", ["process"], {"pid": 4242})
    assert started["kinds"] == ["process"] and started["system"] == system and not started["stopped"]
    assert factory.asked == [(frozenset({"process"}), {"pid": 4242})]
    factory.made[0].feed("process", "exec", pid=7, ppid=1, program="sh", path="/bin/sh")
    for hook in ("watch_read", "watch_stop"):  # its id in hand, the page and no one still read and stop nothing
        for ask in (lambda: app.from_page(hook, started["id"]), lambda: app.on_its_own(hook, started["id"])):
            with pytest.raises(asking.AskRefused, match=f"ebpf's {hook} is asked only by another plugin"):
                ask()
    assert not factory.made[0].stopped
    assert neighbour.wants("watch_read", started["id"])["events"][0]["path"] == "/bin/sh"
    assert neighbour.wants("watch_stop", started["id"]) == {"id": started["id"], "stopped": True, "error": ""}
    assert factory.made[0].stopped and len(factory.made) == 1
