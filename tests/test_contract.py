"""The plugin conforms to the class contract (plugin API 2.2): liminal_libs.sources.conformance, read from the plugin
alone (nothing runs). A machine plugin of the platform, drawn under its OS plugins after the two firewalls, its icon
eBPF's own mark, its two tabs read hooks it answers."""
from __future__ import annotations

import re

import plugin_platform_ebpf as module
from liminal_libs.apps.tabs import Tab
from liminal_libs.sources.conformance import assert_module_conforms


def test_the_plugin_conforms_to_the_class_contract():
    found = assert_module_conforms(module)
    assert [p.name for p in found] == ["ebpf"] and all(p.api == "2.2" and not p.is_record for p in found)
    assert {p.SYSTEM for p in found} == {"platform"} and {p.KIND for p in found} == {"machine"}
    assert all(p.apis and p.interface()["apis"] == [a.name for a in p.apis] for p in found)  # what it attaches to (2.2)


def test_each_call_on_its_cards_names_one_of_its_cards_own_parts():
    """A card's calls each belong to one of its parts (sources.apis: Call.area), which problems() does not check."""
    for api in module.MACHINE.apis:
        areas = {a.name for a in api.areas}
        assert all(c.area in areas for c in api.calls), (api.name, [c.name for c in api.calls if c.area not in areas])


MARKED = (1, 60, 0)  # the liminal-libs release whose icons.js carries eBPF's bee


def release(version: str) -> tuple[int, ...]:
    """A release's number as a tuple ("1.58.0" -> (1, 58, 0)), what follows its digits (a suffix) left out."""
    return tuple(int(re.match(r"\d*", part).group() or 0) for part in str(version).split(".")[:3])


def test_its_icon_is_its_makers_mark_drawn_by_the_library():
    """eBPF's bee, the maker's mark (the user's rule: a plugin's icon is its maker's mark), in liminal-libs' icons.js
    from 1.60.0, the plugin's floor: a mark that is missing, or drawn under another name, fails it."""
    import liminal_libs
    from liminal_libs.ui import STATIC

    assert release(module.LIBS_FLOOR) == MARKED  # the floor (pyproject's, LIBS_FLOOR) is the release with the mark
    assert release(liminal_libs.__version__) >= MARKED
    assert {p.ICON for p in assert_module_conforms(module)} == {"ebpf"}
    drawn = set(re.findall(r"^\s*([a-z]+):\s*'", (STATIC / "icons.js").read_text(encoding="utf-8"), re.M))
    assert "ebpf" in drawn, f"liminal-libs {liminal_libs.__version__} draws no ebpf mark: the page draws the plug"


def test_releases_are_told_apart_by_their_numbers():
    assert release("1.58.0") < MARKED <= release("1.60.0") <= release("1.61.2") and release("2.0.0") > MARKED
    assert release("1.60.0rc1") == (1, 60, 0) and release("1.59") == (1, 59)


def test_it_is_drawn_under_the_platforms_os_plugins_after_the_firewalls():
    """Its section of the platform's list (liminal-platform 0.26.0; the user, 2026-11-15: "then OS plugins"), beside the
    WSL, admin and firewall plugins: after the Windows (710) and the Linux (711) firewalls."""
    assert {(p.SECTION, p.order) for p in assert_module_conforms(module)} == {("os", 712)}


def test_its_tabs_are_compare_and_functions_each_a_hook_it_answers():
    """Its own tabs after Main and API (apps/tabs.py): Compare, asked every 30 s while it is shown, and Functions, every
    5 s; each a hook it lists and answers itself, and a read (not the setup, a command, the settings or the scan)."""
    p = module.MACHINE
    assert p.TABS == (Tab("compare", "Compare", "compare", 30.0), Tab("functions", "Functions", "functions", 5.0))
    hooks = p.interface()["hooks"]
    assert all(t.hook in p.HOOKS and t.hook in hooks for t in p.TABS)
    assert {"setup", "run", "instances", "scan", "settings"}.isdisjoint(hooks)  # none it does not answer
    assert set(hooks) == {"present", "status", "refresh", "compare", "functions", "show_program", "dump",
                          "load_program", "attach_program", "detach_program", "unload_program", "watch_start",
                          "watch_read", "watch_stop"}


def test_a_copy_the_registry_hands_out_shares_what_the_plugin_keeps():
    """The registry hands out a shallow copy (with_): its read, its watches and whether it was detached are the same
    for both, so a watch one starts is the other's to read and stop."""
    p = module.EbpfPlugin(system="linux")
    copy = p.with_(origin="test")
    assert copy is not p and copy._rt is p._rt and copy._rt.service is p._rt.service
