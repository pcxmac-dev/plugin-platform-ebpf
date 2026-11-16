"""What the README and the CHANGELOG tell a caller and the user, where the fix is in their words (the plugin's own
behaviour is tested beside its code): the watch service's asks are logged by the platform until its deferred change; a
spec's pid is the kernel's numbering inside WSL; a lost Windows source is not said yet; root's rights are each
command's, a dump running sh and an unload rm; the bpftool advice for WSL is Ubuntu's alone. Read as text, nothing
run."""
from __future__ import annotations

import re
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent


def words(name: str) -> str:
    """A file's text with its line breaks and runs of spaces as one space, as it reads."""
    return re.sub(r"\s+", " ", (HERE / name).read_text(encoding="utf-8"))


def test_the_readme_says_each_watch_ask_is_logged_until_the_platforms_change():
    readme = words("README.md")
    assert "every `watch_start`, `watch_read` and `watch_stop` writes a line to the platform's log" in readme
    assert "logs/platform.log" in readme and "never their values" in readme
    assert "Connections shows the platform asking, not the caller" in readme
    assert "Read no more often than needed" in readme and "`MachinePlugin.SERVICE_READS`" in readme


def test_the_readme_says_a_spec_pid_is_the_kernels_numbering_inside_wsl():
    readme = words("README.md")
    assert ("It is matched against bpftrace's pid, the kernel's numbering: inside a WSL distribution (a pid namespace "
            "of its own) that is not the pid ps shows there") in readme
    assert "a watch's spec `pid` is matched against the kernel's too" in readme  # Inside WSL's What is seen


def test_the_readme_says_a_windows_source_lost_after_it_opened_is_not_said_yet():
    readme = words("README.md")
    assert ("On Windows a capture or an ETW session lost after it opened (an adapter removed, a session stopped from "
            "outside) is not said yet") in readme
    assert "the plugin's facts call its watches started, not reading" in readme


def test_the_readme_says_root_is_read_from_each_command_a_dump_running_sh_and_an_unload_rm():
    readme = words("README.md")
    assert "Root's rights are read from what each of these runs, never from one check" in readme
    assert "A dump and an unload then need sh and rm too" in readme
    assert "let sudo run bpftool without a password" not in readme  # the advice that left the dump refused


def test_the_bpftool_advice_for_wsl_is_said_as_ubuntus_alone():
    readme, changelog = words("README.md"), words("CHANGELOG.md")
    assert "the usual advice (the distribution's bpftool package) does not hold under WSL." not in readme
    assert "On Ubuntu, and a distribution like it (/etc/os-release's ID or ID_LIKE)" in readme
    assert "Elsewhere (Fedora, Debian, Gentoo) the distribution's own bpftool package is a plain binary" in readme
    assert "on Ubuntu, bpftool with no build for a WSL kernel" in changelog
    assert "bpftool with no build for that kernel" not in changelog
