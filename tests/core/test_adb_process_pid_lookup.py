"""get_pid_for_package_name must match the app's main process exactly.

Live regression (API 36, right after ``am force-stop com.android.chrome``):
``pidof`` returned nothing, the ``ps -A`` fallback substring-matched the
still-alive ``com.android.chrome_zygote`` and friTap attached to it.
"""

from __future__ import annotations

from sandroid.core.adb_process import get_pid_for_package_name

PS_A = """\
USER           PID  PPID        VSZ    RSS WCHAN            ADDR S NAME
u0_a153       4002   462   6522012  90116 do_sys_poll         0 S com.android.chrome_zygote
u0_i1         7082  4002   6800000  80000 do_epoll_wait       0 S com.android.chrome:sandboxed_process0:org.chromium.content.app.SandboxedProcessService0:0
u0_a153       7108   462   6900000  90000 do_epoll_wait       0 S com.android.chrome:privileged_process0
"""


def _send(ps_a: str):
    def send(command):
        if command.startswith("shell pidof"):
            return "", ""
        if command == "shell ps -A":
            return ps_a, ""
        if command == "shell ps -o PID,NAME":
            rows = [line.split() for line in ps_a.splitlines()]
            return "\n".join(f"{r[1]} {r[-1]}" for r in rows), ""
        raise AssertionError(command)

    return send


def test_helper_processes_are_not_the_app():
    assert (
        get_pid_for_package_name(
            _send(PS_A), "com.android.chrome", use_frida_fallback=False
        )
        is None
    )


def test_main_process_is_found_by_exact_name():
    ps_a = PS_A + "u0_a153       7023   462   7000000 99999 do_epoll_wait 0 S com.android.chrome\n"
    assert (
        get_pid_for_package_name(
            _send(ps_a), "com.android.chrome", use_frida_fallback=False
        )
        == 7023
    )
