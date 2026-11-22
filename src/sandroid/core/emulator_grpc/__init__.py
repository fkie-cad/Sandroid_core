"""Android emulator gRPC: live screen frames and input for the device column.

Layout (only ``client`` needs the optional ``screen`` extra):

* :mod:`.support` -- grpc-free: endpoint discovery, the zero-copy frame
  parser, layout-safe typing, rotation mapping, :class:`ScreenRpcError`.
* :mod:`.client` -- the gRPC client (imports grpcio/protobuf; import it
  lazily).
* ``emulator_controller_pb2*.py`` -- vendored generated stubs of the AOSP
  ``emulator_controller.proto`` (Apache-2.0, see ``NOTICE``).
* This module: :func:`install_launch_hooks`, the pre-launch hook that starts
  every emulator Sandroid launches with ``-grpc <port> -grpc-use-token``.

Importing this package is cheap (no grpc, no numpy).
"""

from __future__ import annotations

import importlib.util
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sandroid.core.emulator import LaunchContext

logger = logging.getLogger(__name__)

#: The gRPC port of an emulator is its console port + this (5554 -> 8554),
#: probed upward when taken. The client never relies on the formula: it
#: reads the real port from the emulator's discovery file.
GRPC_PORT_OFFSET = 3000
#: How many ports above console+offset the hook tries.
GRPC_PORT_PROBES = 64
#: Key of this hook's entry in the launch record (``hooks``).
RECORD_KEY = "device_screen_grpc"


def grpc_available() -> bool:
    """True if grpcio and protobuf are installed (found, not imported)."""
    try:
        return (
            importlib.util.find_spec("grpc") is not None
            and importlib.util.find_spec("google.protobuf") is not None
        )
    except (ImportError, ValueError):
        return False


def _grpc_on_launch() -> bool:
    """Config ``tui.device_screen.grpc_on_launch`` (default True)."""
    try:
        from sandroid.config import get_config

        return bool(get_config().tui.device_screen.grpc_on_launch)
    except Exception as exc:
        logger.debug(f"device screen: config unreadable ({exc}); gRPC stays on")
        return True


def _has_grpc_flag(args: tuple[str, ...] | list[str]) -> bool:
    """The launch already configures gRPC (``-grpc``, ``-grpc-use-token``...)."""
    return any(str(a) == "-grpc" or str(a).startswith("-grpc-") for a in args)


def pick_grpc_port(console_port: int) -> int | None:
    """A bindable port for ``-grpc``: console + 3000, else the next free one."""
    from sandroid.core.emulator import _port_bindable

    start = console_port + GRPC_PORT_OFFSET
    for port in range(start, min(start + GRPC_PORT_PROBES, 65536)):
        if _port_bindable(port):
            return port
    return None


def pre_launch(context: LaunchContext) -> tuple[str, ...]:
    """Pre-launch hook: ``-grpc <port> -grpc-use-token`` (never raises).

    A raising hook would abort the launch, so every failure returns ``()``
    (the emulator then simply has no live screen). Skipped when the launch
    options already carry a ``-grpc*`` flag (an emulator started outside
    Sandroid keeps its own across a restart), when the console port is
    unknown, when the ``screen`` extra is not installed, or when config
    ``tui.device_screen.grpc_on_launch`` is false.
    """
    try:
        options = getattr(context, "options", None)
        extra = tuple(getattr(options, "extra_args", ()) or ())
        if _has_grpc_flag(extra):
            return ()
        port = getattr(context, "port", None)
        if port is None:
            return ()
        if not grpc_available() or not _grpc_on_launch():
            return ()
        grpc_port = pick_grpc_port(int(port))
        if grpc_port is None:
            logger.info(
                f"device screen: no free gRPC port near {int(port) + GRPC_PORT_OFFSET}"
                f" for AVD '{context.avd}'; it starts without a live screen"
            )
            return ()
        try:
            context.record[RECORD_KEY] = grpc_port
        except Exception:
            pass
        return ("-grpc", str(grpc_port), "-grpc-use-token")
    except Exception as exc:
        logger.debug(f"device screen: gRPC launch hook skipped ({exc})")
        return ()


def install_launch_hooks() -> None:
    """Register :func:`pre_launch` with the emulator launcher (idempotent).

    Call at startup before any launch path runs (``cli.py``, ``tui/app.py``).
    """
    from sandroid.core import emulator

    emulator.register_pre_launch_hook(pre_launch)


def uninstall_launch_hooks() -> None:
    """Undo :func:`install_launch_hooks` (no-op when not registered)."""
    from sandroid.core import emulator

    emulator.unregister_pre_launch_hook(pre_launch)


__all__ = [
    "GRPC_PORT_OFFSET",
    "grpc_available",
    "install_launch_hooks",
    "pick_grpc_port",
    "pre_launch",
    "uninstall_launch_hooks",
]
