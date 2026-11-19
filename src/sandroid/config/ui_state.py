"""Small UI state that is remembered between runs but is not configuration.

Things such as the AI chat dock's size live in ``tui_state.json`` next to the
user config (``$XDG_CONFIG_HOME/sandroid`` or ``~/.config/sandroid``), never
in a config file: saving them through the config loader used to copy the
whole merged configuration -- secrets included -- into whichever config file
was found first. The file is owner-only (0600), written atomically, and only
ever holds the keys written through :func:`update_ui_state`. Its name is not
one the config discovery loads.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

from .loader import atomic_write_bytes

logger = logging.getLogger(__name__)

#: File name inside the user config directory.
UI_STATE_FILE = "tui_state.json"

_lock = threading.Lock()


def ui_state_path() -> Path:
    """``$XDG_CONFIG_HOME/sandroid/tui_state.json`` (or ``~/.config/...``)."""
    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / "sandroid" / UI_STATE_FILE


def load_ui_state(path: Path | None = None) -> dict[str, Any]:
    """The remembered UI state (``{}`` when missing or unreadable)."""
    path = path or ui_state_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except Exception:
        logger.debug("unreadable %s", path, exc_info=True)
        return {}
    return data if isinstance(data, dict) else {}


def update_ui_state(key: str, value: Any, path: Path | None = None) -> Path:
    """Set one top-level ``key`` (``None`` removes it); returns the file path.

    ``value`` must be JSON-serialisable. Safe to call from worker threads.
    """
    path = path or ui_state_path()
    with _lock:
        data = load_ui_state(path)
        if value is None:
            data.pop(key, None)
        else:
            data[key] = value
        payload = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
        atomic_write_bytes(path, payload, mode=0o600)
    return path


__all__ = ["UI_STATE_FILE", "load_ui_state", "ui_state_path", "update_ui_state"]
