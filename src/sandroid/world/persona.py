"""A persona: one identity profile's world on one AVD, kept as a snapshot.

The identity profile is the truth: its ``owner`` and ``world`` sections (and
the resolved ``world.seed``) decide the manifest. The persona snapshot is a
validated cache of "clean base + the world seeded + the identity applied";
when it is missing or stale, it is built again from the profile.

Order of a build (the caller runs it, off the UI thread)::

    manifest, profile = manifest_for_profile(pid)
    prepare(serial, manifest)                 # sandroid.world.prepare
    get_identity_service().apply(serial, profile=profile)
    save_persona_snapshot(serial, avd, persona_name(profile, manifest))

Snapshots are saved and deleted as the ``persona`` actor
(:mod:`sandroid.core.snapshot_policy`): nobody else may overwrite them, and
a save never lands on a pinned base such as ``clean_8g``. Only the newest
``world.persona_snapshots`` (default :data:`DEFAULT_KEEP`) persona snapshots
of an AVD are kept; each holds about 2.8 GB.

Starting an AVD as a persona (:func:`persona_start`, the Devices screen's
Shift+P) loads the profile's current persona snapshot, else the clean base
and the persona stage builds it. A loaded snapshot is topped up with the
world's SMS, calls and events up to now (:func:`after_load_topup`,
``world.persona_topup``, default on). :func:`refresh_persona` (the Identity
lens' Shift+W) brings a running persona up to its edited profile, changing
only what differs from the host ledger.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from sandroid.world.helper import Device
from sandroid.world.prepare import STAMP_FORMAT, STAMP_PATH, persona_snapshot_name

if TYPE_CHECKING:
    from sandroid.services.identity import IdentityService, Profile
    from sandroid.world.manifest import WorldManifest
    from sandroid.world.packs import PackSet

logger = logging.getLogger(__name__)

#: Prefix of every persona snapshot (the ``persona`` namespace).
PERSONA_PREFIX = "sandroid_persona_"
#: Persona snapshots kept per AVD unless the config says otherwise.
DEFAULT_KEEP = 3
#: The persona actor of the snapshot policy.
ACTOR = "persona"
#: The launch-record meta key naming the persona (an identity profile id).
META_KEY = "persona_id"
#: The base snapshot a persona is built on unless ``meta.persona_base`` says.
DEFAULT_BASE = "clean_8g"
#: Seconds left that the identity apply (a framework restart) and the
#: snapshot save need; with less, the step is skipped, not started late.
APPLY_RESERVE_S = 200.0  # one framework-restart window (180 s) and margin
SAVE_RESERVE_S = 20.0

_BUILT_LOCK = threading.Lock()
#: Launch ids the stage built (or tried to build) a persona on.
_BUILT_LAUNCHES: set[str] = set()


class PersonaError(RuntimeError):
    """A persona cannot be built or saved."""


@dataclass
class PersonaSave:
    """What :func:`save_persona_snapshot` did.

    Attributes:
        name: The snapshot.
        saved: The snapshot was saved and is loadable.
        pruned: Older persona snapshots deleted to stay within ``keep``.
        kept: Persona snapshots of the AVD after pruning, newest first.
        error: Why the save failed (``saved`` False).
        warnings: Prune failures and the like.
    """

    name: str
    saved: bool = False
    pruned: list[str] = field(default_factory=list)
    kept: list[str] = field(default_factory=list)
    error: str = ""
    warnings: list[str] = field(default_factory=list)


def manifest_for_profile(
    profile_id: str,
    *,
    service: IdentityService | None = None,
    packs: PackSet | None = None,
    target_sdk: int | None = None,
) -> tuple[WorldManifest, Profile]:
    """Generate the world of identity profile ``profile_id``.

    ``world.seed: auto`` is resolved (and written back to the profile) once,
    so the same profile always yields the same world. The owner's phone and
    e-mail templates are rendered with the profile's token.

    Args:
        profile_id: The profile in the identity library.
        service: The identity service (tests); default a new one.
        packs: The packs; default the built-in and user packs.
        target_sdk: The device's API level (for the persona phone model).

    Returns:
        ``(manifest, profile)``; the profile as loaded after the seed was
        resolved.

    Raises:
        PersonaError: The profile has no ``world`` section, or its owner
            cannot be rendered.
        sandroid.world.WorldError: The world spec is invalid.
    """
    from sandroid.services.identity import (
        TemplateError,
        get_identity_service,
        render_owner,
    )
    from sandroid.world.generator import generate

    svc = service or get_identity_service()
    seed = svc.resolve_world_seed(profile_id)
    if not seed:
        raise PersonaError(f"identity profile {profile_id!r} has no world section")
    profile = svc.load(profile_id)
    spec = dict(profile.world)
    spec["seed"] = seed
    try:
        owner = render_owner(profile)
    except TemplateError as exc:
        raise PersonaError(f"profile {profile_id!r}: owner: {exc}") from exc
    if not owner.get("first") or not owner.get("last"):
        raise PersonaError(
            f"profile {profile_id!r}: the world needs the owner's first and last name"
        )
    return generate(spec, owner, packs=packs, target_sdk=target_sdk), profile


def persona_name(profile: Profile, manifest: WorldManifest) -> str:
    """The snapshot name of ``profile`` with ``manifest`` (both fingerprints)."""
    from sandroid.services.identity import fingerprint

    return persona_snapshot_name(profile.id, manifest.world_fp, fingerprint(profile))


def configured_keep() -> int:
    """The config's ``world.persona_snapshots`` (at least 1; default 3).

    ``world`` is not a schema section yet; read defensively like
    ``world.email_domain``.
    """
    try:
        from sandroid.config import get_config

        world = getattr(get_config(), "world", None)
    except Exception:
        return DEFAULT_KEEP
    value = (
        world.get("persona_snapshots")
        if isinstance(world, dict)
        else getattr(world, "persona_snapshots", None)
    )
    if isinstance(value, bool) or not isinstance(value, int):
        return DEFAULT_KEEP
    return max(1, value)


def topup_enabled() -> bool:
    """The config's ``world.persona_topup`` (default on): top up a loaded
    persona snapshot with SMS, calls and events up to now.
    """
    try:
        from sandroid.config import get_config

        world = getattr(get_config(), "world", None)
    except Exception:
        return True
    value = (
        world.get("persona_topup")
        if isinstance(world, dict)
        else getattr(world, "persona_topup", None)
    )
    return value if isinstance(value, bool) else True


def persona_snapshots(avd: str) -> list[str]:
    """Loadable persona snapshots of ``avd`` on the host, newest first."""
    from sandroid.core import emulator
    from sandroid.core.snapshot_policy import snapshot_complete

    directory = emulator.avd_dir(avd)
    root = directory / "snapshots" if directory else None
    if root is None or not root.is_dir():
        return []
    found: list[tuple[float, str]] = []
    for entry in root.iterdir():
        name = entry.name
        if not name.startswith(PERSONA_PREFIX) or not snapshot_complete(avd, name):
            continue
        marker = entry / "snapshot.pb"
        try:
            mtime = (marker if marker.exists() else entry).stat().st_mtime
        except OSError:
            continue
        found.append((mtime, name))
    return [name for _mtime, name in sorted(found, reverse=True)]


def device_world(serial: str, *, device: Device | None = None) -> dict[str, Any] | None:
    """The world stamp on the device (``None``: no stamp or unreadable)."""
    dev = device or Device(serial)
    res = dev.shell(f"cat {STAMP_PATH} 2>/dev/null", timeout=20)
    try:
        data = json.loads(res.out) if res.out.strip() else None
    except ValueError:
        return None
    if not isinstance(data, dict) or data.get("format") != STAMP_FORMAT:
        return None
    return data


def save_persona_snapshot(
    serial: str,
    avd: str,
    name: str,
    *,
    world_fp: str,
    keep: int | None = None,
    emulator: Any = None,
    device: Device | None = None,
) -> PersonaSave:
    """Save the running emulator as persona snapshot ``name``, then prune.

    The device must carry a complete world stamp of ``world_fp`` (a prepare
    that finished); otherwise nothing is saved. Older persona snapshots of
    the AVD beyond ``keep`` (newest first, this one included) are deleted.
    Call from a worker thread: the save pauses the emulator for seconds.

    Args:
        serial: The emulator.
        avd: Its AVD name (for the host snapshot folder).
        name: A ``sandroid_persona_`` name (:func:`persona_name`).
        world_fp: The world the device must hold.
        keep: Persona snapshots to keep; default :func:`configured_keep`.
        emulator: The emulator service (tests); default the singleton.
        device: The device wrapper (tests).

    Returns:
        The result; ``saved`` False with ``error`` when it was not saved.
    """
    from sandroid.core.snapshot_policy import acting_as, snapshot_complete

    out = PersonaSave(name=name)
    if not name.startswith(PERSONA_PREFIX):
        out.error = f"{name!r} is not a persona snapshot name"
        return out
    stamp = device_world(serial, device=device)
    if stamp is None:
        out.error = "the device holds no world (prepare it first)"
        return out
    if stamp.get("state") != "complete" or stamp.get("world_fp") != world_fp:
        out.error = (
            f"the device's world is {str(stamp.get('world_fp') or '')[:12]} "
            f"({stamp.get('state')}), not {world_fp[:12]} (complete)"
        )
        return out
    if emulator is None:
        from sandroid.services import get_emulator_service

        emulator = get_emulator_service()
    with acting_as(ACTOR):
        ok = emulator.create_snapshot(name, serial=serial)
    if not ok:
        out.error = "the emulator did not save the snapshot (see the log)"
        return out
    if not snapshot_complete(avd, name):
        out.error = "the snapshot was saved but holds no RAM image"
        return out
    out.saved = True
    limit = max(1, keep if keep is not None else configured_keep())
    current = persona_snapshots(avd)
    older = [n for n in current if n != name]
    for old in older[limit - 1 :]:
        if delete_persona_snapshot(serial, old, emulator=emulator):
            out.pruned.append(old)
        else:
            out.warnings.append(f"could not delete the old persona snapshot {old}")
    out.kept = [n for n in [name, *older] if n not in out.pruned]
    for stub in _persona_stubs(avd):  # an interrupted save: holds nothing
        if delete_persona_snapshot(serial, stub, emulator=emulator):
            out.pruned.append(stub)
    return out


def _persona_stubs(avd: str) -> list[str]:
    """Persona snapshot folders without a RAM image (not loadable)."""
    from sandroid.core import emulator
    from sandroid.core.snapshot_policy import snapshot_complete

    directory = emulator.avd_dir(avd)
    root = directory / "snapshots" if directory else None
    if root is None or not root.is_dir():
        return []
    return sorted(
        e.name
        for e in root.iterdir()
        if e.is_dir()
        and e.name.startswith(PERSONA_PREFIX)
        and not snapshot_complete(avd, e.name)
    )


@dataclass
class PersonaBuild:
    """What :func:`build_persona` did.

    Attributes:
        profile: The identity profile id.
        snapshot: The persona snapshot name.
        cached: The snapshot existed already; nothing was done.
        prepare: :meth:`PrepareReport.to_dict` (empty when cached).
        identity: The identity apply's step statuses.
        save: The snapshot save (None when cached or not reached).
    """

    profile: str
    snapshot: str
    cached: bool = False
    prepare: dict[str, Any] = field(default_factory=dict)
    identity: dict[str, Any] = field(default_factory=dict)
    save: PersonaSave | None = None


def build_persona(
    serial: str,
    profile_id: str,
    *,
    anchor: Any = None,
    progress: Any = None,
    force_cleanup: bool = False,
    keep: int | None = None,
    rebuild: bool = False,
    identity: IdentityService | None = None,
    emulator: Any = None,
    device: Device | None = None,
    deadline: float | None = None,
) -> PersonaBuild:
    """Build the persona snapshot of ``profile_id`` on the clean emulator
    ``serial``: generate, prepare, apply the identity, save, prune.

    The emulator must run a clean base (no world stamp). When the snapshot
    exists already (same world and identity fingerprints) nothing is done
    unless ``rebuild``. Call from a worker thread.

    ``deadline`` (``time.monotonic()``): the identity apply and the save
    start only with :data:`APPLY_RESERVE_S` / :data:`SAVE_RESERVE_S` left;
    otherwise the build stops with a :class:`PersonaError` (the world stays
    on the device, without a snapshot).

    Raises:
        PersonaError: No AVD, no world section, out of time, the identity
            apply failed, or the snapshot was not saved.
        sandroid.world.prepare.PrepareError: Prepare refused or failed.
    """
    from sandroid.core import emulator as emu
    from sandroid.services.identity import get_identity_service
    from sandroid.world.prepare import prepare

    dev = device or Device(serial)
    avd = emu.avd_name_of(serial)
    if not avd:
        raise PersonaError(f"{serial} is not an emulator with a known AVD")
    sdk = dev.shell("getprop ro.build.version.sdk", timeout=30).out.strip()
    # The shared service: its apply lock serialises this apply with the
    # identity stage and app starts, and its memory sees the persona apply.
    svc = identity or get_identity_service()
    manifest, profile = manifest_for_profile(
        profile_id, service=svc, target_sdk=int(sdk) if sdk.isdigit() else None
    )
    name = persona_name(profile, manifest)
    out = PersonaBuild(profile=profile_id, snapshot=name)
    if not rebuild and name in persona_snapshots(avd):
        out.cached = True
        return out
    report = prepare(
        serial,
        manifest,
        anchor=anchor,
        progress=progress,
        force_cleanup=force_cleanup,
        device=dev,
    )
    out.prepare = report.to_dict()
    _in_time(deadline, APPLY_RESERVE_S, "the identity apply")
    from sandroid.services.identity import IdentityApplyError

    try:
        # as_persona: the device's identity record names this persona, so a
        # later load of the snapshot (any launch, a TUI restart) keeps it.
        plan = svc.apply(serial, allow_restart=True, profile=profile, as_persona=True)
    except IdentityApplyError as exc:
        raise PersonaError(f"identity apply refused: {exc}") from exc
    out.identity = {
        vid: {"status": info.status, "reason": info.reason}
        for vid, info in plan.infos.items()
    }
    if getattr(plan, "restored", False):
        # A snapshot load hit the device during the apply: the values may
        # not be on the device that would be saved.
        raise PersonaError("the device was restored during the identity apply")
    failed = _unbaked(plan.infos)
    if failed:
        raise PersonaError(f"identity apply failed for {', '.join(failed)}")
    _in_time(deadline, SAVE_RESERVE_S, "the snapshot save")
    out.save = save_persona_snapshot(
        serial,
        avd,
        name,
        world_fp=manifest.world_fp,
        keep=keep,
        emulator=emulator,
        device=dev,
    )
    if not out.save.saved:
        raise PersonaError(f"persona snapshot not saved: {out.save.error}")
    return out


def _unbaked(infos: dict[str, Any]) -> list[str]:
    """Identity values the snapshot would lack: failed ones, and framework
    values still waiting for a restart (the restart itself failed). A SIM
    value (the emulator's start sets it from the modem files) and per-app or
    hook-only values (seeded at the app's first start) never count.
    """
    from sandroid.services.identity import (
        NEEDS_RESTART,
        NOT_RESTARTED,
        READBACK_NO_ANSWER,
        RESTORED_DURING,
    )

    out = []
    for vid, info in infos.items():
        if not info.enabled or info.sim_launch:
            continue
        reason = info.reason or ""
        # No read-back answer: the device record (and its persona) was not
        # written, so the snapshot would not know its persona. A restore
        # during the apply: the step never ran.
        if (
            info.status == "failed"
            or reason.startswith((READBACK_NO_ANSWER, RESTORED_DURING))
            or (
                info.status == "pending"
                and reason.startswith((NEEDS_RESTART, NOT_RESTARTED))
            )
        ):
            out.append(vid)
    return sorted(out)


def _in_time(deadline: float | None, need_s: float, step: str) -> None:
    if deadline is not None and deadline - time.monotonic() < need_s:
        raise PersonaError(
            f"out of time before {step}; run the build from the CLI "
            "(python -m sandroid.world persona build)"
        )


def launch_persona(serial: str) -> str | None:
    """The persona id of Sandroid's live launch of ``serial`` (``meta.persona_id``)."""
    from sandroid.core import emulator as emu

    record = emu.launch_record(serial)
    meta = (record or {}).get("meta") or {}
    value = meta.get(META_KEY) if isinstance(meta, dict) else None
    return value if isinstance(value, str) and value else None


def _built_from_base(record: dict[str, Any]) -> bool:
    """The launch started from the persona's clean base snapshot."""
    meta = record.get("meta") or {}
    base = meta.get("persona_base") if isinstance(meta, dict) else None
    opts = record.get("options") or {}
    return opts.get("boot") == "snapshot" and opts.get("snapshot") == (
        base if isinstance(base, str) and base else DEFAULT_BASE
    )


def persona_stage(serial: str, fresh_boot: bool, budget_s: float) -> Any:
    """The device-prep stage of a persona launch (``meta.persona_id``).

    * The device holds the persona's world (its snapshot was loaded): info.
    * It holds another world: a warning; nothing is changed.
    * It holds none: only on the first prepare of a launch started from the
      clean base (``meta.persona_base``, default :data:`DEFAULT_BASE`) the
      persona is built and its snapshot saved, so the next start loads it;
      any other missing world (a rewind from outside, a later prepare) is a
      warning. A photo missing from the cache is a warning too: a download
      could outlast the stage. The identity apply and the save are skipped
      when ``budget_s`` would run out (:func:`build_persona`'s deadline).

    Not a persona launch: nothing (``None``).
    """
    from sandroid.core import emulator as emu
    from sandroid.core.device_prep import StageNote
    from sandroid.world.photos import ensure_photos, photo_entries
    from sandroid.world.prepare import PrepareError

    deadline = time.monotonic() + budget_s
    record = emu.launch_record(serial) or {}
    pid = launch_persona(serial)
    if pid is None:
        return None
    label = f"persona {pid}"
    try:
        dev = Device(serial)
        sdk = dev.shell("getprop ro.build.version.sdk", timeout=30).out.strip()
        manifest, profile = manifest_for_profile(
            pid, target_sdk=int(sdk) if sdk.isdigit() else None
        )
    except Exception as exc:
        return StageNote("warning", f"{label}: {exc}")
    notes: list[str] = []
    runs = _device_profile_id(serial)
    if runs and runs != profile.id:
        notes.append(f"the identity stage applies {runs}, not {profile.id}")
    stamp = device_world(serial, device=dev)
    fp = manifest.world_fp
    if stamp is not None:
        same = stamp.get("world_fp") == fp
        if same and stamp.get("state") == "complete":
            avd = record.get("avd") or ""
            name = persona_name(profile, manifest)
            if avd and name in persona_snapshots(avd):
                text = f"{label}: world {fp[:12]} loaded from {name}"
                fresh, warned = after_load_topup(serial, manifest, device=dev)
                if fresh:
                    text += f", {fresh}"
                return StageNote(
                    "warning" if notes or warned else "info",
                    "; ".join([text, *notes]),
                )
            return StageNote(
                "warning",
                "; ".join(
                    [
                        f"{label}: world {fp[:12]} is on the device but no "
                        "persona snapshot of this identity exists; build it "
                        "from the CLI (python -m sandroid.world persona build)",
                        *notes,
                    ]
                ),
            )
        if same:
            return StageNote(
                "warning",
                f"{label}: an interrupted prepare of world {fp[:12]} "
                f"({stamp.get('state')}); clean it with --force-cleanup",
            )
        other = str(stamp.get("world_fp") or "")[:12]
        return StageNote(
            "warning",
            f"{label}: the device holds another world ({other}, "
            f"{stamp.get('state')}); not prepared",
        )
    launch_id = str(record.get("launch_id") or "")
    with _BUILT_LOCK:
        first = bool(launch_id) and launch_id not in _BUILT_LAUNCHES
        build = first and _built_from_base(record)
        if build:
            _BUILT_LAUNCHES.add(launch_id)
    if not build:
        return StageNote(
            "warning",
            "; ".join(
                [
                    f"{label}: the device holds no world and this launch did "
                    "not start from the clean base; not prepared",
                    *notes,
                ]
            ),
        )
    missing = ensure_photos(photo_entries(manifest), download=False).failed
    if missing:
        return StageNote(
            "warning",
            f"{label}: {len(missing)} photos are not downloaded; run "
            f"python -m sandroid.world photos fetch --profile {pid}",
        )
    try:
        result = build_persona(serial, pid, rebuild=True, device=dev, deadline=deadline)
    except (PersonaError, PrepareError) as exc:
        return StageNote("warning", f"{label}: {exc}")
    save = result.save
    text = f"{label}: world {fp[:12]} prepared, saved as {result.snapshot}"
    if save is not None and save.pruned:
        text += f" ({len(save.pruned)} older persona snapshots deleted)"
    return StageNote(
        "warning" if notes or (save and save.warnings) else "info",
        "; ".join([text, *notes, *(save.warnings if save else [])]),
    )


def after_load_topup(
    serial: str, manifest: WorldManifest, *, device: Device | None = None
) -> tuple[str, bool]:
    """Top up a loaded persona snapshot (:func:`sandroid.world.prepare.topup`)
    when ``world.persona_topup`` is on; a timeline line for every top-up.

    Returns:
        ``(words, warned)``: what to add to the stage line (``""`` when off)
        and whether it failed or warned. Never raises.
    """
    if not topup_enabled():
        return "", False
    from sandroid.world.prepare import topup

    try:
        report = topup(serial, manifest, device=device)
    except Exception as exc:
        _topup_line(serial, manifest, None, str(exc))
        return f"top-up failed: {exc}", True
    if report.ran:
        _topup_line(serial, manifest, report, "")
    words = report.words()
    if report.warnings:
        words += " (" + "; ".join(report.warnings) + ")"
    return words, bool(report.warnings)


def _topup_line(serial: str, manifest: Any, report: Any, error: str) -> None:
    """A timeline line for a top-up (never raises)."""
    try:
        from sandroid.core.timeline import get_timeline

        if report is None:
            summary = f"persona top-up failed: {error}"
            data: dict[str, Any] = {"world_fp": manifest.world_fp, "error": error}
        else:
            summary = f"persona {report.words()}"
            data = report.to_dict()
        get_timeline().emit(
            "device",
            "persona_topup",
            summary=summary,
            data=data,
            dev=serial,
            level="warn" if error or (report and report.warnings) else "info",
        )
    except Exception:
        logger.debug("timeline: persona top-up line failed", exc_info=True)


def _device_profile_id(serial: str) -> str:
    """The profile the identity stage applies to ``serial`` (``""``: off).

    The identity service resolves a device's profile itself (its persona,
    else the launch's ``persona_id``, else the active profile); this only
    tells when that is not the persona being built.
    """
    try:
        from sandroid.services.identity import get_identity_service

        return get_identity_service().profile_id_for(serial)
    except Exception:
        return ""


def delete_persona_snapshot(serial: str, name: str, *, emulator: Any = None) -> bool:
    """Delete persona snapshot ``name`` as the ``persona`` actor."""
    from sandroid.core.snapshot_policy import acting_as

    if not name.startswith(PERSONA_PREFIX):
        return False
    if emulator is None:
        from sandroid.services import get_emulator_service

        emulator = get_emulator_service()
    with acting_as(ACTOR):
        return bool(emulator.delete_snapshot(name, serial=serial))


# ------------------------------------------------------------ refresh / start


@dataclass
class PersonaRefresh:
    """What :func:`refresh_persona` did.

    Attributes:
        profile: The identity profile id.
        snapshot: The persona snapshot name now.
        up_to_date: World and identity were current; nothing was done.
        world_changed: The world differed and was refreshed.
        prepare: :meth:`PrepareReport.to_dict` of the refresh (empty when
            the world was current).
        identity: The identity apply's step statuses.
        save: The snapshot save (None when up to date).
        topup: What the top-up after the save did (words).
    """

    profile: str
    snapshot: str
    up_to_date: bool = False
    world_changed: bool = False
    prepare: dict[str, Any] = field(default_factory=dict)
    identity: dict[str, Any] = field(default_factory=dict)
    save: PersonaSave | None = None
    topup: str = ""

    def words(self) -> str:
        """One line for a person."""
        if self.up_to_date:
            return f"persona {self.profile} is up to date ({self.snapshot})"
        parts = []
        changes = self.prepare.get("changes") or {}
        if self.world_changed:
            added = sum((changes.get("added") or {}).values())
            removed = sum((changes.get("removed") or {}).values())
            parts.append(f"phone contents: {added} added, {removed} removed")
        else:
            parts.append("phone contents unchanged")
        if self.save is not None and self.save.saved:
            parts.append(f"saved as {self.snapshot}")
            if self.save.pruned:
                parts.append(f"{len(self.save.pruned)} older persona snapshots deleted")
        if self.topup:
            parts.append(self.topup)
        return f"persona {self.profile}: " + ", ".join(parts)


def refresh_persona(
    serial: str,
    profile_id: str | None = None,
    *,
    progress: Any = None,
    keep: int | None = None,
    identity: IdentityService | None = None,
    emulator: Any = None,
    device: Device | None = None,
) -> PersonaRefresh:
    """Bring the persona on the running emulator ``serial`` up to its profile.

    Incremental: when the world changed, only the items that differ from the
    host ledger are removed and added (:func:`sandroid.world.prepare.refresh`);
    the identity is applied again (values already set stay); the snapshot is
    saved under the new name and older ones pruned. When world and identity
    are current (the snapshot of this profile exists and the device holds its
    world), nothing is done. A top-up follows a refreshed world (not part of
    the snapshot). Call from a worker thread.

    Args:
        serial: The emulator.
        profile_id: The persona; default the one the device holds.

    Raises:
        PersonaError: No persona, no world on the device, the identity apply
            failed or the snapshot was not saved.
        sandroid.world.prepare.PrepareError: The world refresh failed.
    """
    from sandroid.core import emulator as emu
    from sandroid.services.identity import IdentityApplyError, get_identity_service
    from sandroid.world import prepare as pr

    dev = device or Device(serial)
    avd = emu.avd_name_of(serial)
    if not avd:
        raise PersonaError(f"{serial} is not an emulator with a known AVD")
    svc = identity or get_identity_service()
    pid = profile_id or svc.persona_of(serial) or launch_persona(serial) or ""
    if not pid:
        raise PersonaError(f"{serial} holds no persona; build one first")
    stamp = device_world(serial, device=dev)
    if stamp is None or stamp.get("state") != "complete":
        raise PersonaError("the device holds no complete world; build the persona")
    sdk = dev.shell("getprop ro.build.version.sdk", timeout=30).out.strip()
    manifest, profile = manifest_for_profile(
        pid, service=svc, target_sdk=int(sdk) if sdk.isdigit() else None
    )
    name = persona_name(profile, manifest)
    out = PersonaRefresh(profile=pid, snapshot=name)
    same_world = stamp.get("world_fp") == manifest.world_fp
    if same_world and name in persona_snapshots(avd):
        out.up_to_date = True
        return out
    if not same_world:
        report = pr.refresh(serial, manifest, progress=progress, device=dev)
        out.prepare = report.to_dict()
        out.world_changed = True
    try:
        plan = svc.apply(serial, allow_restart=True, profile=profile, as_persona=True)
    except IdentityApplyError as exc:
        raise PersonaError(f"identity apply refused: {exc}") from exc
    out.identity = {
        vid: {"status": info.status, "reason": info.reason}
        for vid, info in plan.infos.items()
    }
    if getattr(plan, "restored", False):
        raise PersonaError("the device was restored during the identity apply")
    failed = _unbaked(plan.infos)
    if failed:
        raise PersonaError(f"identity apply failed for {', '.join(failed)}")
    out.save = save_persona_snapshot(
        serial,
        avd,
        name,
        world_fp=manifest.world_fp,
        keep=keep,
        emulator=emulator,
        device=dev,
    )
    if not out.save.saved:
        raise PersonaError(f"persona snapshot not saved: {out.save.error}")
    if out.world_changed:
        out.topup = after_load_topup(serial, manifest, device=dev)[0]
    return out


@dataclass(frozen=True)
class PersonaChoice:
    """An identity profile that can be started as a persona.

    Attributes:
        id: The profile id.
        name: Its display name.
        snapshots: Persona snapshots of it on the AVD (any version).
    """

    id: str
    name: str
    snapshots: int = 0


def persona_choices(
    avd: str, *, service: IdentityService | None = None
) -> list[PersonaChoice]:
    """The library's profiles with a ``world`` section, and how many persona
    snapshots of each the AVD holds. Reads files only (worker thread).
    """
    from sandroid.services.identity import get_identity_service

    svc = service or get_identity_service()
    present = persona_snapshots(avd)
    out = []
    for info in svc.list_profiles():
        if info.error:
            continue
        try:
            profile = svc.load(info.id)
        except Exception:
            continue
        if not getattr(profile, "world", None):
            continue
        prefix = _snapshot_prefix(info.id)
        count = sum(1 for n in present if prefix and n.startswith(prefix))
        out.append(PersonaChoice(info.id, info.name or info.id, count))
    return out


def _snapshot_prefix(profile_id: str) -> str:
    """``sandroid_persona_<slug>_`` of a profile (see :func:`persona_snapshot_name`)."""
    import re

    slug = re.sub(r"[^a-z0-9-]+", "-", profile_id.lower()).strip("-")[:40]
    return f"{PERSONA_PREFIX}{slug}_" if slug else ""


@dataclass(frozen=True)
class PersonaStart:
    """How to start an AVD as a persona (:func:`persona_start`).

    Attributes:
        options: The launch options (``boot="snapshot"``, no save on exit).
        meta: The launch-record meta (``persona_id``, maybe ``persona_base``).
        snapshot: The persona snapshot name of the current profile.
        cached: That snapshot exists and is loaded; otherwise the start loads
            the clean base and the persona stage builds it.
    """

    options: Any
    meta: dict[str, Any]
    snapshot: str
    cached: bool


def persona_start(
    avd: str,
    profile_id: str,
    *,
    api: int | None = None,
    headless: bool = False,
    base: str = DEFAULT_BASE,
    service: IdentityService | None = None,
) -> PersonaStart:
    """The launch of ``avd`` as persona ``profile_id``.

    The persona snapshot of the profile as it is now (world and identity
    fingerprints) is loaded when it exists; otherwise the clean base, and the
    persona stage builds and saves the persona. Never saves on exit. Generates
    the world (writes a resolved ``seed: auto`` back): call off the UI thread.

    Raises:
        PersonaError: No world section, or neither the persona snapshot nor
            the base exists.
    """
    from sandroid.core import emulator as emu
    from sandroid.core.snapshot_policy import snapshot_complete

    manifest, profile = manifest_for_profile(
        profile_id, service=service, target_sdk=api
    )
    name = persona_name(profile, manifest)
    cached = name in persona_snapshots(avd)
    if not cached and not snapshot_complete(avd, base):
        raise PersonaError(
            f"{avd} has no persona snapshot of {profile_id} and no {base} "
            "snapshot to build it from"
        )
    meta: dict[str, Any] = {META_KEY: profile_id}
    if base != DEFAULT_BASE:
        meta["persona_base"] = base
    options = emu.AvdLaunchOptions(
        headless=headless,
        boot="snapshot",
        snapshot=name if cached else base,
        save_on_exit=False,
    )
    return PersonaStart(options=options, meta=meta, snapshot=name, cached=cached)
