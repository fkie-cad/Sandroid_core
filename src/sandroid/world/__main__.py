r"""Developer entry point of the world module (no public CLI surface yet).

    python -m sandroid.world render  --spec world.yaml --owner-first F --owner-last L
    python -m sandroid.world prepare --serial emulator-5560 --spec world.yaml \
        --owner-first F --owner-last L [--anchor 2026-11-20T15:00] [--force-cleanup]
    python -m sandroid.world photos fetch (--spec world.yaml ... | --all)
    python -m sandroid.world photos import FOLDER
    python -m sandroid.world persona build --serial emulator-5560 --profile ID \
        [--rebuild] [--keep 3] [--anchor ...] [--force-cleanup]
    python -m sandroid.world persona list --avd AVD

``--spec`` is a YAML file holding either the ``world:`` mapping itself or a
profile with a ``world:`` key (and optionally ``owner:``); ``--profile`` takes
an identity profile from the library instead (its seed is resolved and written
back once, its owner rendered with its token). Output is JSON on
stdout; progress goes to stderr.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import signal
import sys
from pathlib import Path
from typing import Any

import yaml


def _load_spec(path: str) -> tuple[dict[str, Any], dict[str, Any]]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: not a mapping")
    if "world" in data:
        world = data.get("world") or {}
        owner = data.get("owner") or {}
    else:
        world, owner = data, {}
    return dict(world), dict(owner) if isinstance(owner, dict) else {}


def _owner(args: argparse.Namespace, base: dict[str, Any]) -> dict[str, Any]:
    owner = dict(base)
    for key in ("first", "last", "phone"):
        value = getattr(args, f"owner_{key}", None)
        if value is not None:
            owner[key] = value
    if not owner.get("first") or not owner.get("last"):
        raise SystemExit("the owner needs --owner-first and --owner-last")
    return owner


def _anchor(text: str | None) -> dt.datetime | None:
    return dt.datetime.fromisoformat(text) if text else None


def _generate(args: argparse.Namespace, target_sdk: int | None = None) -> Any:
    from sandroid.world import generate

    if getattr(args, "profile", None):
        from sandroid.world.persona import PersonaError, manifest_for_profile

        try:
            manifest, _profile = manifest_for_profile(
                args.profile, target_sdk=target_sdk
            )
        except PersonaError as exc:
            raise SystemExit(str(exc)) from exc
        for warning in manifest.warnings:
            print(f"warning: {warning}", file=sys.stderr)
        return manifest
    spec, owner = _load_spec(args.spec)
    manifest = generate(spec, _owner(args, owner), target_sdk=target_sdk)
    if spec.get("seed", "auto") == "auto":
        print(
            f"world seed resolved to {manifest.seed} (not written back)",
            file=sys.stderr,
        )
    for warning in manifest.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    return manifest


def _dump(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=1, sort_keys=True, default=str))


def cmd_render(args: argparse.Namespace) -> int:
    from dataclasses import asdict

    from sandroid.world.prepare import world_timezone

    manifest = _generate(args, args.target_sdk)
    tz = world_timezone(manifest)
    anchor = _anchor(args.anchor) or dt.datetime.now(tz)
    # As prepare() does: local wall times of the world's zone (DST included).
    anchor = (
        anchor.replace(tzinfo=tz) if anchor.tzinfo is None else anchor.astimezone(tz)
    )
    _dump(asdict(manifest.render(anchor)))
    return 0


def cmd_prepare(args: argparse.Namespace) -> int:
    from sandroid.world.helper import Device
    from sandroid.world.prepare import PrepareError, prepare

    device = Device(args.serial)
    sdk_out = device.shell("getprop ro.build.version.sdk", timeout=30).out.strip()
    target = int(sdk_out) if sdk_out.isdigit() else None
    manifest = _generate(args, target)

    def progress(step: str, done: int, total: int) -> None:
        print(f"{step}: {done}/{total}", file=sys.stderr)

    try:
        report = prepare(
            args.serial,
            manifest,
            anchor=_anchor(args.anchor),
            progress=progress,
            force_cleanup=args.force_cleanup,
            device=device,
        )
    except PrepareError as exc:
        print(f"prepare failed: {exc}", file=sys.stderr)
        if exc.report is not None:
            _dump(exc.report.to_dict())
        return 1
    _dump(report.to_dict())
    return 0


def cmd_persona(args: argparse.Namespace) -> int:
    from dataclasses import asdict

    from sandroid.world import persona
    from sandroid.world.prepare import PrepareError

    if args.persona_cmd == "list":
        _dump(persona.persona_snapshots(args.avd))
        return 0

    def progress(step: str, done: int, total: int) -> None:
        print(f"{step}: {done}/{total}", file=sys.stderr)

    try:
        result = persona.build_persona(
            args.serial,
            args.profile,
            anchor=_anchor(args.anchor),
            progress=progress,
            force_cleanup=args.force_cleanup,
            keep=args.keep,
            rebuild=args.rebuild,
        )
    except PrepareError as exc:
        print(f"prepare failed: {exc}", file=sys.stderr)
        if exc.report is not None:
            _dump(exc.report.to_dict())
        return 1
    except persona.PersonaError as exc:
        print(f"persona failed: {exc}", file=sys.stderr)
        return 1
    _dump(asdict(result))
    return 0


def cmd_photos(args: argparse.Namespace) -> int:
    from sandroid.world.packs import load_packs
    from sandroid.world.photos import ensure_photos, import_photos, photo_entries

    if args.photos_cmd == "import":
        result = import_photos(Path(args.folder))
        _dump(
            {
                "imported": result.imported,
                "present": result.present,
                "unknown": result.unknown,
            }
        )
        return 0
    if args.all:
        pack = load_packs().photos()
        entries = (pack.data.get("photos") if pack else None) or []
    else:
        if not (args.spec or args.profile):
            raise SystemExit("photos fetch needs --spec, --profile or --all")
        entries = photo_entries(_generate(args))

    def progress(pid: str, done: int, total: int) -> None:
        print(f"{done}/{total} {pid}", file=sys.stderr)

    result = ensure_photos(entries, progress=progress)
    _dump(
        {
            "available": len(result.paths),
            "downloaded": result.downloaded,
            "failed": result.failed,
        }
    )
    return 0 if not result.failed else 1


def _owner_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--spec", help="YAML: the world mapping or a profile")
    p.add_argument("--profile", help="an identity profile id (instead of --spec)")
    p.add_argument("--owner-first")
    p.add_argument("--owner-last")
    p.add_argument("--owner-phone", help="E.164; only its country code is used")


def _exit_on_signal(signum: int, _frame: object) -> None:
    raise SystemExit(128 + signum)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m sandroid.world")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("render", help="print the rendered world as JSON")
    _owner_args(p)
    p.add_argument("--anchor", help="ISO time; default now in the world's zone")
    p.add_argument("--target-sdk", type=int)
    p.set_defaults(func=cmd_render)

    p = sub.add_parser("prepare", help="seed a world onto a clean device")
    p.add_argument("--serial", required=True)
    _owner_args(p)
    p.add_argument("--anchor", help="ISO time; default now (host clock)")
    p.add_argument("--force-cleanup", action="store_true")
    p.set_defaults(func=cmd_prepare)

    p = sub.add_parser("persona", help="persona snapshots")
    psub = p.add_subparsers(dest="persona_cmd", required=True)
    b = psub.add_parser("build", help="prepare, apply the identity, save")
    b.add_argument("--serial", required=True)
    b.add_argument("--profile", required=True)
    b.add_argument("--anchor", help="ISO time; default now (host clock)")
    b.add_argument("--force-cleanup", action="store_true")
    b.add_argument("--keep", type=int, help="persona snapshots kept per AVD")
    b.add_argument("--rebuild", action="store_true", help="even if it exists")
    b.set_defaults(func=cmd_persona)
    ls = psub.add_parser("list", help="persona snapshots of an AVD")
    ls.add_argument("--avd", required=True)
    ls.set_defaults(func=cmd_persona)

    p = sub.add_parser("photos", help="the photo cache")
    psub = p.add_subparsers(dest="photos_cmd", required=True)
    f = psub.add_parser("fetch", help="download the photos a world (or all) uses")
    _owner_args(f)
    f.add_argument("--all", action="store_true")
    f.set_defaults(func=cmd_photos)
    i = psub.add_parser("import", help="copy verified files into the cache")
    i.add_argument("folder")
    i.set_defaults(func=cmd_photos)

    args = parser.parse_args(argv)
    # A terminated run still unwinds: prepare() turns the network back on
    # and leaves its ledger and partial stamp for --force-cleanup.
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, _exit_on_signal)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        stream=sys.stderr,
        format="%(levelname)s %(name)s: %(message)s",
    )
    if args.cmd in ("render", "prepare") and not (args.spec or args.profile):
        parser.error("--spec or --profile is required")
    if args.cmd in ("render", "prepare") and args.spec and args.profile:
        parser.error("--spec and --profile exclude each other")
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
