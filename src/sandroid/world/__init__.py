"""Sandroid's "lived-in world": data packs and the deterministic generator.

:func:`generate` builds a :class:`WorldManifest` (a social graph plus
contacts, SMS, calls, calendar, photo metadata, files and notes) from a
:class:`WorldSpec`, the owner's name and the packs in
``sandroid/assets/world``; it never talks to a device.

Seeding a device lives in submodules that are not imported here:
:mod:`sandroid.world.prepare` (the Prepare pipeline, ledger and stamp),
:mod:`sandroid.world.photos` (photo cache and the EXIF privacy step),
:mod:`sandroid.world.helper` (the on-device world helper) and
``python -m sandroid.world`` (developer entry point).

Example::

    from sandroid.world import generate

    manifest = generate(
        {"seed": "auto", "size": "medium", "country": "de"},
        {"first": "Mara", "last": "Keller", "phone": "+49...", "email": "..."},
    )
    manifest.seed                  # write back to the profile when the spec said auto
    world = manifest.render(anchor)  # absolute times and final text at seed time
    world.markers()                # values for the privacy scanner
"""

from sandroid.world.generator import (
    GENERATOR_VERSION,
    NumberFactory,
    generate,
    phone_check,
)
from sandroid.world.manifest import (
    SIZES,
    Owner,
    RenderedWorld,
    WorldManifest,
    WorldSpec,
)
from sandroid.world.markers import build_markers, to_markers
from sandroid.world.packs import (
    PackSet,
    ValidationReport,
    WorldError,
    load_packs,
    validate_pack,
)
from sandroid.world.stream import SeedStream

__all__ = [
    "GENERATOR_VERSION",
    "SIZES",
    "NumberFactory",
    "Owner",
    "PackSet",
    "RenderedWorld",
    "SeedStream",
    "ValidationReport",
    "WorldError",
    "WorldManifest",
    "WorldSpec",
    "build_markers",
    "generate",
    "load_packs",
    "phone_check",
    "to_markers",
    "validate_pack",
]
