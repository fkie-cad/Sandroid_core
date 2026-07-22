"""Extended package info parsing + real manifest-based component parsing.

Two things live here:

- :func:`parse_extended_package_info` -- reuses
  :class:`~sandroid.services.app_selection_parsers.PackageInfoParser` for the
  scalar fields it already extracts (``version_name``/``version_code``/
  ``target_sdk``/``min_sdk``/``apk_path``/``data_dir``/``install_date``) and
  layers on the fields that parser doesn't cover: ``uid``,
  ``requested_permissions`` (list-valued -- needs section-scanning, not a
  single capture group), ``install_source``, and basic ``signing_info``. This
  parses ``dumpsys package <pkg>`` text and was independently confirmed
  correct against real device output (its ``Packages:`` section genuinely
  contains all of these fields) -- unchanged from the original implementation.
- :func:`parse_component_info` -- extracts every activity/service/receiver/
  provider's ``exported``, guarding permission, and intent-filters
  (providers additionally get ``read_permission``/``write_permission``/
  ``authorities``): the core pentest attack-surface signal.

Bug-fix history (read before touching :func:`parse_component_info`): this
function used to scan ``dumpsys package <pkg>`` text for
``Activity #0:``/``exported=``/``permission=``/``intent filters:`` blocks.
That data simply **does not exist** in real ``dumpsys package`` output --
verified against a live emulator (WhatsApp, Chrome: both returned nothing)
and cross-referenced against AOSP's ``Settings.java::dumpComponents()``
across three Android versions. Real ``dumpsys package <pkg>`` component
sections are just a bare ``Activities:``/``Services:``/``Receivers:``/
``Providers:`` header followed by one ``pkg/.ClassName`` line per component
-- no ``exported=``, no permission, no intent-filter data at all. (What
*does* carry ``exported=``/permission/intent-filter data in a live dumpsys
invocation is the *Activity/Service/Receiver/Provider Resolver Table*
sections -- but those are indexed by intent action, list only *some*
components, mix multiple packages together, and never surface non-exported
components at all, which makes them unusable as a complete per-package
enumeration.)

The real, verified data source is the compiled ``AndroidManifest.xml``
inside the app's APK, decoded via `androguard
<https://github.com/androguard/androguard>`_ (already a genuine transitive
dependency here -- pulled in by ``dexray-insight``, which this codebase
already depends on for static analysis; see ``pyproject.toml``'s
``static-analysis`` extra, which now lists it directly rather than leaving
it implicit). :func:`parse_component_info` itself stays a pure,
Adb/androguard-free function -- it takes the *already-decoded* manifest XML
text (what ``androguard.core.apk.APK.get_android_manifest_xml()`` produces,
serialized back to a string) plus the app's effective target SDK version.
The device round trip (``pm path`` -> pull the APK(s) -> ``androguard``
decode) lives in :mod:`sandroid.ai.tools.app_query`, which already owns the
Adb-calling side of every other tool in that module.

This was verified against real installed apps on a live emulator (WhatsApp,
Microsoft Edge) -- see ``tests/services/test_component_info_parser.py`` for
fixtures built from real captured (decoded) manifest snippets, not
hand-built approximations.
"""

import logging
import re
from typing import Any

from lxml import etree

from sandroid.services.app_selection_parsers import PackageInfoParser

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Extended scalar package info (uid / install_source / signing_info /
# requested_permissions) -- unchanged, confirmed correct against real
# `dumpsys package <pkg>` output.
# ---------------------------------------------------------------------------

_package_info_parser = PackageInfoParser()

_UID_RE = re.compile(r"(?:userId|appId)=(\d+)")
_INSTALLER_RE = re.compile(r"installerPackageName=(\S+)")
# Only "signatures=PackageSignatures{...}" is genuinely present in a typical
# `dumpsys package` blob -- there is no separate structured signing-cert
# section to parse, so this raw capture is the extent of "signing info".
_SIGNATURES_RE = re.compile(r"signatures=PackageSignatures\{([^}]*)\}")


def _extract_requested_permissions(dumpsys_output: str) -> list[str]:
    """Extract the `requested permissions:` section as a list of names.

    List-valued, so (per the plan) this needs section-scanning rather than
    ``PackageInfoParser``'s single-capture-group ``_PatternSpec`` model:
    walk lines after the ``requested permissions:`` header, collecting every
    subsequent line that is indented *more* than the header, and stop at the
    first line that isn't (e.g. the following ``install permissions:``
    header, which sits at the same indentation).
    """
    lines = dumpsys_output.splitlines()
    permissions: list[str] = []
    header_indent: int | None = None

    for line in lines:
        if header_indent is None:
            if line.strip() == "requested permissions:":
                header_indent = len(line) - len(line.lstrip(" "))
            continue

        if not line.strip():
            continue

        current_indent = len(line) - len(line.lstrip(" "))
        if current_indent <= header_indent:
            break

        permissions.append(line.strip())

    return permissions


def parse_extended_package_info(dumpsys_output: str) -> dict[str, Any]:
    """Parse extended package-level fields from a `dumpsys package <pkg>` blob.

    Returns everything :class:`PackageInfoParser` already extracts
    (``version_name``, ``version_code``, ``target_sdk``, ``min_sdk``,
    ``apk_path``, ``data_dir``, ``install_date`` -- present only if matched)
    plus:

    - ``uid``: int or ``None`` (from ``userId=``/``appId=``)
    - ``requested_permissions``: ``list[str]`` (empty if the section is
      absent)
    - ``install_source``: the installing package name, or ``None`` if absent
      or literally ``"null"`` (e.g. sideloaded via ``adb install``)
    - ``signing_info``: raw ``PackageSignatures{...}`` body as a string, or
      ``None`` if the dump has no ``signatures=`` line

    Args:
        dumpsys_output: Raw stdout of ``adb shell dumpsys package <pkg>``.

    Returns:
        Dictionary of extracted fields, as described above.
    """
    result = _package_info_parser.parse(dumpsys_output)

    uid_match = _UID_RE.search(dumpsys_output)
    result["uid"] = int(uid_match.group(1)) if uid_match else None

    installer_match = _INSTALLER_RE.search(dumpsys_output)
    installer = installer_match.group(1) if installer_match else None
    result["install_source"] = None if installer in (None, "null") else installer

    signatures_match = _SIGNATURES_RE.search(dumpsys_output)
    result["signing_info"] = (
        signatures_match.group(1).strip() if signatures_match else None
    )

    result["requested_permissions"] = _extract_requested_permissions(dumpsys_output)

    return result


# ---------------------------------------------------------------------------
# Exported-component parsing (activities / services / receivers / providers)
#
# Operates on a *decoded* AndroidManifest.xml (real XML text, e.g. from
# ``etree.tostring(apk.get_android_manifest_xml())``) -- not on `dumpsys`
# text. See the module docstring for why.
# ---------------------------------------------------------------------------

_ANDROID_NS = "http://schemas.android.com/apk/res/android"

_TAG_BY_KEY = {
    "activities": "activity",
    "services": "service",
    "receivers": "receiver",
    "providers": "provider",
}

# Attributes a real <data> element inside an <intent-filter> may carry.
# (Real captured manifests only ever showed the lowercase-first attribute
# name -- there is no separate "Type" alias as the old dumpsys-based parser
# assumed; that was a guess made without real data.)
_DATA_ATTRS = (
    "scheme",
    "host",
    "port",
    "path",
    "pathPrefix",
    "pathPattern",
    "mimeType",
)

# Below this effective targetSdkVersion, a <provider> with no explicit
# `android:exported` attribute defaults to exported=true (Android docs +
# AOSP PackageParser); at or above it, the default is exported=false.
_PROVIDER_EXPORTED_DEFAULT_SDK_CUTOFF = 17


def _android_attr(element: etree._Element, name: str) -> str | None:
    """Read a namespaced `android:<name>` attribute off *element*."""
    return element.get(f"{{{_ANDROID_NS}}}{name}")


def _format_value(value: str | None, package: str | None) -> str | None:
    """Resolve a package-relative component name (e.g. ``.Foo``) to fully
    qualified, mirroring androguard's ``APK._format_value``.

    Real captured manifests from ``aapt2``-compiled APKs never actually
    contained a relative name (the compiler resolves them at build time --
    verified against every component in a real WhatsApp + Microsoft Edge
    manifest), but this stays as defensive insurance for manifests built by
    other toolchains.
    """
    if value and package:
        dot_index = value.find(".")
        if dot_index == 0:
            return package + value
        if dot_index == -1:
            return f"{package}.{value}"
    return value


def _parse_intent_filters(component: etree._Element) -> list[dict[str, Any]]:
    """Extract every real ``<intent-filter>`` child as its own entry.

    Unlike the old dumpsys-text parser (which could only approximate "one
    intent-filter entry per component" since flat text gave no reliable
    per-filter boundary), the decoded manifest XML makes each
    ``<intent-filter>`` element's boundary exact -- so multi-intent-filter
    components (real example: WhatsApp's ``HomeActivity`` has four) are now
    represented precisely instead of merged into one blob.
    """
    filters: list[dict[str, Any]] = []
    for intent_filter in component.findall("intent-filter"):
        actions = [
            name
            for action in intent_filter.findall("action")
            if (name := _android_attr(action, "name")) is not None
        ]
        categories = [
            name
            for category in intent_filter.findall("category")
            if (name := _android_attr(category, "name")) is not None
        ]
        data: list[dict[str, str]] = []
        for data_element in intent_filter.findall("data"):
            entry = {
                attr: value
                for attr in _DATA_ATTRS
                if (value := _android_attr(data_element, attr)) is not None
            }
            if entry:
                data.append(entry)

        filters.append({"actions": actions, "categories": categories, "data": data})

    return filters


def _is_exported(
    component: etree._Element,
    *,
    has_intent_filter: bool,
    is_provider: bool,
    target_sdk: int | None,
) -> bool:
    """Compute a component's effective ``exported`` value.

    If ``android:exported`` is explicit, that value wins outright. Otherwise
    this reproduces the Android default-computation rules (the same ones
    ``PackageManagerService`` applies at parse time):

    - Activities/services/receivers: exported defaults to ``True`` if the
      component declares at least one intent-filter, ``False`` otherwise.
    - Providers: exported defaults to ``True`` only when the app's effective
      ``targetSdkVersion`` is below 17 (Android 4.1.1 and earlier);
      otherwise ``False``. If *target_sdk* is unknown (``None``), the
      modern/majority-case default (``False``) is assumed.
    """
    explicit = _android_attr(component, "exported")
    if explicit is not None:
        return explicit == "true"

    if is_provider:
        return (
            target_sdk is not None
            and target_sdk < _PROVIDER_EXPORTED_DEFAULT_SDK_CUTOFF
        )

    return has_intent_filter


def _parse_component(
    component: etree._Element, package: str | None, target_sdk: int | None
) -> dict[str, Any]:
    """Parse an activity/service/receiver element."""
    intent_filters = _parse_intent_filters(component)
    return {
        "name": _format_value(_android_attr(component, "name"), package),
        "exported": _is_exported(
            component,
            has_intent_filter=bool(intent_filters),
            is_provider=False,
            target_sdk=target_sdk,
        ),
        "permission": _android_attr(component, "permission"),
        "intent_filters": intent_filters,
    }


def _parse_provider(
    component: etree._Element, package: str | None, target_sdk: int | None
) -> dict[str, Any]:
    """Parse a content-provider element.

    A provider's blanket ``android:permission`` sets *both* read and write
    access when the more specific ``readPermission``/``writePermission``
    attributes are absent (real Android behavior -- the old dumpsys-based
    parser explicitly left this out of scope for lack of real data to
    verify against; it's folded in now that real manifest attributes are
    available directly).
    """
    blanket_permission = _android_attr(component, "permission")
    read_permission = _android_attr(component, "readPermission") or blanket_permission
    write_permission = _android_attr(component, "writePermission") or blanket_permission

    authorities_raw = _android_attr(component, "authorities")
    authorities = (
        [a.strip() for a in authorities_raw.split(";") if a.strip()]
        if authorities_raw
        else []
    )

    return {
        "name": _format_value(_android_attr(component, "name"), package),
        "exported": _is_exported(
            component, has_intent_filter=False, is_provider=True, target_sdk=target_sdk
        ),
        "read_permission": read_permission,
        "write_permission": write_permission,
        "authorities": authorities,
    }


def parse_component_info(
    manifest_xml: str, target_sdk: int | None = None
) -> dict[str, Any]:
    """Parse every exported-component-relevant element from a decoded manifest.

    Args:
        manifest_xml: A decoded ``AndroidManifest.xml`` as XML text (e.g.
            ``etree.tostring(apk.get_android_manifest_xml())``, where
            ``apk`` is an ``androguard.core.apk.APK`` instance). Not
            `dumpsys` output -- see the module docstring for why that data
            source doesn't work.
        target_sdk: The app's effective ``targetSdkVersion`` (e.g.
            ``apk.get_effective_target_sdk_version()``), used only to
            compute providers' implicit ``exported`` default when the
            manifest doesn't declare it explicitly. Pass ``None`` if
            unknown -- providers will then default to non-exported (the
            modern/majority-case behavior).

    Returns:
        ``{"components": {"activities": [...], "services": [...],
        "receivers": [...], "providers": [...]}}``. Activities/services/
        receivers entries are ``{"name", "exported", "permission",
        "intent_filters"}``; provider entries are ``{"name", "exported",
        "read_permission", "write_permission", "authorities"}``. Any
        component type absent from the manifest yields an empty list for
        that key.
    """
    root = etree.fromstring(manifest_xml.encode("utf-8"))
    package = root.get("package")

    components: dict[str, list[dict[str, Any]]] = {}
    for key, tag in _TAG_BY_KEY.items():
        elements = root.findall(f".//{tag}")
        if key == "providers":
            components[key] = [
                _parse_provider(element, package, target_sdk) for element in elements
            ]
        else:
            components[key] = [
                _parse_component(element, package, target_sdk) for element in elements
            ]

    return {"components": components}


def merge_component_info(infos: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge multiple :func:`parse_component_info` results (split APKs).

    Some apps (Android App Bundles with dynamic feature modules -- verified
    for real against Microsoft Edge, whose ``split_chrome.apk`` carries over
    a hundred activities absent from ``base.apk``) declare additional
    components in non-base split APKs, each with its own
    ``AndroidManifest.xml``. Merges by component ``name``, keeping the first
    occurrence (callers should pass ``base.apk``'s info first, since it's
    authoritative if a name were ever to appear in more than one split).

    Args:
        infos: One :func:`parse_component_info` result per APK split.

    Returns:
        A single merged result in the same shape as :func:`parse_component_info`.
    """
    merged: dict[str, list[dict[str, Any]]] = {key: [] for key in _TAG_BY_KEY}
    seen: dict[str, set[str | None]] = {key: set() for key in _TAG_BY_KEY}

    for info in infos:
        for key, component_list in info.get("components", {}).items():
            for component in component_list:
                name = component.get("name")
                if name in seen[key]:
                    continue
                seen[key].add(name)
                merged[key].append(component)

    return {"components": merged}
