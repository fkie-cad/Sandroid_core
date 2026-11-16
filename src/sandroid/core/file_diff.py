import os
import os.path
import shutil
import sqlite3
import subprocess
import tempfile
import xml.etree.ElementTree as xmltree
from collections.abc import Callable
from logging import getLogger
from pathlib import Path

from lxml import etree

from sandroid.core.ccl_abx import AbxDecodeError, AbxReader

logger = getLogger(__name__)

# Cache to avoid re-reading files
_sqlite_file_cache = {}


def is_sqlite_file(file_path):
    r"""Check if a file is a SQLite database by reading its magic header.

    SQLite databases have a distinctive 16-byte header starting with "SQLite format 3\x00".
    This function reads the header to determine if a file is a SQLite database,
    regardless of its file extension.

    :param file_path: The full path to the file to check.
    :type file_path: str
    :returns: True if the file is a SQLite database, False otherwise.
    :rtype: bool
    """
    # Check cache first
    if file_path in _sqlite_file_cache:
        return _sqlite_file_cache[file_path]

    try:
        with open(file_path, "rb") as f:
            header = f.read(16)
            is_sqlite = header.startswith(b"SQLite format 3\x00")
            _sqlite_file_cache[file_path] = is_sqlite
            return is_sqlite
    except (FileNotFoundError, PermissionError, OSError) as e:
        logger.debug(f"Could not read file header for {file_path}: {e}")
        _sqlite_file_cache[file_path] = False
        return False


def is_sqlite_from_device_path(device_path, base_folder=""):
    """Check if a device file path corresponds to a SQLite database.

    This is a helper for noise filtering where we have device paths (like /data/data/...)
    and need to check if the pulled local file is a SQLite database.

    :param device_path: The device file path (e.g., /data/data/com.app/databases/file).
    :type device_path: str
    :param base_folder: The base folder where files are pulled (default to RAW_RESULTS_PATH).
    :type base_folder: str
    :returns: True if the file is a SQLite database or has .db extension, False otherwise.
    :rtype: bool
    """
    # Fast path: check common SQLite extensions
    if device_path.endswith((".db", ".sqlite", ".sqlite3", ".db3")):
        return True

    # Try to check the actual file header if it was pulled
    if not base_folder:
        base_folder = os.getenv("RAW_RESULTS_PATH")

    # Try first_pull directory first
    local_path = os.path.join(f"{base_folder}first_pull", device_path.lstrip("/"))
    if os.path.isfile(local_path):
        return is_sqlite_file(local_path)

    # Fallback: assume not SQLite if we can't check
    return False


# sqldiff will give a script to turn one db into another. So rows that are in db1 but not in db2 are inserted
# (INSERT INTO statement names the content we are interested in).
# Thats why, to get new rows that were added in run 2, we need the sqldiff of "db_run_1 db_run_2"
# To see content that was deleted in run 2, we need to reverse the order of the diff


#: Prefixes of diff strings that mean "this file could not be analysed" (as
#: opposed to "analysed, no change"). They are never compared against the
#: noise diff -- an identical failure on both sides is not noise.
_DIFF_FAILURE_PREFIXES: tuple[str, ...] = (
    "\tError:",
    "\tCould not analyse",
    "\tNot enough data",
    "\tToo many rows",
    "\tFailed to convert",
)

_NOT_ENOUGH_DATA = (
    "\tNot enough data for intra file analysis. At least one version was not "
    "pulled. Refer to errors or warnings created during pulls."
)

#: Logged once per process when ``sqldiff`` is missing.
_sqldiff_missing_warned = False


def is_diff_failure(diff):
    """Whether ``diff`` reports that a file could not be analysed."""
    return isinstance(diff, str) and diff.startswith(_DIFF_FAILURE_PREFIXES)


def is_no_change(diff):
    """Whether ``diff`` is one of the "analysed, nothing changed" messages."""
    return isinstance(diff, str) and diff.strip().lower() in (
        "no changes detected",
        "no change detected",
        "",
    )


def clear_caches():
    """Forget cached per-path facts (call once per analysis run).

    :func:`is_sqlite_file` caches by path string; the pull folders of a new
    run (or a re-pull into the same folder) can hold different files under
    the same paths.
    """
    _sqlite_file_cache.clear()


# returns a nicely formatted string, naming entries that have been added and removed from filename_database_of_interest
def db_diff(db_path1, db_path2, noise_path=None):
    """Calculates the differences between two database versions.

    The pulled databases (and their ``-wal``/``-journal`` companions) are
    never modified: pending writes are integrated into temporary copies.

    :param db_path1: The full path to the first database file.
    :type db_path1: str
    :param db_path2: The full path to the second database file.
    :type db_path2: str
    :param noise_path: The full path to the noise database file (optional).
    :type noise_path: str
    :returns: A formatted string naming entries that have been added, removed,
        and updated; ``"ITS ALL NOISE"`` only when there are real changes and
        every one of them also happened in the noise run.
    :rtype: str
    """
    if not os.path.isfile(db_path1) or not os.path.isfile(db_path2):
        return _NOT_ENOUGH_DATA
    diff = db_diff_helper(db_path1, db_path2)
    if not noise_path or not os.path.isfile(noise_path):
        return diff
    if is_diff_failure(diff) or is_no_change(diff):
        return diff
    noise = db_diff_helper(db_path1, noise_path)
    if is_diff_failure(noise) or is_no_change(noise):
        return diff
    noise_lines = set(noise.splitlines())
    kept = [line for line in diff.splitlines() if line not in noise_lines]
    if not kept:
        return "ITS ALL NOISE"
    return "".join(f"{line}\n" for line in kept)


def _copy_for_diff(db_path, dest_dir, name):
    """Copy a pulled database (+ ``-wal``/``-journal``) into ``dest_dir``.

    Pending WAL/journal content is integrated into the *copy* only, so the
    pulled evidence (hashed later into the manifest) stays byte-identical.
    ``-shm`` is not copied; SQLite rebuilds it for the copy.

    :returns: Path of the (integrated) copy.
    """
    copy = os.path.join(dest_dir, name)
    shutil.copyfile(db_path, copy)
    for suffix in ("-wal", "-journal"):
        if os.path.isfile(db_path + suffix):
            shutil.copyfile(db_path + suffix, copy + suffix)
    if os.path.isfile(copy + "-wal"):
        db_wal_helper(copy)
    if os.path.isfile(copy + "-journal"):
        db_journal_helper(copy)
    return copy


def _run_sqldiff(source, target):
    """Run ``sqldiff source target``; return ``(stdout, failure_message)``."""
    global _sqldiff_missing_warned
    try:
        proc = subprocess.run(
            ["sqldiff", source, target],
            check=False,
            capture_output=True,
            text=False,
        )
    except OSError as e:
        if not _sqldiff_missing_warned:
            _sqldiff_missing_warned = True
            logger.warning(
                "sqldiff could not be started (%s): SQLite databases are listed "
                "without row diffs. Install sqlite3-tools / sqldiff.",
                e,
            )
        return "", "\tCould not analyse: sqldiff command not found or failed to start"
    except subprocess.SubprocessError as e:
        logger.error(f"Subprocess error running sqldiff: {e}")
        return "", "\tCould not analyse: sqldiff subprocess failed"
    stdout = proc.stdout.decode("utf-8", errors="replace")
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace").strip()
        reason = (stderr.splitlines() or [f"exit code {proc.returncode}"])[0]
        logger.warning(f"sqldiff failed for {target}: {reason}")
        return stdout, f"\tCould not analyse: sqldiff failed ({reason})"
    return stdout, None


def db_diff_helper(db_path1, db_path2):
    """Helper function to calculate the differences between two database versions.

    Works on temporary copies (see :func:`_copy_for_diff`); neither VACUUM
    nor ``sqldiff`` ever touches the files at ``db_path1``/``db_path2``.

    :param db_path1: The full path to the first database file.
    :type db_path1: str
    :param db_path2: The full path to the second database file.
    :type db_path2: str
    :returns: A formatted string naming entries that have been added, removed, and updated.
    :rtype: str
    """
    try:
        with tempfile.TemporaryDirectory(prefix="sandroid_dbdiff_") as tmp:
            first = _copy_for_diff(db_path1, tmp, "first.db")
            second = _copy_for_diff(db_path2, tmp, "second.db")
            return _db_diff_copies(first, second, db_path1)
    except OSError as e:
        logger.error(f"Could not prepare database copies for diff: {e}")
        return f"\tCould not analyse: {e}"


def _db_diff_copies(db_path1, db_path2, display_path):
    """Diff two (already integrated, temporary) database copies."""
    result = ""
    logger.debug(f"Calculating Database Diff for {display_path}")
    deleted_stdout, failure = _run_sqldiff(db_path2, db_path1)
    if failure:
        return failure
    new_stdout, failure = _run_sqldiff(db_path1, db_path2)
    if failure:
        return failure

    complexity = new_stdout.count("\n") * 2 + deleted_stdout.count("\n")
    logger.debug(
        f"Inferring inserted, updated, and deleted content from the diffs. Working through {complexity} cases"
    )
    if complexity > 30000:
        logger.warning(
            f"Skipping intra file analysis of {display_path} because the file is too big"
        )
        return "\tToo many rows for intra file analysis ( more than 10000 )"

    if not new_stdout and not deleted_stdout:
        return "\tNo changes detected"

    # new rows
    for line in new_stdout.splitlines():
        words = line.split(" ")
        if words[0] == "INSERT":
            row_value = line[line.find("VALUES(") :]
            row_value = row_value[7:-2]
            table_of_row = words[2]
            table_of_row = table_of_row[0 : table_of_row.find("(")]
            result = (
                result
                + f"\t\\[[success]INSERT[/success]] Table \\[{table_of_row}] row \\[[success]{row_value}[/success]] has been added\n"
            )

    # updated rows
    for line in new_stdout.splitlines():
        words = line.split(" ")
        if words[0] == "UPDATE":
            row_value = line[line.find("SET") + 3 : line.find("WHERE")]
            table_of_row = words[1]
            update_condition = line[line.find("WHERE") + 6 : -1]
            # find matching update in deleted_rows to get old value
            old_value = ""
            for old_line in deleted_stdout.splitlines():
                words = old_line.split(" ")
                if (
                    words[0] == "UPDATE"
                    and words[1] == table_of_row
                    and old_line[old_line.find("WHERE") + 6 : -1] == update_condition
                ):
                    old_value = old_line[
                        old_line.find("SET") + 3 : old_line.find("WHERE")
                    ]

            # Parse key-value pairs from old_value and new_value (row_value)
            old_pairs = {}
            new_pairs = {}

            # Parse old values
            if old_value:
                for pair in old_value.split(","):
                    if "=" in pair:
                        key, value = pair.split("=", 1)
                        old_pairs[key.strip()] = value.strip()

            # Parse new values
            for pair in row_value.split(","):
                if "=" in pair:
                    key, value = pair.split("=", 1)
                    new_pairs[key.strip()] = value.strip()

            # Build a formatted diff string that highlights only changed values
            diff_details = []
            for key in dict.fromkeys([*old_pairs, *new_pairs]):
                old_val = old_pairs.get(key, "N/A")
                new_val = new_pairs.get(key, "N/A")

                if old_val != new_val:
                    # Use color for changed values
                    diff_details.append(
                        f"{key}=([warning]{old_val} → {new_val}[/warning])"
                    )
                else:
                    diff_details.append(f"{key}={old_val}")

            formatted_diff = ", ".join(diff_details)

            result = (
                result
                + f"\t\\[[warning]UPDATE[/warning]] Table \\[{table_of_row}] row "
                f"where \\[{update_condition}] changed: {formatted_diff}\n"
            )

    # deleted rows
    for line in deleted_stdout.splitlines():
        words = line.split(" ")
        if words[0] == "INSERT":
            row_value = line[line.find("VALUES(") :]
            row_value = row_value[7:-2]
            table_of_row = words[2]
            table_of_row = table_of_row[0 : table_of_row.find("(")]
            result = (
                result
                + f"\t\\[[error]DELETE[/error]] Table \\[{table_of_row}] row \\[[error]{row_value}[/error]] has been removed\n"
            )

    return result[:-1]


def _integrate_pending_writes(db_path, label, extra_pragmas=None):
    """Integrate pending writes (WAL or journal) into a SQLite database.

    :param db_path: The full path to the database file.
    :type db_path: str
    :param label: Human-readable label for log messages (e.g., "WAL", "journal").
    :type label: str
    :param extra_pragmas: Optional list of PRAGMA statements to execute before VACUUM.
    :type extra_pragmas: list[str] or None
    """
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    try:
        for pragma in extra_pragmas or []:
            cur.execute(pragma)
        cur.execute("VACUUM")
    except Exception as e:
        logger.warning(f"Failed to integrate {label} file for {db_path}: {e}")
    finally:
        con.close()


def db_wal_helper(db_path):
    """Integrates any temporary database files (.db-wal) that may be around.

    :param db_path: The full path to the database file whose .db-wal file to integrate.
    :type db_path: str
    """
    _integrate_pending_writes(db_path, "WAL")


def db_journal_helper(db_path):
    """Integrates any journal database files (.db-journal) that may be around.

    :param db_path: The full path to the database file whose .db-journal file to integrate.
    :type db_path: str
    """
    _integrate_pending_writes(
        db_path, "journal", extra_pragmas=["PRAGMA integrity_check"]
    )


def xml_diff(xml_path1, xml_path2, noise_path=None):
    """Calculates the differences between two XML files.

    Elements are matched by a stable key (see :func:`keyed_xml_diff`), so an
    added, updated or deleted SharedPreferences entry shows up as exactly
    that instead of as a cascade of positional moves.

    :param xml_path1: The full path to the first XML file.
    :type xml_path1: str
    :param xml_path2: The full path to the second XML file.
    :type xml_path2: str
    :param noise_path: The full path to the noise XML file (optional). Lines
        that also appear in the first-vs-noise diff are dropped.
    :type noise_path: str
    :returns: One tab-indented line per added, removed or updated entry, or
        ``"ITS ALL NOISE"`` when every change also happened without the app.
    :rtype: str
    """
    if not os.path.isfile(xml_path1) or not os.path.isfile(xml_path2):
        return _NOT_ENOUGH_DATA

    diff = xml_diff_helper(xml_path1, xml_path2)
    if not noise_path or not os.path.isfile(noise_path):
        return diff
    if is_diff_failure(diff) or is_no_change(diff):
        # A failure (or "no change") is reported as-is, never as noise.
        return diff
    noise = xml_diff_helper(xml_path1, noise_path)
    if is_diff_failure(noise) or is_no_change(noise):
        return diff
    noise_lines = set(noise.splitlines())
    kept = [line for line in diff.splitlines() if line not in noise_lines]
    if not kept and diff.strip() and _NO_XML_CHANGE.strip() not in diff:
        return "ITS ALL NOISE"
    return "".join(f"{line}\n" for line in kept) or _NO_XML_CHANGE


def xml_diff_helper(xml_path1, xml_path2):
    """Helper function to calculate the differences between two XML files.

    This function differentiates between normal XML files and binary XML (ABX) files.

    :param xml_path1: The full path to the first XML file.
    :type xml_path1: str
    :param xml_path2: The full path to the second XML file.
    :type xml_path2: str
    :returns: A formatted string naming entries that have been added and removed.
    :rtype: str
    """
    try:
        with open(xml_path1, "rb") as f:
            first_bytes = f.read(3)
    except OSError as e:
        logger.error(f"Failed to open XML file '{xml_path1}': {e}")
        return f"\tError: Could not open file {xml_path1}"

    if first_bytes == b"ABX":
        logger.debug("ABX file detected")
        return abx_xml_diff(xml_path1, xml_path2)
    return txt_xml_diff(xml_path1, xml_path2)


_NO_XML_CHANGE = "\tNo change detected\n"

#: Attributes that identify an element among its siblings, in priority order.
#: SharedPreferences use ``name``; package-restrictions/roles use ``name`` or
#: ``package``; the ground-truth app uses ``ID``.
XML_KEY_ATTRIBUTES: tuple[str, ...] = (
    "name",
    "key",
    "id",
    "ID",
    "package",
    "packageName",
    "task_id",
)


def _local_name(tag):
    """Strip an lxml ``{namespace}`` prefix from a tag or attribute name."""
    return tag.split("}", 1)[1] if tag.startswith("{") else tag


def _element_key_attr(element):
    """Return ``(attr, value)`` of the element's identifying attribute, if any."""
    attrs = {_local_name(k): v for k, v in element.attrib.items()}
    for name in XML_KEY_ATTRIBUTES:
        if name in attrs:
            return name, attrs[name]
    return None


def _child_elements(element):
    """Child elements, skipping comments and processing instructions."""
    return [child for child in element if isinstance(child.tag, str)]


def _split_children(element):
    """Split children into keyed (by path segment) and un-keyed (by tag).

    Keyed children (see :data:`XML_KEY_ATTRIBUTES`) get the segment
    ``tag[@attr="value"]``; a repeated key gets an extra occurrence index so
    no child is dropped. Un-keyed children are grouped per tag, in order.
    """
    keyed = {}
    unkeyed: dict[str, list] = {}
    for child in _child_elements(element):
        tag = _local_name(child.tag)
        key_attr = _element_key_attr(child)
        if key_attr is None:
            unkeyed.setdefault(tag, []).append(child)
            continue
        segment = f'{tag}[@{key_attr[0]}="{key_attr[1]}"]'
        if segment in keyed:
            n = 2
            while f"{segment}[{n}]" in keyed:
                n += 1
            segment = f"{segment}[{n}]"
        keyed[segment] = child
    return keyed, unkeyed


def _unkeyed_segment(tag, index, multiple):
    """Path segment of an un-keyed child: ``tag`` or ``tag[n]`` (1-based)."""
    return f"{tag}[{index + 1}]" if multiple else tag


def _signature(element):
    """Hashable deep fingerprint of an element (tag, attributes, text, children)."""
    return (
        _local_name(element.tag),
        tuple(sorted((_local_name(k), v) for k, v in element.attrib.items())),
        _element_text(element),
        tuple(_signature(child) for child in _child_elements(element)),
    )


def _pair_unkeyed(old_list, new_list):
    """Pair un-keyed same-tag siblings: identical ones first, then by position.

    Pairing identical subtrees first makes an insert into an unordered
    ``<set>`` (e.g. a SharedPreferences string set) come out as one
    ``[ADDED]`` instead of a chain of positional updates.

    Returns:
        ``(pairs, deleted, added)`` -- index pairs that need a recursive diff,
        and the old/new indexes without a partner.
    """
    by_signature: dict = {}
    for j, child in enumerate(new_list):
        by_signature.setdefault(_signature(child), []).append(j)
    used_new: set[int] = set()
    unmatched_old: list[int] = []
    for i, child in enumerate(old_list):
        candidates = by_signature.get(_signature(child))
        if candidates:
            used_new.add(candidates.pop(0))
        else:
            unmatched_old.append(i)
    unmatched_new = [j for j in range(len(new_list)) if j not in used_new]
    pairs = list(zip(unmatched_old, unmatched_new, strict=False))
    deleted = unmatched_old[len(pairs) :]
    added = unmatched_new[len(pairs) :]
    return pairs, deleted, added


def _element_text(element):
    return (element.text or "").strip()


def _one_line(value):
    """Escape line breaks so every diff entry stays on a single line."""
    return value.replace("\r", "\\r").replace("\n", "\\n")


#: Values longer than this are shown trimmed to the changed region.
_XML_VALUE_CONTEXT = 60


def _format_value_change(old, new):
    """Render ``"old" → "new"``, trimming long values to the changed region.

    Cookie maps and JSON blobs in SharedPreferences are several KB long and
    typically change in one timestamp; the shared prefix/suffix is elided
    with ``…`` so the change itself stays visible.
    """
    old, new = _one_line(old), _one_line(new)
    limit = 2 * _XML_VALUE_CONTEXT
    if len(old) <= limit and len(new) <= limit:
        return f'"{old}" → "{new}"'
    prefix = 0
    while prefix < min(len(old), len(new)) and old[prefix] == new[prefix]:
        prefix += 1
    suffix = 0
    while (
        suffix < min(len(old), len(new)) - prefix
        and old[-1 - suffix] == new[-1 - suffix]
    ):
        suffix += 1
    start = max(0, prefix - _XML_VALUE_CONTEXT)

    def clip(value):
        end = min(len(value), len(value) - suffix + _XML_VALUE_CONTEXT)
        head = "…" if start > 0 else ""
        tail = "…" if end < len(value) else ""
        return f"{head}{value[start:end]}{tail}"

    return f'"{clip(old)}" → "{clip(new)}"'


def _describe_element(element):
    """Render an element's attributes (minus its key) and text on one line."""
    key_attr = _element_key_attr(element)
    parts = [
        f'{_local_name(k)}="{_one_line(v)}"'
        for k, v in element.attrib.items()
        if key_attr is None or _local_name(k) != key_attr[0]
    ]
    text = _element_text(element)
    if text:
        parts.append(f'text="{_one_line(text)}"')
    return " ".join(parts)


def _emit_subtree(lines, label, path, element):
    """Emit ``[ADDED]``/``[DELETED]`` lines for an element and its descendants."""
    desc = _describe_element(element)
    lines.append(f"\t[{label}] {path}" + (f" {desc}" if desc else ""))
    keyed, unkeyed = _split_children(element)
    for segment, child in keyed.items():
        _emit_subtree(lines, label, f"{path}/{segment}", child)
    for tag, children in unkeyed.items():
        for i, child in enumerate(children):
            segment = _unkeyed_segment(tag, i, len(children) > 1)
            _emit_subtree(lines, label, f"{path}/{segment}", child)


def _diff_elements(lines, path, old, new):
    old_attrs = {_local_name(k): v for k, v in old.attrib.items()}
    new_attrs = {_local_name(k): v for k, v in new.attrib.items()}
    for name, value in new_attrs.items():
        if name not in old_attrs:
            lines.append(
                f"\t[UPDATED] {path} attribute '{name}' added: \"{_one_line(value)}\""
            )
        elif old_attrs[name] != value:
            change = _format_value_change(old_attrs[name], value)
            lines.append(f"\t[UPDATED] {path} {name}: {change}")
    for name, value in old_attrs.items():
        if name not in new_attrs:
            lines.append(
                f"\t[UPDATED] {path} attribute '{name}' removed"
                f' (was "{_one_line(value)}")'
            )
    old_text, new_text = _element_text(old), _element_text(new)
    if old_text != new_text:
        change = _format_value_change(old_text, new_text)
        lines.append(f"\t[UPDATED] {path} text: {change}")

    old_keyed, old_unkeyed = _split_children(old)
    new_keyed, new_unkeyed = _split_children(new)
    for segment, child in old_keyed.items():
        if segment not in new_keyed:
            _emit_subtree(lines, "DELETED", f"{path}/{segment}", child)
    for segment, child in new_keyed.items():
        child_path = f"{path}/{segment}"
        if segment in old_keyed:
            _diff_elements(lines, child_path, old_keyed[segment], child)
        else:
            _emit_subtree(lines, "ADDED", child_path, child)

    for tag in dict.fromkeys([*old_unkeyed, *new_unkeyed]):
        old_list = old_unkeyed.get(tag, [])
        new_list = new_unkeyed.get(tag, [])
        multiple = len(old_list) > 1 or len(new_list) > 1
        pairs, deleted, added = _pair_unkeyed(old_list, new_list)
        for i in deleted:
            segment = _unkeyed_segment(tag, i, multiple)
            _emit_subtree(lines, "DELETED", f"{path}/{segment}", old_list[i])
        for i, j in pairs:
            segment = _unkeyed_segment(tag, j, multiple)
            _diff_elements(lines, f"{path}/{segment}", old_list[i], new_list[j])
        for j in added:
            segment = _unkeyed_segment(tag, j, multiple)
            _emit_subtree(lines, "ADDED", f"{path}/{segment}", new_list[j])


def keyed_xml_diff(old_root, new_root):
    """Diff two parsed XML trees, matching elements by a stable key.

    Children are paired by tag plus their identifying attribute (``name``,
    ``key``, ``id``/``ID``, ``package`` ...; see :data:`XML_KEY_ATTRIBUTES`),
    or by position among same-tag siblings when they have none. Sibling order
    is ignored (SharedPreferences are an unordered map), so an insert or
    delete no longer shifts every following element. Output lines:

    * ``[ADDED] <path> <attributes/text>``
    * ``[DELETED] <path> <attributes/text>``
    * ``[UPDATED] <path> <attr>: "old" → "new"`` / ``text: "old" → "new"``

    :param old_root: Root element of the earlier version (lxml or ElementTree).
    :param new_root: Root element of the later version.
    :returns: Tab-indented, newline-terminated diff lines, or
        a "No change detected" line.
    :rtype: str
    """
    lines: list[str] = []
    old_tag, new_tag = _local_name(old_root.tag), _local_name(new_root.tag)
    if old_tag != new_tag:
        _emit_subtree(lines, "DELETED", f"/{old_tag}", old_root)
        _emit_subtree(lines, "ADDED", f"/{new_tag}", new_root)
    else:
        _diff_elements(lines, f"/{new_tag}", old_root, new_root)
    if not lines:
        return _NO_XML_CHANGE
    return "".join(f"{line}\n" for line in lines)


_XML_PARSER = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=True)


def _parse_xml_bytes(data):
    return etree.fromstring(data, parser=_XML_PARSER)


def txt_xml_diff(file_path1, file_path2):
    """Calculates the differences between two text (aka normal) XML files.

    :param file_path1: The full path to the first XML file.
    :type file_path1: str
    :param file_path2: The full path to the second XML file.
    :type file_path2: str
    :returns: A formatted string naming entries that have been added and removed.
    :rtype: str
    """
    try:
        old_root = _parse_xml_bytes(Path(file_path1).read_bytes())
        new_root = _parse_xml_bytes(Path(file_path2).read_bytes())
    except etree.XMLSyntaxError as e:
        logger.error(f"XML Syntax Error encountered: {e}")
        return f"\tCould not analyse: XML parse error ({e})\n"
    except OSError as e:
        logger.error(f"Failed to read XML file for diff: {e}")
        return f"\tError: Could not open file {e.filename}\n"
    return keyed_xml_diff(old_root, new_root)


def _format_xml_diff_output(changes):
    """Tab-indent a multi-line diff string (``"No change detected"`` if empty).

    :param changes: The diff text to indent.
    :type changes: str
    :returns: A tab-indented, newline-terminated diff string.
    :rtype: str
    """
    if not changes:
        return _NO_XML_CHANGE
    return "".join(f"\t{line}\n" for line in changes.splitlines())


def _convert_abx_to_xml_string(file_path):
    """Decode an ABX (Android Binary XML) file into a unicode XML string.

    :param file_path: The full path to the ABX file to decode.
    :type file_path: str
    :returns: The decoded document as a unicode XML string.
    :rtype: str
    :raises OSError: If the file cannot be opened or read.
    :raises ValueError: If the ABX magic header or a length field is invalid.
    :raises AbxDecodeError: If the ABX token stream is structurally malformed.
    """
    with open(file_path, "rb") as abx_file:
        reader = AbxReader(abx_file)
        document = reader.read(is_multi_root=True)
    return xmltree.tostring(document.getroot(), encoding="unicode")


def abx_xml_diff(file_path1, file_path2):
    """Calculates the differences between two ABX XML files.

    Decodes both files in-process using the repo's own ``AbxReader``
    decoder (:mod:`sandroid.core.ccl_abx`) and diffs the resulting trees
    with :func:`keyed_xml_diff` -- no subprocess, no temporary files.

    :param file_path1: The full path to the first ABX file.
    :type file_path1: str
    :param file_path2: The full path to the second ABX file.
    :type file_path2: str
    :returns: A formatted string naming entries that have been added and removed.
    :rtype: str
    """
    logger.debug("Calculating ABX XML Diff between both versions of " + file_path1)

    try:
        first_xml = _convert_abx_to_xml_string(file_path1)
        second_xml = _convert_abx_to_xml_string(file_path2)
    except (OSError, ValueError, AbxDecodeError, NotImplementedError) as exc:
        # NotImplementedError: ccl_abx refuses mixed text/element content.
        logger.error(f"Failed to convert ABX files for diff: {exc}")
        return f"\tCould not analyse: Failed to convert ABX files for diff ({exc})\n"

    try:
        old_root = _parse_xml_bytes(first_xml.encode("utf-8"))
        new_root = _parse_xml_bytes(second_xml.encode("utf-8"))
    except etree.XMLSyntaxError as e:
        logger.error(f"XML Syntax Error encountered while diffing ABX XML: {e}")
        return f"\tCould not analyse: decoded ABX is not well-formed XML ({e})\n"
    return keyed_xml_diff(old_root, new_root)


def xml_diff_beautify(raw_diff_string):
    """Formats the raw output from xmldiff into a more readable natural language format.

    :param raw_diff_string: The raw diff string from xmldiff.
    :type raw_diff_string: str
    :returns: A formatted, human-readable string describing the XML changes, without colors.
    :rtype: str
    """
    beautified_lines = []
    for line in raw_diff_string.strip().splitlines():
        line = line.strip()  # Remove leading/trailing whitespace
        if not line.startswith("[") or not line.endswith("]"):
            beautified_lines.append(
                f"\t{line}"
            )  # Keep lines that don't match the pattern
            continue

        try:
            # Remove brackets and split by comma + space
            parts = line[1:-1].split(", ")
            action = parts[0]

            # Clean up paths/values by removing potential extra quotes
            args = [p.strip().strip("'\"") for p in parts[1:]]

            formatted_line = "\t"  # Start with a tab for indentation

            if action == "move" and len(args) == 3:
                path, target_parent, position = args
                formatted_line += (
                    f"Moved: {path} to position {position} under {target_parent}"
                )
            elif action == "update-text" and len(args) in (2, 3):
                # xmldiff >= 2.5 appends the old text ("null" for none).
                path, new_text = args[0], args[1]
                old_text = args[2] if len(args) == 3 else "null"
                if new_text == "null":
                    new_text = ""
                formatted_line += f'Updated text: {path} to "{new_text}"'
                if old_text != "null":
                    formatted_line += f' (was "{old_text}")'
            elif action == "update-attribute" and len(args) == 3:
                path, attr_name, new_value = args
                formatted_line += f"Updated attribute: {path} attribute '{attr_name}' to \"{new_value}\""
            elif action == "delete" and len(args) == 1:
                path = args[0]
                formatted_line += f"Deleted: {path}"
            elif action == "insert" and len(args) == 3:
                parent_path, element_name, position = args
                formatted_line += f"Inserted: element '{element_name}' at position {position} under {parent_path}"
            elif action == "insert-attribute" and len(args) == 3:
                path, attr_name, value = args
                formatted_line += f"Inserted attribute: {path} attribute '{attr_name}' with value \"{value}\""
            else:
                # Fallback for unknown actions or incorrect argument counts
                formatted_line += f"Unknown: {line}"

            beautified_lines.append(formatted_line)

        except Exception:
            beautified_lines.append(f"\tMalformed: {line}")

    return "\n".join(beautified_lines)


def txt_diff(txt_file):
    """Calculates the differences between two text files.

    :param txt_file: The name of the text file to compare.
    :type txt_file: str
    :returns: A formatted string naming entries that have been added and removed.
    :rtype: str
    """
    raw_results = os.getenv("RAW_RESULTS_PATH", "")
    # Device paths are absolute ("/data/..."); os.path.join would discard the
    # pull-folder prefix for them and open the *device* path on the host.
    relative = txt_file.lstrip("/")
    old_path = os.path.join(raw_results, "first_pull", relative)
    new_path = os.path.join(raw_results, "second_pull", relative)
    # Same algorithm; txt_diff_paths also survives non-UTF-8 content.
    return txt_diff_paths(old_path, new_path)


def txt_diff_paths(old_path, new_path):
    """Calculates the differences between two text files given explicit paths.

    Same line-set diff algorithm as :func:`txt_diff`, but takes the two file
    paths directly instead of assuming the ``RAW_RESULTS_PATH``/
    ``first_pull``/``second_pull`` convention baked into that function's
    signature. Added for callers with their own baseline-cache layout (e.g.
    the Files tab's Watchlist sub-tab, which keeps a ``previous``/``current``
    pull cache per watched path) that still want the same textual diffing
    ``ChangedFiles.return_data()`` uses for ``.txt`` files. Deliberately a
    **new** function rather than an overload of ``txt_diff``'s signature --
    ``ChangedFiles.return_data()`` calls ``txt_diff(file)`` as-is and must be
    left untouched.

    Also tolerates non-UTF-8/binary content (returning a friendly error
    string instead of raising ``UnicodeDecodeError``), unlike ``txt_diff``:
    that function is only ever called for files already known to be
    ``.txt``, while this one may be used as a generic fallback for files
    whose type isn't otherwise recognized.

    :param old_path: Full path to the "before" version of the file.
    :type old_path: str
    :param new_path: Full path to the "after" version of the file.
    :type new_path: str
    :returns: A formatted string naming lines that have been added and removed.
    :rtype: str
    """
    try:
        with open(old_path, encoding="utf-8") as f:
            old_text = f.readlines()
    except OSError as e:
        logger.error(f"Failed to open old text file '{old_path}': {e}")
        return f"\tError: Could not open file {old_path}"
    except UnicodeDecodeError as e:
        logger.debug(f"'{old_path}' is not valid UTF-8 text: {e}")
        return f"\tError: {old_path} is not a text file"

    try:
        with open(new_path, encoding="utf-8") as f:
            new_text = f.readlines()
    except OSError as e:
        logger.error(f"Failed to open new text file '{new_path}': {e}")
        return f"\tError: Could not open file {new_path}"
    except UnicodeDecodeError as e:
        logger.debug(f"'{new_path}' is not valid UTF-8 text: {e}")
        return f"\tError: {new_path} is not a text file"

    # Use sets for efficient membership testing
    old_set = set(old_text)
    new_set = set(new_text)

    parts = []
    for line in old_text:
        if line not in new_set:
            parts.append(f"\t[LINE DELETED] {line}")

    for line in new_text:
        if line not in old_set:
            parts.append(f"\t[LINE ADDED] {line}")

    return "".join(parts)


def diff_files(
    previous_main: Path, current_main: Path, is_sqlite_fn: Callable[[str], bool]
) -> tuple[str, bool]:
    """Diff *current_main* against *previous_main* by extension/magic-header dispatch.

    Promoted from ``tui/widgets/watchlist_view.py``'s originally-private
    ``_compute_diff`` (that function is now a thin delegator to this one) so
    the AI chat's ``get_file_diff`` tool
    (:mod:`sandroid.ai.tools.monitor_control`) can reuse the exact same
    dispatch instead of a second, drifting copy.

    Uses the SAME extension/magic-header dispatch
    ``ChangedFiles.return_data()`` uses (``core/changedfiles.py``):
    *is_sqlite_fn* -> :func:`db_diff`, ``.xml`` -> :func:`xml_diff`.
    Deliberately **widened** from that dispatch's ``.txt``-only text
    fallback to *any* other file (via :func:`txt_diff_paths`) -- both
    Watchlist and the AI tool are frequently pointed at extension-less
    config/log files, and ChangedFiles' own "no dispatch match -> no diff at
    all" behavior would make diffing nearly useless for exactly the files
    people are most likely to hand-add here. This is the one deliberate
    deviation from a literal reading of "the SAME dispatch logic".

    Args:
        previous_main: The "before" file (the last-promoted baseline).
        current_main: The "after" file (freshly pulled).
        is_sqlite_fn: The magic-header sniff to use for the SQLite check.
            Callers MUST pass an **uncached** check (e.g.
            ``file_extraction_service.is_sqlite_file``), NOT this module's
            own :func:`is_sqlite_file` -- that one keeps a process-lifetime
            cache keyed by path string with no invalidation, which is wrong
            here: both Watchlist's and this tool's ``current``/``previous``
            paths are fixed and get overwritten in place on every pull, so a
            cached answer from an earlier pull would silently outlive
            whatever a later pull wrote to that same path.

    Returns:
        ``(diff_text, changed)`` -- ``changed`` is False when the
        underlying diff function reports "no change(s)" in its own words
        (its established convention), so the caller can show a plain
        "unchanged" message instead of an empty/no-op diff view.
    """
    prev_str, cur_str = str(previous_main), str(current_main)
    if is_sqlite_fn(prev_str):
        diff = db_diff(prev_str, cur_str, "")
    elif previous_main.suffix.lower() == ".xml":
        diff = xml_diff(prev_str, cur_str, "")
    else:
        diff = txt_diff_paths(prev_str, cur_str)
    changed = bool(diff.strip()) and "no change" not in diff.lower()
    return diff, changed


# to get the sqldiff tool, run "sudo apt install sqlite3-tools"
