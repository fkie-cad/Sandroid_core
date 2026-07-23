import os
import os.path
import sqlite3
import subprocess
import tempfile
from collections.abc import Callable
from logging import getLogger
from pathlib import Path

from lxml import etree
from xmldiff import formatting, main

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


# returns a nicely formatted string, naming entries that have been added and removed from filename_database_of_interest
def db_diff(db_path1, db_path2, noise_path=None):
    """Calculates the differences between two database versions.

    :param db_path1: The full path to the first database file.
    :type db_path1: str
    :param db_path2: The full path to the second database file.
    :type db_path2: str
    :param noise_path: The full path to the noise database file (optional).
    :type noise_path: str
    :returns: A formatted string naming entries that have been added, removed, and updated.
    :rtype: str
    """
    diff = db_diff_helper(db_path1, db_path2)
    if not noise_path or not os.path.isfile(noise_path):
        return diff
    noise = db_diff_helper(db_path1, noise_path)
    result = ""
    if diff == noise:
        return "ITS ALL NOISE"
    for line in diff.splitlines():
        if line not in noise:
            result = result + line + "\n"
        else:
            # result = result + "[NOISE]" + line + "\n"
            pass
    return result


def db_diff_helper(db_path1, db_path2):
    """Helper function to calculate the differences between two database versions.

    :param db_path1: The full path to the first database file.
    :type db_path1: str
    :param db_path2: The full path to the second database file.
    :type db_path2: str
    :returns: A formatted string naming entries that have been added, removed, and updated.
    :rtype: str
    """
    # Check for WAL files
    if os.path.isfile(db_path1 + "-wal"):
        db_wal_helper(db_path1)
    if os.path.isfile(db_path2 + "-wal"):
        db_wal_helper(db_path2)

    # Check for journal files
    if os.path.isfile(db_path1 + "-journal"):
        db_journal_helper(db_path1)
    if os.path.isfile(db_path2 + "-journal"):
        db_journal_helper(db_path2)

    result = ""
    logger.debug(f"Calculating Database Diff between {db_path1} and {db_path2}")
    try:
        deleted_rows = subprocess.run(
            ["sqldiff", db_path2, db_path1],
            check=False,
            capture_output=True,
            text=False,
        )
    except OSError as e:
        logger.error(f"Failed to start sqldiff process: {e}")
        return "\tError: sqldiff command not found or failed to start"
    except subprocess.SubprocessError as e:
        logger.error(f"Subprocess error running sqldiff: {e}")
        return "\tError: sqldiff subprocess failed"
    try:
        deleted_stdout = deleted_rows.stdout.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        deleted_stdout = deleted_rows.stdout.decode("latin-1")

    logger.debug(f"Calculating reverse Database Diff between {db_path1} and {db_path2}")
    try:
        new_rows = subprocess.run(
            ["sqldiff", db_path1, db_path2],
            check=False,
            capture_output=True,
            text=False,
        )
    except OSError as e:
        logger.error(f"Failed to start sqldiff process: {e}")
        return "\tError: sqldiff command not found or failed to start"
    except subprocess.SubprocessError as e:
        logger.error(f"Subprocess error running sqldiff: {e}")
        return "\tError: sqldiff subprocess failed"
    try:
        new_stdout = new_rows.stdout.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        new_stdout = new_rows.stdout.decode("latin-1")

    complexity = new_stdout.count("\n") * 2 + deleted_stdout.count("\n")
    logger.debug(
        f"Inferring inserted, updated, and deleted content from the diffs. Working through {complexity} cases"
    )
    if complexity > 30000:
        logger.warning(
            f"Skipping intra file analysis of {db_path1} because the file is too big"
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
            for key in set(old_pairs) | set(new_pairs):
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

    :param xml_path1: The full path to the first XML file.
    :type xml_path1: str
    :param xml_path2: The full path to the second XML file.
    :type xml_path2: str
    :param noise_path: The full path to the noise XML file (optional).
    :type noise_path: str
    :returns: A formatted string naming entries that have been added, removed, and updated.
    :rtype: str
    """
    if not os.path.isfile(xml_path1) or not os.path.isfile(xml_path2):
        return "\tNot enough data for intra file analysis. At least one version was not pulled. Refer to errors or warnings created during pulls."

    diff = xml_diff_helper(xml_path1, xml_path2)
    if not os.path.isfile(noise_path):
        return xml_diff_beautify(diff)
    noise = xml_diff_helper(xml_path1, noise_path)
    result = ""
    if diff == noise:
        return "ITS ALL NOISE"
    for line in diff.splitlines():
        if line not in noise:
            result = result + line + "\n"
        else:
            # result = result + "[NOISE]" + line + "\n"
            pass
    return xml_diff_beautify(result)


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


def txt_xml_diff(file_path1, file_path2):
    """Calculates the differences between two text (aka normal) XML files.

    :param file_path1: The full path to the first XML file.
    :type file_path1: str
    :param file_path2: The full path to the second XML file.
    :type file_path2: str
    :returns: A formatted string naming entries that have been added and removed.
    :rtype: str
    """
    formatter = formatting.DiffFormatter(pretty_print=True)

    try:
        changes = main.diff_files(file_path1, file_path2, formatter=formatter)
    except etree.XMLSyntaxError as e:
        logger.error(f"XML Syntax Error encountered: {e}")
        return "\tNo change detected\n"

    if changes == "":
        return "\tNo change detected\n"

    s = changes.splitlines()
    result = ""
    for line in s:
        result = result + "\t" + line + "\n"
    return result


def abx_xml_diff(file_path1, file_path2):
    """Calculates the differences between two ABX XML files.

    Converts ABX binary XML files to text XML using ccl_abx, then delegates
    to txt_xml_diff for the actual comparison.

    :param file_path1: The full path to the first ABX XML file.
    :type file_path1: str
    :param file_path2: The full path to the second ABX XML file.
    :type file_path2: str
    :returns: A formatted string naming entries that have been added and removed.
    :rtype: str
    """
    logger.debug("Calculating ABX XML Diff between both versions of " + file_path1)
    logger.debug({"file_path1": file_path1, "file_path2": file_path2})

    # Convert the ABX files to XML in memory
    try:
        first_xml_result = subprocess.run(
            ["python3", "src/utils/ccl_abx.py", file_path1, "-mr"],
            check=False,
            capture_output=True,
            text=True,
        )
        first_xml = first_xml_result.stdout
    except OSError as e:
        logger.error(f"Failed to start ABX conversion process: {e}")
        return "\tError: ABX conversion failed - python3 or ccl_abx.py not found"
    except subprocess.SubprocessError as e:
        logger.error(f"Subprocess error during ABX conversion: {e}")
        return "\tError: ABX conversion subprocess failed"

    try:
        second_xml_result = subprocess.run(
            ["python3", "src/utils/ccl_abx.py", file_path2, "-mr"],
            check=False,
            capture_output=True,
            text=True,
        )
        second_xml = second_xml_result.stdout
    except OSError as e:
        logger.error(f"Failed to start ABX conversion process: {e}")
        return "\tError: ABX conversion failed - python3 or ccl_abx.py not found"
    except subprocess.SubprocessError as e:
        logger.error(f"Subprocess error during ABX conversion: {e}")
        return "\tError: ABX conversion subprocess failed"

    logger.debug("Converting ABX files to XML")
    logger.debug({"first_xml": first_xml, "second_xml": second_xml})

    # Write the converted XML into temporary files.
    with (
        tempfile.NamedTemporaryFile(mode="w", delete=True) as temp1,
        tempfile.NamedTemporaryFile(mode="w", delete=True) as temp2,
    ):
        temp1.write(first_xml)
        temp2.write(second_xml)
        temp1.flush()
        temp2.flush()
        temp1_name = temp1.name
        temp2_name = temp2.name
        diff = txt_xml_diff(temp1.name, temp2.name)

    if diff.strip() == "":
        return "\tNo change detected\n"
    return diff


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
            elif action == "update-text" and len(args) == 2:
                path, new_text = args
                formatted_line += f'Updated text: {path} to "{new_text}"'
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
    old_path = os.path.join(raw_results, "first_pull", txt_file)
    new_path = os.path.join(raw_results, "second_pull", txt_file)

    try:
        with open(old_path, encoding="utf-8") as f:
            old_text = f.readlines()
    except OSError as e:
        logger.error(f"Failed to open old text file '{old_path}': {e}")
        return f"\tError: Could not open file {old_path}"

    try:
        with open(new_path, encoding="utf-8") as f:
            new_text = f.readlines()
    except OSError as e:
        logger.error(f"Failed to open new text file '{new_path}': {e}")
        return f"\tError: Could not open file {new_path}"

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
