import os
import os.path
import sqlite3
import subprocess
import tempfile
from logging import getLogger

from colorama import Fore, Style
from lxml import etree
from xmldiff import formatting, main

logger = getLogger(__name__)


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
    deleted_rows = subprocess.run(
        ["sqldiff", db_path2, db_path1], check=False, capture_output=True, text=False
    )
    try:
        deleted_stdout = deleted_rows.stdout.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        deleted_stdout = deleted_rows.stdout.decode("latin-1")

    logger.debug(f"Calculating reverse Database Diff between {db_path1} and {db_path2}")
    new_rows = subprocess.run(
        ["sqldiff", db_path1, db_path2], check=False, capture_output=True, text=False
    )
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
                + f"\t[{Fore.GREEN}INSERT{Style.RESET_ALL}] Table [{table_of_row}] row [{Fore.GREEN}{row_value}{Style.RESET_ALL}] has been added\n"
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
                        f"{key}=({Fore.YELLOW}{old_val} → {new_val}{Style.RESET_ALL})"
                    )
                else:
                    diff_details.append(f"{key}={old_val}")

            formatted_diff = ", ".join(diff_details)

            result = (
                result
                + f"\t[{Fore.YELLOW}UPDATE{Style.RESET_ALL}] Table [{table_of_row}] row "
                f"where [{update_condition}] changed: {formatted_diff}\n"
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
                + f"\t[{Fore.RED}DELETE{Style.RESET_ALL}] Table [{table_of_row}] row [{Fore.RED}{row_value}{Style.RESET_ALL}] has been removed\n"
            )

    return result[:-1]


def db_wal_helper(db_path):
    """Integrates any temporary database files (.db-wal) that may be around.

    :param db_path: The full path to the database file whose .db-wal file to integrate.
    :type db_path: str
    """
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    try:
        cur.execute("VACUUM")
    except Exception as e:
        logger.warning(f"Failed to integrate WAL file for {db_path}: {e}")
    finally:
        con.close()


def db_journal_helper(db_path):
    """Integrates any journal database files (.db-journal) that may be around.

    :param db_path: The full path to the database file whose .db-journal file to integrate.
    :type db_path: str
    """
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    try:
        # PRAGMA integrity_check ensures the journal is applied
        cur.execute("PRAGMA integrity_check")
        # VACUUM rebuilds the database
        cur.execute("VACUUM")
    except Exception as e:
        logger.warning(f"Failed to integrate journal file for {db_path}: {e}")
    finally:
        con.close()


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
    file = open(xml_path1, "rb")
    # Read the first 3 bytes to check if it's an ABX file
    first_bytes = file.read(3)
    file.close()
    if first_bytes == b"ABX":
        logger.debug("ABX file detected")
        return abx_xml_diff(xml_path1, xml_path2)
    # Use full paths for txt_xml_diff
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

    :param xml_file: The name of the XML file to compare.
    :type xml_file: str
    :param dir1: The base directory of the first XML version.
    :type dir1: str
    :param dir2: The base directory of the second XML version.
    :type dir2: str
    :returns: A formatted string naming entries that have been added and removed.
    :rtype: str
    """
    logger.debug("Calculating ABX XML Diff between both versions of " + file_path1)
    logger.debug({"file_path1": file_path1, "file_path2": file_path2})

    # Convert the ABX files to XML in memory
    first_xml = subprocess.run(
        ["python3", "src/utils/ccl_abx.py", file_path1, "-mr"],
        check=False,
        capture_output=True,
        text=True,
    ).stdout

    second_xml = subprocess.run(
        ["python3", "src/utils/ccl_abx.py", file_path2, "-mr"],
        check=False,
        capture_output=True,
        text=True,
    ).stdout

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
    old = open(f"{os.getenv('RAW_RESULTS_PATH')}first_pull/{txt_file}")
    new = open(f"{os.getenv('RAW_RESULTS_PATH')}second_pull/{txt_file}")

    old_text = old.readlines()
    new_text = new.readlines()

    result = ""

    for line in old_text:
        if line not in new_text:
            result = result + "\t[LINE DELETED] " + line

    for line in new_text:
        if line not in old_text:
            result = result + "\t[LINE ADDED] " + line

    return result


# to get the sqldiff tool, run "sudo apt install sqlite3-tools"
