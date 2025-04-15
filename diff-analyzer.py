#!/usr/bin/env python3
"""
Analyzes diff files to count and categorize different types of changes.
Usage: python diff_analyzer.py <path_to_diff_file>
"""

import re
import sys
import json
import lmstudio as lms
from collections import Counter
from pathlib import Path

ZIPDETAILS_DIFF_PATTERN = re.compile(r'^(?P<sign>[+-])(?:(?P<address>[A-F0-9]+)\s+(?P<data_type>[A-z]+(?:\s[A-z1-9#]+)*)+|\W+(?P<bit>\[Bits? [\d-]+\]))\s*(?P<value>.+)?$')
ZIPINFO_HEADER_PATTERN = re.compile(r'^([+-])Zip file size: (\d+ bytes), number of entries: (\d+)$')
ZIPINFO_FILE_PATTERN = re.compile(r"""
^(?P<sign>[+-])
(?P<perm>[\-dcbslprwxRWXsStT]+)\s+
(?P<version>\d+\.\d+)\s+
(?P<os>[a-z]{3})\s+
(?P<size>\d+)\s+
(?P<flags>\S{2})\s+
(?P<method>\S{4})\s+
(?P<date>\d{2}-[A-Za-z]{3}-\d{2})\s+
(?P<time>\d{2}:\d{2})\s+
(?P<path>.+)
""".replace('\n', ''))

MAX_DIFFOSCOPE_FILES = 20

def gather_x_diffoscope_files(root_dir: Path, numberOfFiles) -> list[Path]:
    """
    Gather x diffoscope files from the given directory and its subdirectories.
    """
    if not root_dir.is_dir():
        raise ValueError(f"Provided path {root_dir} is not a directory.")
    diffoscope_files = []
    for path in root_dir.rglob('*.diffoscope.*'):
        if len(diffoscope_files) >= numberOfFiles:
            break
        diffoscope_files.append(path)
    return diffoscope_files

def analyze_diff_portion(diff_lines: list[str], diff_types: Counter) -> int:
    total_diffs = 0

    changes: dict[str, dict[str, str]] = {}
    for line in diff_lines:
        # Extract the type of diff (the label of what changed)
        match = ZIPDETAILS_DIFF_PATTERN.search(line)
        # Skip lines that don't match the expected pattern
        # Sometimes we see lines that aren't relevant so we skip them for now
        if not match:
            continue
        else:
            # Skip bit info
            if match.group("bit"):
                continue

            sign = match.group("sign")
            address = match.group("address")
            data_type = match.group("data_type")
            value = match.group("value")

            if "offset" in data_type.lower():
                # Skip offset lines
                continue

            if data_type not in changes:
                changes[data_type] = {}

            if sign == '-':
                changes[data_type].update({"address_before": address, "value_before": value})
            elif sign == '+':
                changes[data_type].update({"address_after": address, "value_after": value})
            else:
                raise ValueError(f"Invalid diff sign: {sign}")

    for data_type, obj in changes.items():
        # print(f"Data type: {data_type} {obj}")
        if obj.get("value_before") != obj.get("value_after"):
            # print(f"{obj.get('address_before')} -> {obj.get('address_after')} {obj.get('value_before')} -> {obj.get('value_after')}")
            # print(f"Adding diff {data_type} {obj['value_before']} -> {obj['value_after']}")
            total_diffs += 1
            diff_type = data_type
            diff_types[diff_type] += 1

    return total_diffs

def analyze_diff_node(diff: dict) -> str:
    result = "\n-----------------------\n"

    if "unified_diff" in diff and diff["unified_diff"]:
        if "zipdetails" in diff["source1"]:
            result += analyze_zipdetails(diff, result)
        elif "zipinfo" in diff["source1"]:
            result += analyze_zipinfo(diff, result)
        else:
            result = ""

    if "details" in diff:
        for detail in diff["details"]:
            result += analyze_diff_node(detail)

    return result

def analyze_zipdetails(diff, result):
    total_diffs = 0
    diff_types = Counter()
    result += f"Source 1: {diff['source1']}\n"
    result += f"Source 2: {diff['source2']}\n"
    diff_lines = diff["unified_diff"].splitlines()

    diff_portion = []
    for line in diff_lines:
        if line.startswith('+') or line.startswith('-'):
            diff_portion.append(line)
        elif diff_portion:
            total_diffs += analyze_diff_portion(diff_portion, diff_types)
            diff_portion = []
                # result += line + '\n'

    if diff_portion:
        total_diffs += analyze_diff_portion(diff_portion, diff_types)

    result += f"\nTotal number of diffs: {total_diffs:,}"
    result += "\nTypes of diffs:"
    for diff_type, count in diff_types.most_common():
        percentage = (count / total_diffs) * 100
        result += f"\n{diff_type}: {count:,} occurrences ({percentage:.2f}%)"

    return result

def analyze_zipinfo(diff, result):
    result += f"Source 1: {diff['source1']}\n"
    result += f"Source 2: {diff['source2']}\n"

    diff_lines = diff["unified_diff"].splitlines()

    # Let's define different types of reasons for diffs
    timestamp_change = False
    permission_change = False
    number_of_files_change = False
    file_content_or_size_change = False
    file_reordered_change = False
    file_removed_change = False
    file_added_change = False


    diff_line_results = {}
    for line in diff_lines:
        header_match = ZIPINFO_HEADER_PATTERN.search(line)
        if header_match:
            sign = header_match.group(1)
            if "zipinfo_header" not in diff_line_results:
                diff_line_results["zipinfo_header"] = {}
            if sign == '-':
                size_before = header_match.group(2)
                num_entries_before = header_match.group(3)
                diff_line_results["zipinfo_header"].update({
                            "size_before": size_before,
                            "num_entries_before": num_entries_before,
                        })
            elif sign == '+':
                size_after = header_match.group(2)
                num_entries_after = header_match.group(3)
                diff_line_results["zipinfo_header"].update({
                            "size_after": size_after,
                            "num_entries_after": num_entries_after,
                        })

        file_diff_match = ZIPINFO_FILE_PATTERN.search(line)
        if file_diff_match:
            sign = file_diff_match.group("sign")
            permissions = file_diff_match.group("perm")
            size = file_diff_match.group("size")
            date = file_diff_match.group("date")
            path = file_diff_match.group("path")

            if path not in diff_line_results:
                diff_line_results[path] = {}

            if sign == "-":
                diff_line_results[path].update({
                            "permissions_before": permissions,
                            "size_before": size,
                            "date_before": date,
                        })
            if sign == "+":
                diff_line_results[path].update({
                            "permissions_after": permissions,
                            "size_after": size,
                            "date_after": date,
                        })


    if "zipinfo_header" not in diff_line_results:
                result += "No zipinfo header change.\n"

    date_change_count = 0
    for key, changes in diff_line_results.items():
        if key == "zipinfo_header":
            if changes["size_before"] != changes["size_after"]:
                file_content_or_size_change = True
                result += f"Zip file size changed from {size_before} bytes to {size_after} bytes.\n"
            if changes["num_entries_before"] != changes["num_entries_after"]:
                number_of_files_change = True
                result += f"Number of entries changed from {num_entries_before} to {num_entries_after}.\n"
            if changes["size_before"] == changes["size_after"] and changes["num_entries_before"] == changes["num_entries_after"]:
                result += "No zipinfo header change even though there is a diff in header.\n"
        else:
            path = key
            if "date_before" in changes and "date_after" in changes:
                date_changed = changes["date_before"] != changes["date_after"]
                permissions_changed = changes["permissions_before"] != changes["permissions_after"]
                size_changed = changes["size_before"] != changes["size_after"]

                if date_changed and not permissions_changed and not size_changed:
                    date_change_count += 1
                    continue

                result += f"\nChanges for file: {path}\n"
                if date_changed:
                    timestamp_change = True
                    result += f"Date changed from {changes['date_before']} to {changes['date_after']}\n"
                if permissions_changed:
                    permission_change = True
                    result += f"Permissions changed from {changes['permissions_before']} to {changes['permissions_after']}\n"
                if size_changed:
                    file_content_or_size_change = True
                    result += f"Size changed from {changes['size_before']} to {changes['size_after']}\n"
                if not date_changed and not permissions_changed and not size_changed:
                    file_reordered_change = True
                    result += "File is probably reordered\n"
            elif "date_before" in changes and "date_after" not in changes:
                file_removed_change = True
                result += f"\nFile removed. {path}\n"
            elif "date_before" not in changes and "date_after" in changes:
                file_added_change = True
                result += f"\nFile added. {path}\n"
            else:
                raise ValueError(f"Unexpected changes for file: {path}")

    if timestamp_change:
        print("Timestamp(s) changed")
    if permission_change:
        print("File permissions changed")
    if number_of_files_change:
        print("Number of files changed")
    if file_content_or_size_change:
        print("File content or file size changed")
    if file_reordered_change:
        print("File(s)  reordered")
    if file_removed_change:
        print("File(s) removed")
    if file_added_change:
        print("File(s) added")


    if date_change_count > 0:
        result += f"\n{date_change_count} files changed only their date.\n"

    return result

def analyze_diff_file(file_path: Path) -> str:
    # Initialize counters
    result = ""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            diff_data: dict = json.loads(f.read())
            result += analyze_diff_node(diff_data)
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
        sys.exit(1)

    return result


def analyze_file_diff(diff: str) -> str:
    # model = lms.llm("gemma-3-27b-it")
    # result = model.respond("Tell me the cause of the diff in the following diff input. Be thorough but concice:\n" + diff[:4000])
    result = "Disabled for now"
    return str(result)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)

    # Create output directory if it doesn't exist
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    aggregated_result = ""
    for file_path in gather_x_diffoscope_files(Path(sys.argv[1]), MAX_DIFFOSCOPE_FILES):
        print(f"File: {file_path}")
        result = analyze_diff_file(file_path)
        aggregated_result += result
        # Create output path in the output directory
        output_path = output_dir / file_path.name.replace(".diffoscope.json", ".analysis.txt")
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(result)
        print(f"Report at {output_path}\n")

    with open("report.txt", "w", encoding='utf-8') as f:
        f.write(aggregated_result)
