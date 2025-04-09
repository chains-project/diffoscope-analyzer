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

ZIPDETAILS_DIFF_PATTERN = re.compile(r'^(?P<sign>[+-])(?:(?P<address>[A-F0-9]+)\s+(?P<data_type>[A-z]+(?:\s[A-z1-9#]+)*)+|\W+(?P<bit>\[Bits? [\d-]+\]))\s+(?P<value>.+)$')
MAX_DIFFOSCOPE_FILES = 20

def analyze_diff_portion(diff: str, diff_types: Counter) -> int:
    total_diffs = 0

    changes: dict[str, dict[str, str]] = {}
    for line in diff.splitlines():
        # Extract the type of diff (the label of what changed)
        match = ZIPDETAILS_DIFF_PATTERN.search(line)
        # Skip lines that don't match the expected pattern
        # Sometimes we see lines that aren't relevant so we skip them for now
        if not match:
            continue
        else:
            sign = match.group("sign")
            address = match.group("address")
            data_type = match.group("data_type")
            value = match.group("value")

            if data_type not in changes:
                changes[data_type] = {}

            # Skip bit info
            if match.group("bit"):
                continue

            if sign == '-':
                changes[data_type].update({"address_before": address, "value_before": value})
            elif sign == '+':
                changes[data_type].update({"address_after": address, "value_after": value})
            else:
                raise ValueError(f"Invalid diff sign: {sign}")

    for data_type, obj in changes.items():
        if obj.get("value_before") != obj.get("value_after"):
            total_diffs += 1
            diff_type = data_type
            diff_types[diff_type] += 1

    return total_diffs

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

def analyze_diff_node(diff: dict) -> str:
    result = "\n-----------------------\n"
    diff_types = Counter()
    total_diffs = 0

    if "zipdetails" not in diff["source1"]:
        result = ""
        pass # Only analyze zipdetails diffs for now
    elif "unified_diff" in diff and diff["unified_diff"]:
        result += f"Source 1: {diff['source1']}\n"
        result += f"Source 2: {diff['source2']}\n"
        diff_lines = diff["unified_diff"].splitlines()

        diff_portion = []
        for line in diff_lines:
            if line.startswith('+') or line.startswith('-'):
                diff_portion.append(line)
            elif diff_portion:
                total_diffs += analyze_diff_portion('\n'.join(diff_portion), diff_types)
                diff_portion = []
                # result += line + '\n'

        if diff_portion:
            total_diffs += analyze_diff_portion('\n'.join(diff_portion), diff_types)

        result += f"\nTotal number of diffs: {total_diffs:,}"
        result += "\nTypes of diffs:"
        for diff_type, count in diff_types.most_common():
            percentage = (count / total_diffs) * 100
            result += f"\n{diff_type}: {count:,} occurrences ({percentage:.2f}%)"

    if "details" in diff:
        for detail in diff["details"]:
            result += analyze_diff_node(detail)

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

    for file_path in gather_x_diffoscope_files(Path(sys.argv[1]), MAX_DIFFOSCOPE_FILES):
        print(f"Analyzing file: {file_path}")
        result = analyze_diff_file(file_path)
        # Create output path in the output directory
        output_path = output_dir / file_path.name.replace(".diffoscope.json", ".analysis.txt")
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(result)
