#!/usr/bin/env python3
"""
Analyzes diff files to count and categorize different types of changes.
Usage: python diff_analyzer.py <path_to_diff_file>
"""

import sys
import json
# import lmstudio as lms
from pathlib import Path
from zipdetails_analyzer import analyze_zipdetails
from zipinfo_analyzer import analyze_zipinfo

MAX_DIFFOSCOPE_FILES = 50

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

    if "unified_diff" in diff and diff["unified_diff"]:
        if "zipdetails" in diff["source1"]:
            result += analyze_zipdetails(diff, result)
        elif "zipinfo" in diff["source1"]:
            result += analyze_zipinfo(diff, result)
        else:
            result += f"File diff type: {diff['source1']}\n"
            result += diff["unified_diff"]

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
        print("----------------------------\n")

    with open("report.txt", "w", encoding='utf-8') as f:
        f.write(aggregated_result)
