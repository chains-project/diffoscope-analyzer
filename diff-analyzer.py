#!/usr/bin/env python3
"""
Analyzes diff files to count and categorize different types of changes.
Usage: python diff_analyzer.py <path_to_diff_file>
"""

import sys
import json
import time
import constants
# import lmstudio as lms # type: ignore
from pathlib import Path
from analyzers.zipdetails_analyzer import analyze_zipdetails
from analyzers.zipinfo_analyzer import analyze_zipinfo
from analyzers.file_list_analyzer import analyze_file_list
from analyzers.file_diff_analyzer import analyze_file_diff

MAX_DIFFOSCOPE_FILES = 500

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


def analyze_diff_node(diff: dict) -> tuple[set[str],str]:
    change_types, report = analyze_diff_node_recursive(diff)

    for change_type in change_types:
        print(f"Change type: {change_type}")
    if not change_types:
        report += "Unknown changes.\n"
        change_types.add(constants.UNKNOWN_CHANGE)

    return (change_types, report)


def analyze_diff_node_recursive(diff: dict) -> tuple[set[str],str]:
    report = "\n-----------------------\n"
    change_types = set()

    if "unified_diff" in diff and diff["unified_diff"]:
        if "zipinfo" in diff["source1"]:
            (zipinfo_change_types, zipinfo_report) = analyze_zipinfo(diff, report)
            report += zipinfo_report
            change_types = change_types | zipinfo_change_types
        elif "file list" in diff["source1"]:
            (file_list_change_types, file_list_report) = analyze_file_list(diff, report)
            report += file_list_report
            change_types = change_types | file_list_change_types
        elif "zipdetails" in diff["source1"]:
            report += analyze_zipdetails(diff, report)
        else:
            pass
            (file_diff_change_types, report) = analyze_file_diff(diff, report)
            change_types = change_types | file_diff_change_types
            # report += diff["unified_diff"]

    if "details" in diff:
        for detail in diff["details"]:
            (child_change_type, report) = analyze_diff_node_recursive(detail)
            change_types = change_types | child_change_type
            report += report

    return (change_types, report)


def process_diffoscope_files(input_path: Path, output_dir: Path) -> dict:
    change_types_dict = {}
    file_count = 0

    for file_path in gather_x_diffoscope_files(input_path, MAX_DIFFOSCOPE_FILES):
        file_count += 1
        print(f"File: {file_path}")
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                diff_data: dict = json.loads(f.read())
            (change_types, report) = analyze_diff_node(diff_data)
            if change_types:
                for change_type in change_types:
                    change_types_dict.setdefault(change_type, [])
                    change_types_dict[change_type].append(file_path)
                change_types_dict.setdefault(frozenset(change_types), [])
                change_types_dict[frozenset(change_types)].append(file_path)

            # Create output path in the output directory
            output_path = output_dir / file_path.name.replace(".diffoscope.json", ".analysis.txt")
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"Report at {output_path}\n")
            print("----------------------------\n")
        except FileNotFoundError:
            print(f"Error: File not found: {file_path}")
            sys.exit(1)

    return (change_types_dict, file_count)

# def analyze_file_diff(diff: str) -> str:
#     model = lms.llm("gemma-3-27b-it")
#     result = model.respond("Tell me what you think is the type of this file. Ignore that it looks like a diff or patch and look at the rest. VERY SHORT ANSWER WITH FILE TYPE AND HOW CERTAIN YOU ARE ON THIS FORMAT: <file-type>. Answer nothing more. Here's the file snippet:\n" + diff[:1000])

#     return f"There are diffs in a file of type: {result}"

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)

    time_before = time.time()

    # Create output directory if it doesn't exist
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    change_types_dict, file_count = process_diffoscope_files(Path(sys.argv[1]), output_dir)

    combined_change_types = {key: value for key, value in change_types_dict.items() if isinstance(key, frozenset)}
    simple_change_types = {key: value for key, value in change_types_dict.items() if isinstance(key, str)}

    print("Combined types of changes:")
    for change_types, files in sorted(combined_change_types.items(), key=lambda item: len(item[1]), reverse=True):
        percentage = (len(files) / MAX_DIFFOSCOPE_FILES) * 100
        sorted_change_types = sorted(change_types)
        change_types_str = ', '.join(sorted_change_types)
        print(f"\n{change_types_str}: {len(files):,} occurrences ({percentage:.2f}%)")

    print("\nSimple types of changes:")
    for change_type, files in sorted(simple_change_types.items(), key=lambda item: len(item[1]), reverse=True):
        percentage = (len(files) / MAX_DIFFOSCOPE_FILES) * 100
        print(f"\n{change_type}: {len(files):,} occurrences ({percentage:.2f}%)")


    elapsed_time = time.time() - time_before
    print(f"\nWent through {file_count} files. Elapsed time: {elapsed_time:.2f} seconds, average time per file: {elapsed_time / MAX_DIFFOSCOPE_FILES:.2f} seconds")
