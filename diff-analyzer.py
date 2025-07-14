#!/usr/bin/env python3
"""
Analyzes diff files to count and categorize different types of changes.
Usage: python diff_analyzer.py <path_to_diff_file>
"""

import sys
import json
import time
from pathlib import Path
import oss_rebuild_files

# Assuming constants.py is in the same directory or available in PYTHONPATH
try:
    import change_types
except ImportError:
    print("Error: change_types.py not found. Please ensure it is in the same directory or in your PYTHONPATH.")
    sys.exit(1)

# Import analyzers (assuming they are in a subdirectory named 'analyzers')
try:
    from analyzers.zipdetails_analyzer import analyze_zipdetails
    from analyzers.zipinfo_analyzer import analyze_zipinfo
    from analyzers.file_list_analyzer import analyze_file_list
    from analyzers.file_diff_analyzer import analyze_file_diff
    from analyzers.zipnote_analyzer import analyze_zipnote
except ImportError:
    print("Error: Analyzers modules not found. Please ensure they are in the 'analyzers' subdirectory.")
    sys.exit(1)

MAX_DIFFOSCOPE_FILES = 10000

def gather_x_diffoscope_files(root_dir: Path, max_files) -> list[Path]:
    """
    Gather x diffoscope files from the given directory and its subdirectories.
    """
    if not root_dir.is_dir():
        raise ValueError(f"Provided path {root_dir} is not a directory.")

    print("Searching for diffoscope files...")

    exclude_dirs = [
        "oss-rebuild",
        "oss-rebuild-improved",
         # "oss-rebuild-improved-2",
        "rebuild",
        "reference"
    ]

    get_non_oss_rebuilt_files = False

    if get_non_oss_rebuilt_files:
        exclude_dirs.append("oss-rebuild-improved-2")
        all_files = list(root_dir.rglob('*.diffoscope.json'))
    else:
        all_files = list(root_dir.rglob('**/oss-rebuild-improved-2/*.diffoscope.json'))


    # Filter out files in excluded directories
    filtered_files = [
        f for f in all_files
        if not any(excluded in f.parts for excluded in exclude_dirs)
        and f.name in oss_rebuild_files.failed_normalization_files # Use only files that failed oss rebuild normalization
    ]

    print(f"Found {len(filtered_files)} diffoscope files.")

    return filtered_files[:max_files]


def analyze_diff_node(diff: dict) -> tuple[set[change_types.ChangeType],str]:
    change_categories, report = analyze_diff_node_recursive(diff)

    for change_type in change_categories:
        print(f"Change type: {change_type}")
    if not change_categories:
        report += "Unknown changes.\n"
        change_categories.add(change_types.UNKNOWN_CHANGE)
    elif change_types.FILE_CONTENT_CHANGE in change_categories:
        if not any(change_type in change_categories for change_type in change_types.FILE_DIFF_CHANGES):
            change_categories.add(change_types.UNKNOWN_FILE_CONTENT_CHANGE)
        change_categories.remove(change_types.FILE_CONTENT_CHANGE)


    return (change_categories, report)


def analyze_diff_node_recursive(diff: dict) -> tuple[set[change_types.ChangeType], str]:
    """
    Recursively analyzes a diff node to determine types of changes and generate a report.

    Args:
        diff (Dict): A dictionary representing the diff data.

    Returns:
        Tuple[Set[str], str]: A set of unique change types and a concatenated report string.
    """
    report = "\n-----------------------\n"
    change_categories = set()

    if "comments" in diff and diff["comments"]:
        report += f"Comments: {diff['comments']}\n"

    # Analyze unified diff if present
    if "unified_diff" in diff and diff["unified_diff"]:
        child_change_types, child_report = _analyze_source_type(diff)
        change_categories.update(child_change_types)
        report += child_report

    # Recursively process child diff details
    if "details" in diff:
        for detail in diff["details"]:
            child_change_types, child_report = analyze_diff_node_recursive(detail)
            change_categories.update(child_change_types)
            report += child_report

    return change_categories, report


def _analyze_source_type(diff: dict) -> tuple[set[change_types.ChangeType], str]:
    """Helper to handle different source types."""
    source_type = diff["source1"]

    match True:
        case _ if "zipinfo" in source_type:
            return analyze_zipinfo(diff)

        case _ if "file list" in source_type:
            return analyze_file_list(diff)

        case _ if "zipdetails" in source_type:
            additional_report = analyze_zipdetails(diff)
            return set(), additional_report

        case _ if "zipnote" in source_type:
            return analyze_zipnote(diff)

        case _:
            return analyze_file_diff(diff)

def process_diffoscope_files(input_path: Path, output_dir: Path) -> dict:
    change_types_dict = {}
    file_count = 0

    for file_path in gather_x_diffoscope_files(input_path, MAX_DIFFOSCOPE_FILES):
        file_count += 1
        print(f"File: {file_path}")
        try:
            # For the first two filename based detectors, don't bother running analyzers
            if "buildinfo" in file_path.name:
                change_categories = {change_types.BUILDINFO_CHANGE}
                report = "Buildinfo file changes detected.\n"
                print(f"Change type: {change_types.BUILDINFO_CHANGE}")
            elif "cyclonedx.xml" in file_path.name or "cyclonedx.json" in file_path.name:
                change_categories = {change_types.SBOM_CHANGE}
                report = "CycloneDX BOM file changes detected.\n"
                print(f"Change type: {change_types.SBOM_CHANGE}")
            elif "spdx.json" in file_path.name:
                change_categories = {change_types.SBOM_CHANGE}
                report = "SPDX BOM file changes detected.\n"
                print(f"Change type: {change_types.SBOM_CHANGE}")
            elif "bom.json" in file_path.name:
                change_categories = {change_types.SBOM_CHANGE}
                report = "BOM file changes detected.\n"
                print(f"Change type: {change_types.SBOM_CHANGE}")
            else:
                with open(file_path, 'r', encoding='utf-8') as f:
                    diff_data: dict = json.loads(f.read())
                (change_categories, report) = analyze_diff_node(diff_data)
            if change_categories:
                for change_type in change_categories:
                    change_types_dict.setdefault(change_type, [])
                    change_types_dict[change_type].append(file_path)
                change_types_dict.setdefault(frozenset(change_categories), [])
                change_types_dict[frozenset(change_categories)].append(file_path)

            # Create output path in the output directory
            output_path = output_dir / file_path.name.replace(".diffoscope.json", ".analysis.md")
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

    # files = gather_x_diffoscope_files(Path(sys.argv[1]), MAX_DIFFOSCOPE_FILES)

    # # Load normalization results
    # with open("tmp/oss_rebuild_improved_2_result.txt", "r") as f:
    #     normalization_data = json.load(f)

    #     # Collect all diffoscope files from the JSON
    #     json_diffoscope_files = set()
    #     for entries in normalization_data.get("failed_normalization", {}).values():
    #         for entry in entries:
    #             json_diffoscope_files.add(Path(entry["diffoscope_diff"]).name)

    #     # Gathered files (convert Path to str for comparison)
    #     gathered_files = set(str(f.name) for f in files)

    #     # Find files in JSON but not gathered
    #     missing_in_gathered = json_diffoscope_files - gathered_files
    #     # Find files gathered but not in JSON
    #     extra_in_gathered = gathered_files - json_diffoscope_files

    #     print(f"Files found but not in oss rebuild JSON: {len(extra_in_gathered)}")
    #     for f in files:
    #         if str(f.name) in extra_in_gathered:
    #             print(f"  {f}")

    #     print(f"Files in oss rebuild JSON but not found: {len(missing_in_gathered)}")
    #     for f in sorted(missing_in_gathered):
    #         print(f"  {f}")

    # sys.exit(0)

    change_types_dict, file_count = process_diffoscope_files(Path(sys.argv[1]), output_dir)

    combined_change_types = {key: value for key, value in change_types_dict.items() if isinstance(key, frozenset)}
    simple_change_types = {key: value for key, value in change_types_dict.items() if isinstance(key, str)}

    print("Combined types of changes:")
    for change_categories, files in sorted(combined_change_types.items(), key=lambda item: len(item[1]), reverse=True):
        percentage = (len(files) / file_count) * 100
        sorted_change_types = sorted(change_categories)
        change_types_str = ', '.join(sorted_change_types)
        print(f"\n{change_types_str}: {len(files):,} occurrences ({percentage:.2f}%)")
        for file in sorted(files):
            print(f"  {file}")

    print("\nSimple types of changes:")
    for change_type, files in sorted(simple_change_types.items(), key=lambda item: len(item[1]), reverse=True):
        percentage = (len(files) / file_count) * 100
        print(f"\n{change_type}: {len(files):,} occurrences ({percentage:.2f}%)")


    elapsed_time = time.time() - time_before
    print(f"\nWent through {file_count} files. Elapsed time: {elapsed_time:.2f} seconds, average time per file: {elapsed_time / file_count * 1000:.1f} milliseconds")

    print("--------------------------")
    files_with_unknown_diffs = simple_change_types.get(change_types.UNKNOWN_CHANGE, [])
    print(f"  {len(files_with_unknown_diffs):,} files with unknown changes")
    for file in files_with_unknown_diffs:
        print(f"  {file}")


    # Write to json files
    # Write simple change types
    simple_changes = {
        change_type: [str(file) for file in files]
        for change_type, files in simple_change_types.items()
    }
    with open(output_dir / "simple_change_types.json", "w") as f:
        json.dump(simple_changes, f, indent=2)

    # Write combined change types
    combined_changes = {
        ",".join(sorted(change_types)): [str(file) for file in files]
        for change_types, files in combined_change_types.items()
    }
    with open(output_dir / "combined_change_types.json", "w") as f:
        json.dump(combined_changes, f, indent=2)

    print("\nChange types have been written to:")
    print(f"  {output_dir}/simple_change_types.json")
    print(f"  {output_dir}/combined_change_types.json")
