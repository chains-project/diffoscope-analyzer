#!/usr/bin/env python3
"""
Analyzes diff files to count and categorize different types of changes.
Usage: python diff_analyzer.py <path_to_diff_file>
"""

import re
import sys
import json
from collections import Counter
from pathlib import Path

DIFF_PATTERN = re.compile(r'^(?P<sign>[+-])(?:(?P<address>[A-F0-9]+)\s+(?P<data_type>[A-z]+(?:\s[A-z1-9#]+)*)+|\W+(?P<bit>\[Bit [\d-]+\]))\s+(?P<value>.+)$')

def analyze_diff_portion(diff: str, diff_types: Counter) -> int:
    total_diffs = 0

    changes: dict[str, dict[str, str]] = {}
    for line in diff.splitlines():
        # Extract the type of diff (the label of what changed)
        match = DIFF_PATTERN.search(line)
        if not match:
            raise ValueError(f"Invalid diff line: {line}")
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


def analyze_diff_file(file_path: Path) -> None:
    # Initialize counters
    diff_types = Counter()
    total_diffs = 0

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            diff_data: dict = json.loads(f.read())

            for diff in diff_data["details"]:
                print(f"\nSource 1: {diff["source1"]}")
                print(f"Source 2: {diff["source2"]}")
                diff_lines = diff["unified_diff"].splitlines()

                diff_portion = []
                for line in diff_lines:
                    match = DIFF_PATTERN.search(line)
                    if match:
                        diff_portion.append(line)
                    elif diff_portion:  # If we have collected a portion and hit a non-matching line
                        total_diffs += analyze_diff_portion('\n'.join(diff_portion), diff_types)
                        diff_portion = []
                    print(line)

                # Process any remaining portion
                if diff_portion:
                    total_diffs += analyze_diff_portion('\n'.join(diff_portion), diff_types)

                # Print results
                print(f"\nTotal number of diffs: {total_diffs:,}")
                print("\nTypes of diffs:")
                for diff_type, count in diff_types.most_common():
                    percentage = (count / total_diffs) * 100
                    print(f"{diff_type}: {count:,} occurrences ({percentage:.2f}%)")

    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)

    analyze_diff_file(Path(sys.argv[1]))
