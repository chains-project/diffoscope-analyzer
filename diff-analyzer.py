#!/usr/bin/env python3
"""
Analyzes diff files to count and categorize different types of changes.
Usage: python diff_analyzer.py <path_to_diff_file>
"""

import re
import sys
from collections import Counter
from pathlib import Path

def analyze_diff_file(file_path: Path) -> None:
    # Initialize counters
    diff_types = Counter()
    total_diffs = 0

    # Improved regex pattern to match the label of the change
    diff_pattern = re.compile(r'^..[+-][A-F0-9]+\s([A-z]+\s[A-z]+)+')

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = iter(f)
            for line in lines:
                # Extract the type of diff (the label of what changed)
                match = diff_pattern.search(line)
                if match:
                    total_diffs += 1
                    diff_type = match.group(1).strip()
                    diff_types[diff_type] += 1
                    next(lines, None)

        # Print results
        print(f"\nTotal number of diffs: {total_diffs:,}")
        print("\nTypes of diffs:")
        for diff_type, count in diff_types.most_common():
            percentage = (count / total_diffs) * 100
            print(f"{diff_type}: {count:,} occurrences ({percentage:.2f}%)")

    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        print(f"Error processing file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)

    analyze_diff_file(Path(sys.argv[1]))
