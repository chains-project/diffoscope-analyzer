import re
import constants

# We want to detect different types of timestamps on different formats
TIMESTAMP_DIFF_PATTERN = re.compile(r"""
    ^\s*[-+]                            # line starts with optional space and - or +
    .*?                                # non-greedy match of anything up to the timestamp
    (?P<timestamp>                     # named capture group 'timestamp'
        \d{4}-\d{2}-\d{2}              # ISO date e.g., 2024-04-23
        [ T]                           # T or space separator
        \d{2}:\d{2}(:\d{2})?           # HH:MM[:SS] (optional seconds)
        (\.\d+)?                       # optional milliseconds
        (Z|[+-]\d{2}:\d{2})?           # optional timezone
    )
""", re.VERBOSE)

def analyze_file_diff(diff: dict, report: str) -> tuple[set[str],str]:
    report += f"Source 1: {diff['source1']}\n"
    report += f"Source 2: {diff['source2']}\n"

    diff_lines = diff["unified_diff"].splitlines()

    timestamp_change = False
    for line in diff_lines:
        has_timestamp_diff = TIMESTAMP_DIFF_PATTERN.search(line)
        if has_timestamp_diff:
            timestamp_change = True
            report += f"Timestamp diff detected: {line}\n"

    change_types = set()
    if timestamp_change:
        change_types.add(constants.TIMESTAMP_CHANGE)
    return (change_types, report)
