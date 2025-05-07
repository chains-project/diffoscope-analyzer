import re
from collections import Counter

ZIPDETAILS_DIFF_PATTERN = re.compile(r'^(?P<sign>[+-])(?:(?P<address>[A-F0-9]+)\s+(?P<data_type>[A-z]+(?:\s[A-z1-9#]+)*)+|\W+(?P<bit>\[Bits? [\d-]+\]))\s*(?P<value>.+)?$')

def analyze_zipdetails(diff):
    total_diffs = 0
    diff_types = Counter()
    report = f"Source 1: {diff['source1']}\n"
    report += f"Source 2: {diff['source2']}\n"
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

    report += f"\nTotal number of diffs: {total_diffs:,}"
    report += "\nTypes of diffs:"
    for diff_type, count in diff_types.most_common():
        percentage = (count / total_diffs) * 100
        report += f"\n{diff_type}: {count:,} occurrences ({percentage:.2f}%)"

    return report


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
