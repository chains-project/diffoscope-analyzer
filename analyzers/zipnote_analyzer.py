import constants

def parse_diff_format(diff_text):
    added_files = []
    removed_files = []

    for line in diff_text.splitlines():
        line = line.strip()
        if line.startswith('+Filename:'):
            filename = line[len('+Filename:'):].strip()
            added_files.append(filename)
        elif line.startswith('-Filename:'):
            filename = line[len('-Filename:'):].strip()
            removed_files.append(filename)

    return added_files, removed_files


def analyze_zipnote(diff: dict) -> tuple[set[str], str]:
    report = f"Source 1: {diff['source1']}\n"
    report += f"Source 2: {diff['source2']}\n"

    diff_lines = diff["unified_diff"]

    # Let's define different types of reasons for diffs
    # number_of_files_change = False
    # file_removed_change = False
    # file_added_change = False

    added_files, removed_files = parse_diff_format(diff_lines)

    report += f"Added files: {', '.join(added_files)}\n"
    report += f"Removed files: {', '.join(removed_files)}\n"

    change_types = set()
    if removed_files:
        change_types.add(constants.FILE_REMOVED_CHANGE)
    if added_files:
        change_types.add(constants.FILE_ADDED_CHANGE)

    return (change_types, report)
