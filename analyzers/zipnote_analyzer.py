import change_types
from helpers import report_section_init, report_section_end

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

    added_files_without_removed = [added_file for added_file in added_files if added_file not in removed_files]
    removed_files_without_added = [removed_file for removed_file in removed_files if removed_file not in added_files]

    return added_files_without_removed, removed_files_without_added


def analyze_zipnote(diff: dict) -> tuple[set[change_types.ChangeType], str]:
    report = report_section_init(diff['source1'], diff['source2'])

    diff_lines = diff["unified_diff"]

    # Let's define different types of reasons for diffs
    # number_of_files_change = False
    # file_removed_change = False
    # file_added_change = False

    added_files, removed_files = parse_diff_format(diff_lines)

    if added_files:
        report += f"Added files: {', '.join(added_files)}\n"
    if removed_files:
        report += f"Removed files: {', '.join(removed_files)}\n"

    change_categories = set()
    if removed_files:
        change_categories.add(change_types.FILE_REMOVED_CHANGE)
    if added_files:
        change_categories.add(change_types.FILE_ADDED_CHANGE)

    report += report_section_end()
    return (change_categories, report)
