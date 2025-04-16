import re
import constants

FILE_LIST_PATTERN = re.compile(r"""
    ^(?P<sign>[+-])                       # Diff sign
    (?P<perm>[drwx\-]{10})\s+            # Permissions
    \d+\s+                                # Hard link count (ignored)
    (?P<owner>\S+)\s+\(\d+\)\s+          # Owner (with UID)
    (?P<group>\S+)\s+\(\d+\)\s+          # Group (with GID)
    (?P<size>\d+)\s+                     # Size in bytes
    (?P<timestamp>\d{4}-\d{2}-\d{2}      # Date YYYY-MM-DD
        \s+\d{2}:\d{2}:\d{2}\.\d+)       # Time HH:MM:SS.micro
    \s+(?P<path>.+)                      # File path
""", re.VERBOSE)

def analyze_file_list(diff: dict, report: str) -> tuple[set[str],str]:
    report += f"Source 1: {diff['source1']}\n"
    report += f"Source 2: {diff['source2']}\n"

    diff_lines = diff["unified_diff"].splitlines()

    # Let's define different types of reasons for diffs
    timestamp_change = False
    permission_change = False
    owner_change = False
    group_change = False
    number_of_files_change = False
    file_content_or_size_change = False
    file_reordered_change = False
    file_removed_change = False
    file_added_change = False

    diff_line_results = {}
    for line in diff_lines:
        file_diff_match = FILE_LIST_PATTERN.search(line)
        if file_diff_match:
            sign = file_diff_match.group("sign")
            permissions = file_diff_match.group("perm")
            owner = file_diff_match.group("owner")
            group = file_diff_match.group("group")
            size = file_diff_match.group("size")
            timestamp = file_diff_match.group("timestamp")
            path = file_diff_match.group("path")

            if path not in diff_line_results:
                diff_line_results[path] = {}

            if sign == "-":
                diff_line_results[path].update({
                            "permissions_before": permissions,
                            "owner_before": owner,
                            "group_before": group,
                            "size_before": size,
                            "timestamp_before": timestamp,
                        })
            if sign == "+":
                diff_line_results[path].update({
                            "permissions_after": permissions,
                            "owner_after": owner,
                            "group_after": group,
                            "size_after": size,
                            "timestamp_after": timestamp,
                        })

    date_change_count = 0
    for path, changes in diff_line_results.items():
        if "timestamp_before" in changes and "timestamp_after" in changes:
            date_changed = changes["timestamp_before"] != changes["timestamp_after"]
            permissions_changed = changes["permissions_before"] != changes["permissions_after"]
            owner_changed = changes["owner_before"] != changes["owner_after"]
            group_changed = changes["group_before"] != changes["group_after"]
            size_changed = changes["size_before"] != changes["size_after"]

            if date_changed and not permissions_changed and not size_changed:
                timestamp_change = True
                date_change_count += 1
                continue

            report += f"\nChanges for file: {path}\n"
            if date_changed:
                timestamp_change = True
                report += f"Date changed from {changes['timestamp_before']} to {changes['timestamp_after']}\n"
            if permissions_changed:
                permission_change = True
                report += f"Permissions changed from {changes['permissions_before']} to {changes['permissions_after']}\n"
            if owner_changed:
                owner_change = True
                report += f"Owner changed from {changes['owner_before']} to {changes['owner_after']}\n"
            if group_changed:
                group_change = True
                report += f"Group changed from {changes['group_before']} to {changes['group_after']}\n"
            if size_changed:
                file_content_or_size_change = True
                report += f"Size changed from {changes['size_before']} to {changes['size_after']}\n"
            if not date_changed and not permissions_changed and not size_changed:
                file_reordered_change = True
                report += "File is probably reordered\n"
        elif "timestamp_before" in changes and "timestamp_after" not in changes:
            file_removed_change = True
            report += f"\nFile removed. {path}\n"
        elif "timestamp_before" not in changes and "timestamp_after" in changes:
            file_added_change = True
            report += f"\nFile added. {path}\n"
        else:
            raise ValueError(f"Unexpected changes for file: {path} object: {changes}")

    change_types = set()
    if timestamp_change:
        change_types.add(constants.TIMESTAMP_CHANGE)
    if permission_change:
        change_types.add(constants.PERMISSION_CHANGE)
    if owner_change:
        change_types.add(constants.OWNER_CHANGE)
    if group_change:
        change_types.add(constants.GROUP_CHANGE)
    if number_of_files_change:
        change_types.add(constants.NUMBER_OF_FILES_CHANGE)
    if file_content_or_size_change:
        change_types.add(constants.FILE_CONTENT_OR_SIZE_CHANGE)
    if file_reordered_change:
        change_types.add(constants.FILE_REORDERED_CHANGE)
    if file_removed_change:
        change_types.add(constants.FILE_REMOVED_CHANGE)
    if file_added_change:
        change_types.add(constants.FILE_ADDED_CHANGE)


    if date_change_count > 0:
        report += f"\n{date_change_count} files changed only their date.\n"

    return (change_types, report)
