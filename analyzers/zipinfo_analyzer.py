import re

ZIPINFO_HEADER_PATTERN = re.compile(r'^([+-])Zip file size: (\d+ bytes), number of entries: (\d+)$')
ZIPINFO_FILE_PATTERN = re.compile(r"""
    ^(?P<sign>[+-])                      # Diff sign (+ for added, - for removed)
    (?P<perm>[\-dcbslprwxRWXsStT]+)\s+   # File permissions
    (?P<version>\d+\.\d+)\s+             # ZIP version (e.g., 2.0)
    (?P<os>[a-z]{3})\s+                  # Operating system (e.g., fat, unix)
    (?P<size>\d+)\s+                     # Compressed size in bytes
    (?P<flags>\S{2})\s+                  # Compression flags
    (?P<method>\S{4})\s+                 # Compression method (e.g., defN)
    (?P<date>\d{2}-[A-Za-z]{3}-\d{2})\s+ # Date of the file (e.g., 23-Nov-20)
    (?P<time>\d{2}:\d{2})\s+             # Time of the file (e.g., 16:22)
    (?P<path>.+)                         # File path inside the ZIP
""", re.VERBOSE)

def analyze_zipinfo(diff, result):
    result += f"Source 1: {diff['source1']}\n"
    result += f"Source 2: {diff['source2']}\n"

    diff_lines = diff["unified_diff"].splitlines()

    # Let's define different types of reasons for diffs
    timestamp_change = False
    permission_change = False
    number_of_files_change = False
    file_content_or_size_change = False
    file_reordered_change = False
    file_removed_change = False
    file_added_change = False


    diff_line_results = {}
    for line in diff_lines:
        header_match = ZIPINFO_HEADER_PATTERN.search(line)
        if header_match:
            sign = header_match.group(1)
            if "zipinfo_header" not in diff_line_results:
                diff_line_results["zipinfo_header"] = {}
            if sign == '-':
                size_before = header_match.group(2)
                num_entries_before = header_match.group(3)
                diff_line_results["zipinfo_header"].update({
                            "size_before": size_before,
                            "num_entries_before": num_entries_before,
                        })
            elif sign == '+':
                size_after = header_match.group(2)
                num_entries_after = header_match.group(3)
                diff_line_results["zipinfo_header"].update({
                            "size_after": size_after,
                            "num_entries_after": num_entries_after,
                        })

        file_diff_match = ZIPINFO_FILE_PATTERN.search(line)
        if file_diff_match:
            sign = file_diff_match.group("sign")
            permissions = file_diff_match.group("perm")
            size = file_diff_match.group("size")
            date = file_diff_match.group("date")
            path = file_diff_match.group("path")

            if path not in diff_line_results:
                diff_line_results[path] = {}

            if sign == "-":
                diff_line_results[path].update({
                            "permissions_before": permissions,
                            "size_before": size,
                            "date_before": date,
                        })
            if sign == "+":
                diff_line_results[path].update({
                            "permissions_after": permissions,
                            "size_after": size,
                            "date_after": date,
                        })


    if "zipinfo_header" not in diff_line_results:
                result += "No zipinfo header change.\n"

    date_change_count = 0
    for key, changes in diff_line_results.items():
        if key == "zipinfo_header":
            if changes["size_before"] != changes["size_after"]:
                file_content_or_size_change = True
                result += f"Zip file size changed from {size_before} bytes to {size_after} bytes.\n"
            if changes["num_entries_before"] != changes["num_entries_after"]:
                number_of_files_change = True
                result += f"Number of entries changed from {num_entries_before} to {num_entries_after}.\n"
            if changes["size_before"] == changes["size_after"] and changes["num_entries_before"] == changes["num_entries_after"]:
                result += "No zipinfo header change even though there is a diff in header.\n"
        else:
            path = key
            if "date_before" in changes and "date_after" in changes:
                date_changed = changes["date_before"] != changes["date_after"]
                permissions_changed = changes["permissions_before"] != changes["permissions_after"]
                size_changed = changes["size_before"] != changes["size_after"]

                if date_changed and not permissions_changed and not size_changed:
                    timestamp_change = True
                    date_change_count += 1
                    continue

                result += f"\nChanges for file: {path}\n"
                print(f"Changes for file: {path}")
                if date_changed:
                    timestamp_change = True
                    result += f"Date changed from {changes['date_before']} to {changes['date_after']}\n"
                if permissions_changed:
                    permission_change = True
                    result += f"Permissions changed from {changes['permissions_before']} to {changes['permissions_after']}\n"
                if size_changed:
                    file_content_or_size_change = True
                    result += f"Size changed from {changes['size_before']} to {changes['size_after']}\n"
                if not date_changed and not permissions_changed and not size_changed:
                    file_reordered_change = True
                    result += "File is probably reordered\n"
            elif "date_before" in changes and "date_after" not in changes:
                file_removed_change = True
                result += f"\nFile removed. {path}\n"
            elif "date_before" not in changes and "date_after" in changes:
                file_added_change = True
                result += f"\nFile added. {path}\n"
            else:
                raise ValueError(f"Unexpected changes for file: {path}")

    if timestamp_change:
        print("Timestamp(s) changed")
    if permission_change:
        print("File permissions changed")
    if number_of_files_change:
        print("Number of files changed")
    if file_content_or_size_change:
        print("File content or file size changed")
    if file_reordered_change:
        print("File(s)  reordered")
    if file_removed_change:
        print("File(s) removed")
    if file_added_change:
        print("File(s) added")


    if date_change_count > 0:
        result += f"\n{date_change_count} files changed only their date.\n"

    return result
