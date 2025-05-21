import re
import constants
from collections import Counter


# We want to detect different types of timestamps on different formats
TIMESTAMP_DIFF_PATTERN = re.compile(r"""
    ^\s*[-+].*?(
        (?P<java_ts>                   # Java-style date
            [A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+[A-Z]{3,4}\s+\d{4}
        )
        |
        (?P<iso_ts>                    # ISO 8601 style date
            \d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?:\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?
        )
        |
        (?P<utc_ts>                    # UTC timestamp with optional timezone
            \d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+(?:UTC|[+-]\d{4})
        )
        |
        (?P<compact_ts>            # Compact timestamp (from PDF)
            \d{14}[+-]\d{2}
        )
        |
        (?P<jaxb_ts>                # Exlipse JAXB-style date
            \d{4}\.\d{2}\.\d{2}\s+at\s+\d{2}:\d{2}:\d{2}\s+(?:AM|PM)\s+[A-Z]{2,4}
        )
        |
        (?P<manifest_build_ts>
            [+-]Bnd-LastModified:\s+\d{13}
        )
        |
        (?P<dot_date_am_pm_ts>
            \d{4}\.\d{2}\.\d{2}              # Date as YYYY.MM.DD
            \s+at\s+                         # ' at ' with spaces
            \d{2}:\d{2}:\d{2}                # Time: HH:MM:SS
            \s+(?:AM|PM)                     # AM or PM
            \s+[A-Z]{2,4}                    # Timezone (e.g., UTC)
        )
        |
        (?P<flex_iso_with_backslash_ts>
            \d{4}-\d{2}-\d{2}T                    # Date part
            \d{2}(\\{1,2}:)\d{2}(\\{1,2}:)\d{2}   # Time part, with 1 or 2 backslashes before colons
            [+-]\d{4}                             # Timezone offset
        )
        |
        (?P<month_day_year_ts>              # Format: "Jan 29, 2025 (03:39:58 UTC)" or "Jun 07, 2022 (03:47:13 EDT)"
            [A-Za-z]{3}\s+\d{1,2},\s+\d{4}        # Date part: "Jan 29, 2025"
            \s+\(\d{2}:\d{2}:\d{2}\s+[A-Z]{2,4}\) # Time part with any timezone: "(03:39:58 UTC)" or "(03:47:13 EDT)"
        )
        |
        (?P<iso_with_am_pm_ts>              # Format: "2025-01-31 23\\:24\\:19PM"
            \d{4}-\d{2}-\d{2}                    # Date part: "2025-01-31"
            \s+\d{2}(?:\\+:)\d{2}(?:\\+:)\d{2}   # Time part with escaped colons: "23\\:24\\:19"
            (?:AM|PM)                            # AM/PM indicator
        )
    )
""", re.VERBOSE)

HASH_IN_XML_DIFF_PATTERN = re.compile(r"""
    ^\s*[-+]                            # Line starts with optional whitespace, then - or +
    [^<]*                               # Match any characters until <
    <hash\s+                            # Opening <hash> tag with space after
    alg=                                # Match 'alg='
    [\"'\\]*                            # Optional escaped or unescaped quotes
    (?P<algo_xml>[\w\-]+)               # Capture algorithm name (e.g., MD5, SHA3-256)
    [\"'\\]*                            # Optional closing quotes
    >                                   # End of opening tag
""", re.VERBOSE)

HASH_IN_JSON_DIFF_PATTERN = re.compile(r"""
    ^\s*[-+]                            # Line starts with optional whitespace, then - or +
    .*?                                 # Non-greedy match up to the key
    (?:
        \\?"(?:alg|md5|sha1|sha256|sha512)"\\?    # Match "alg" key or hash name (escaped or not)
        \s*:\s*
        \\?"(?P<algo_json>[\w\-]+)\\?"            # Capture algorithm name
      |
        \\?"content"\\?                            # Match "content" key (escaped or not)
        \s*:\s*
        \\?"(?P<content_hash>[a-fA-F0-9]{32,})\\?"  # Capture content hash
    )
""", re.VERBOSE)

#+- followed by the hash with no space for the most common algorithms
HASH_FILE_CHANGE_PATTERN = re.compile(r"""
    ^\s*[-+]                            # Line starts with optional whitespace, then - or +
    [a-fA-F0-9]{32,}                    # Match a hash (e.g., MD5, SHA1, SHA256)
""", re.VERBOSE)

PARTIAL_POM_CHUNK_PATTERN = re.compile(r"""
    <                                   # Opening angle bracket
    /?                                  # Optional closing slash
    (?:                                 # Non-capturing group for common POM tags
        project |
        modelVersion |
        groupId |
        artifactId |
        version |
        packaging |
        # name |
        dependencies |
        dependency |
        build |
        plugin |
        plugins |
        executions |
        execution |
        configuration |
        id |
        phase |
        goals |
        goal
        # properties |
    )\b                                 # Word boundary (so we don't match e.g., "artifactIdentifier")
    [^>]*>                              # Anything until closing '>'
""", re.VERBOSE | re.IGNORECASE)

COPYRIGHT_CHANGE_PATTERN = re.compile(r"""
    ^\s*[-+]                            # Line starts with optional whitespace, then - or +
    \#?                                 # Optional #
    \s*                                 # Optional whitespace
    (?:<strong>|<p>)?                   # Optional HTML tags
    Copyright                           # Match 'Copyright'
""", re.VERBOSE | re.IGNORECASE)

# Regex for diff line with +- in an xml file
# With capture group for the property name
XML_DIFF_LINE_PATTERN = re.compile(r"""
    ^\s*(?P<sign>[+-])                  # Line starts with optional whitespace, then - or +
    [^<]*                               # Match any characters until <
    <(?P<tag_name>[\w\-]+)              # Capture the tag name (e.g., <property>)
""", re.VERBOSE)

GENERATED_INTERNAL_ID_PATTERN = re.compile(r"""
    ^\s*[-+]                            # Line starts with optional whitespace, then - or +
    .*?                                 # Non-greedy match
    \$[a-zA-Z_]+\$\d+                   # Match a generated internal ID "$something$xx"
""", re.VERBOSE)

MODULE_INFO_JAVA_VERSION_PATTERN = re.compile(r"""
    ^\s*[-+]                           # Line starts with optional whitespace, then - or +
    \s+
    \#\d+\s+=\s+Utf8\s+                # Match a module-info line with UTF-8
    \d+(?:\.\d+){0,2}                  # Match a Java version string (e.g., "1.8.0")
""", re.VERBOSE)

BUILD_METADATA_PATTERN = re.compile(r"""
    ^\s*[-+]                                      # Line starts with optional whitespace and a - or +
    (?P<key>Bnd-LastModified|Build-Jdk|Built-By)  # Match only these keys
""", re.VERBOSE)

PATH_DIFF_PATTERN = re.compile(r"""
    (?P<path>
        /(?:[\w\-]+/){2,}                     # Starts with / and at least two path segments
        (?P<tail>[\w\-.]+)                    # Final segment
    )
""", re.VERBOSE)

GIT_COMMIT_CHANGE_PATTERN = re.compile(r"""
    [-+]
    (?:git\.commit\.id\.full=[0-9a-fA-F]{40}
    |
    git\.commit\.id\.abbrev=[0-9a-fA-F]{7}
    |
    Git-Revision:\s+[0-9a-fA-F]{40}
    |
    Scm-Revision:\s+[0-9a-fA-F]{40}
    )
""", re.VERBOSE)

def analyze_pom_diff(diff: str):
    """
    Analyze what has been added and removed in the Pom file
    """
    ADDED = "ADDED"
    REMOVED = "REMOVED"
    tags_changed = {}
    report = ""
    for line in diff.splitlines():
        match = XML_DIFF_LINE_PATTERN.match(line)
        if match:
            tag_name = match.group("tag_name")
            # We have a property that has been changed
            # if it is not in the properties_changed dict, we add it
            tags_changed.setdefault(tag_name, set())
            if match.group("sign") == "+":
                tags_changed[tag_name].add(ADDED)
            elif match.group("sign") == "-":
                tags_changed[tag_name].add(REMOVED)

    for tag, changes in tags_changed.items():
        if ADDED in changes and REMOVED in changes:
            report += f"Tag <{tag}> has been changed\n"
        elif ADDED in changes:
            report += f"Tag <{tag}> has been added\n"
        elif REMOVED in changes:
            report += f"Tag <{tag}> has been removed\n"
    return report


def extract_words(text):
    return re.findall(r'\b[\w\d$._-]+\b', text)

def is_reordered_words(line1, line2):
    """Check if two lines have the same words, different order."""
    words1 = extract_words(line1)
    words2 = extract_words(line2)
    return Counter(words1) == Counter(words2) and words1 != words2

def detect_word_reordering(unified_diff):

    removed_lines = []
    added_lines = []
    results: list[tuple[str, str]] = []

    prev_type = None

    splitlines = unified_diff.splitlines()
    MAX_NUMBER_OF_LINES = 10000
    if len(splitlines) > MAX_NUMBER_OF_LINES: # This is too slow to be practical otherwise
        return []
    for line in splitlines:
        if line.startswith('-'):
            line_type = '-'
        elif line.startswith('+'):
            line_type = '+'
        else:
            # On neutral line, flush block
            results.extend(compare_block_for_reordered_words(removed_lines, added_lines))
            removed_lines.clear()
            added_lines.clear()
            prev_type = None
            continue

        # On direction switch, flush block
        if prev_type == '+' and line_type != prev_type:
            results.extend(compare_block_for_reordered_words(removed_lines, added_lines))
            removed_lines.clear()
            added_lines.clear()

        content = line[1:].strip()
        if line_type == '-':
            removed_lines.append(content)
        else:
            added_lines.append(content)

        prev_type = line_type

    # Final flush
    results.extend(compare_block_for_reordered_words(removed_lines, added_lines))
    return results


def compare_block_for_reordered_words(removed, added):
    """Return reordered line pairs based on word reordering."""
    reordered = []
    for rem_line in removed:
        for add_line in added:
            if is_reordered_words(rem_line, add_line):
                reordered.append((rem_line, add_line))
                break  # Avoid duplicate matches
    return reordered

def analyze_file_diff(diff: dict) -> tuple[set[str],str]:
    report = f"Source 1: {diff['source1']}\n"
    report += f"Source 2: {diff['source2']}\n"


    if "has_internal_linenos" in diff and diff["has_internal_linenos"]: # High risk of false positives if the file has internal line numbers
        report += "Probably a hexdump or other hard to parse file, skipping analysis\n"
        return {constants.HEXDUMP_CHANGE}, report
    if "jandex" in diff["source1"] or "jandex" in diff["source2"]:
        report += "Jandex diff detected, skipping analysis\n"
        return {constants.JANDEX_CHANGE}, report
    if "js-beautify" in diff["source1"] or "js-beautify" in diff["source2"]:
        report += "js-beautify changes detected, skipping analysis\n"
        return {constants.JS_BEAUTIFY_CHANGE}, report
    if ".class" in diff["source1"] or ".class" in diff["source2"]:
        report += "Class file diff detected, skipping analysis\n"
        return {constants.CLASS_FILE_CHANGE}, report

    if "comments" in diff and diff["comments"]:
        print (f"Comment: {diff['comments']}")
        if diff["comments"] == ["Ordering differences only"]:
            report += "Line ordering differences only, skipping analysis\n"
            return {constants.LINE_ORDERING_CHANGE}, report
        if diff["comments"] == ["Line-ending differences only"]:
            report += "Line-ending differences only, skipping analysis\n"
            return {constants.LINE_ENDING_CHANGE}, report

    change_types = set()
    unified_diff = diff["unified_diff"]
    match = PARTIAL_POM_CHUNK_PATTERN.search(unified_diff)

    if match:
        report += "Partial POM chunk detected, this is probably a pom file\n"

        change_types.add(constants.POM_CHANGE)
        report += analyze_pom_diff(unified_diff)

    diff_line_analysis = {
        TIMESTAMP_DIFF_PATTERN: (constants.TIMESTAMP_CHANGE, "Timestamp diff detected"),
        HASH_IN_XML_DIFF_PATTERN: (constants.HASH_IN_XML_CHANGE, "Hash in XML diff detected"),
        HASH_IN_JSON_DIFF_PATTERN: (constants.HASH_IN_JSON_CHANGE, "Hash in JSON diff detected"),
        HASH_FILE_CHANGE_PATTERN: (constants.HASH_FILE_CHANGE, "Hash file change detected"),
        COPYRIGHT_CHANGE_PATTERN: (constants.COPYRIGHT_CHANGE, "Copyright change detected"),
        GIT_COMMIT_CHANGE_PATTERN: (constants.GIT_COMMIT_CHANGE, "Git commit change detected"),
    }
    if "MANIFEST" in diff["source1"] or "MANIFEST" in diff["source2"]:
        diff_line_analysis.update({
            BUILD_METADATA_PATTERN: (constants.BUILD_METADATA_CHANGE, "Build metadata change detected"),
        })
    if "DEPENDENCIES" in diff["source1"] or "DEPENDENCIES" in diff["source2"]:
        change_types.add(constants.DEPENDENCY_METADATA_CHANGE)
        report += "Dependency metadata diff detected.\n"
    if "git.properties" in diff["source1"] or "git.properties" in diff["source2"]:
        change_types.add(constants.GIT_PROPERTIES_CHANGE)
        report += "Git properties diff detected.\n"
    if ".class" not in diff["source1"] and ".class" not in diff["source2"]: # This check is for java files. We get a lot of false positives on class files
        diff_line_analysis.update({
            GENERATED_INTERNAL_ID_PATTERN: (constants.GENERATED_ID_CHANGE, "Generated internal ID detected"),
        })


    if "module-info" in unified_diff:
        diff_line_analysis.update({
            MODULE_INFO_JAVA_VERSION_PATTERN: (constants.JAVA_VERSION_CHANGE, "Java version change detected"),
        })

    removed_paths: dict[str,re.Match] = {}
    added_paths: dict[str,re.Match] = {}

    word_reordering_result = detect_word_reordering(unified_diff)
    if word_reordering_result:
        for (rem_line, add_line) in word_reordering_result:
            report += f"Reordered words: {rem_line} -> {add_line}\n"
            change_types.add(constants.WORD_ORDERING_CHANGE)

    for line in unified_diff.splitlines():
        if not line.startswith(('-', '+')):
            continue

        matches = PATH_DIFF_PATTERN.finditer(line)

        for match in matches:
            if line.startswith('-'):
                removed_paths[match.group("tail")] = match
            elif line.startswith('+'):
                added_paths[match.group("tail")] = match

    if removed_paths or added_paths:
        for tail, removed_match in removed_paths.items():
            added_match = added_paths.get(tail)
            if added_match and removed_match.group("path") != added_match.group("path"):
                # If the path exists in both, but the match is different
                report += f"Path change detected: {removed_match['path']} -> {added_match['path']}\n"
                change_types.add(constants.PATH_CHANGE)

    for line in unified_diff.splitlines():
        if not (line.strip() and line.strip()[0] in '+-'):
            # Skip lines that are not relevant
            continue
        for pattern, (change_type, message) in diff_line_analysis.items():

            if pattern.search(line):
                change_types.add(change_type)
                report += f"{message}: {line}\n"
                # TODO: test time without break # break  # Move to the next line once a match is found

    if not change_types and ("MANIFEST" in diff["source1"] or "MANIFEST" in diff["source2"]):
        # If we have a manifest file and no other changes, we assume it's a manifest change
        change_types.add(constants.UNKNOWN_MANIFEST_CHANGE)
        report += "Unknown manifest file change detected\n"

    return (change_types, report)
