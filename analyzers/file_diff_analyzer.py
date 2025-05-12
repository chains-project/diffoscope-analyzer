import re
import constants


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
    \s*                                 # Optional whitespace
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
    \$[a-zA-Z_]+\$\d+                   # Match a generated internal ID
""", re.VERBOSE)

MODULE_INFO_JAVA_VERSION_PATTERN = re.compile(r"""
    ^\s*[-+]                            # Line starts with optional whitespace, then - or +
    \s+
    \#\d+\s+=\s+Utf8\s+                 # Match a module-info line with UTF-8
    \d+(?:\.\d+){0,2}                  # Match a Java version string (e.g., "1.8.0")
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


def analyze_file_diff(diff: dict) -> tuple[set[str],str]:
    report = f"Source 1: {diff['source1']}\n"
    report += f"Source 2: {diff['source2']}\n"

    if "jandex" in diff["source1"] or "jandex" in diff["source2"]:
        report += "Jandex diff detected, skipping analysis\n"
        return {constants.JANDEX_CHANGE}, report

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
        GENERATED_INTERNAL_ID_PATTERN: (constants.GENERATED_ID_CHANGE, "Generated internal ID detected"),
    }
    if "module-info" in unified_diff:
        diff_line_analysis.update({
            MODULE_INFO_JAVA_VERSION_PATTERN: (constants.JAVA_VERSION_CHANGE, "Java version change detected"),
        })

    for line in unified_diff.splitlines():
        if not (line.strip() and line.strip()[0] in '+-'):
            # Skip lines that are not relevant
            continue
        for pattern, (change_type, message) in diff_line_analysis.items():

            if pattern.search(line):
                change_types.add(change_type)
                report += f"{message}: {line}\n"
                break  # Move to the next line once a match is found

    return (change_types, report)
