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

HASH_IN_XML_DIFF_PATTERN = re.compile(r"""
    ^\s*[-+]                            # Line starts with optional whitespace, then - or +
    .*?                                 # Non-greedy match up to the <hash> tag
        <hash\s+                        # Opening <hash> tag with space after
        alg=                            # Match 'alg='
        [\"'\\]*                        # Optional escaped or unescaped quotes
        (?P<algo_xml>[\w\-]+)           # Capture algorithm name (e.g., MD5, SHA3-256)
        [\"'\\]*                        # Optional closing quotes
        >                               # End of opening tag
""", re.VERBOSE)

HASH_IN_JSON_DIFF_PATTERN = re.compile(r"""
    ^\s*[-+]                            # Line starts with optional whitespace, then - or +
    .*?                                 # Non-greedy match up to the "alg" key
    \\?\"alg\"\\?                         # Match "alg" key with optional escaping
    \s*:\s*                             # Match colon with optional spaces
    \\?\"                                # Opening quote (escaped)
    (?P<algo_json>[\w\-]+)              # Capture algorithm name (e.g., SHA3-256)
    \\?\"                                # Closing quote (escaped)
""", re.VERBOSE)

PARTIAL_POM_CHUNK_PATTERN = re.compile(r"""
    <                # Opening angle bracket
    (?:              # Non-capturing group for common POM tags
        project |
        modelVersion |
        groupId |
        artifactId |
        version |
        packaging |
        name |
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
        goal |
        properties
    )
    \b               # Word boundary (so we don't match e.g., "artifactIdentifier")
    [^>]*>           # Anything until closing '>'
""", re.VERBOSE | re.IGNORECASE)

XML_VERSION_CHANGED_OR_REMOVED_PATTERN = re.compile(r"""
    ^\s*[-+]                            # Line starts with optional whitespace, then - or +
    .*?                                 # Non-greedy match up to the "alg" key
    <version>                           # Match <version> tag
""", re.VERBOSE)

XML_PROPERTY_CHANGED_OR_REMOVED_PATTERN = re.compile(r"""
    ^\s*[-+]                            # Line starts with optional whitespace, then - or +
    .*?                                 # Non-greedy match up to the "alg" key
    <property>                          # Match <property> tag
""", re.VERBOSE)

def analyze_file_diff(diff: dict, report: str) -> tuple[set[str],str]:
    report += f"Source 1: {diff['source1']}\n"
    report += f"Source 2: {diff['source2']}\n"

    if PARTIAL_POM_CHUNK_PATTERN.search(diff["unified_diff"]):
        report += "Partial POM chunk detected\n"
        change_types = {constants.POM_CHANGE}

        # Type of pom change

        return (change_types, report)

    diff_lines = diff["unified_diff"].splitlines()

    timestamp_change = False
    hash_in_xml_change = False
    hash_in_json_change = False
    version_in_xml_change = False
    property_in_xml_change = False
    for line in diff_lines:
        if TIMESTAMP_DIFF_PATTERN.search(line):
            timestamp_change = True
            report += f"Timestamp diff detected: {line}\n"
        if HASH_IN_XML_DIFF_PATTERN.search(line):
            hash_in_xml_change = True
            report += f"Hash in XML diff detected: {line}\n"
        if HASH_IN_JSON_DIFF_PATTERN.search(line):
            hash_in_json_change = True
            report += f"Hash in JSON diff detected: {line}\n"
        if XML_VERSION_CHANGED_OR_REMOVED_PATTERN.search(line):
            version_in_xml_change = True
            report += f"XML version changed or removed: {line}\n"
        if XML_PROPERTY_CHANGED_OR_REMOVED_PATTERN.search(line):
            property_in_xml_change = True
            report += f"XML property changed or removed: {line}\n"

    change_types = set()
    if timestamp_change:
        change_types.add(constants.TIMESTAMP_CHANGE)
    if hash_in_xml_change:
        change_types.add(constants.HASH_IN_XML_CHANGE)
    if hash_in_json_change:
        change_types.add(constants.HASH_IN_JSON_CHANGE)
    if version_in_xml_change:
        change_types.add(constants.VERSION_IN_XML_CHANGED_OR_REMOVED_CHANGE)
    if property_in_xml_change:
        change_types.add(constants.PROPERTY_IN_XML_CHANGED_OR_REMOVED_CHANGE)
    return (change_types, report)
