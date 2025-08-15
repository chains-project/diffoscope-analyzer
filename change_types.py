"""
Here, we define constants for types of diffs in the project.
"""
from typing import NewType

ChangeType = NewType("ChangeType", str)

# Zipinfo
PERMISSION_CHANGE: ChangeType = ChangeType("file_permission_differences")
OWNER_CHANGE: ChangeType = ChangeType("file_owner_differences") # These dissapear after OSS-rebuild
GROUP_CHANGE: ChangeType = ChangeType("file_group_differences") # These dissapear after OSS-rebuild
# NUMBER_OF_FILES_CHANGE: ChangeType = ChangeType("number_of_files_change")
FILE_CONTENT_CHANGE: ChangeType = ChangeType("file_content_differences") # This is replaced by unknown_file_content_change in a later step
UNKNOWN_FILE_CONTENT_CHANGE: ChangeType = ChangeType("unknown_file_content_differences")
FILE_REORDERED_CHANGE: ChangeType = ChangeType("file_ordering_differences")
FILE_REMOVED_CHANGE: ChangeType = ChangeType("file_removed_differences")
FILE_ADDED_CHANGE: ChangeType = ChangeType("file_added_differences")

# File name based changes
BUILDINFO_CHANGE: ChangeType = ChangeType("buildinfo_differences")
SBOM_CHANGE: ChangeType = ChangeType("sbom_differences")

# File diff changes
TIMESTAMP_CHANGE: ChangeType = ChangeType("timestamp_differences")
HASH_IN_XML_CHANGE: ChangeType = ChangeType("hash_in_xml_differences")
HASH_IN_JSON_CHANGE: ChangeType = ChangeType("hash_in_json_differences")
HASH_FILE_CHANGE: ChangeType = ChangeType("hash_file_differences")
POM_CHANGE: ChangeType = ChangeType("pom_differences")
COPYRIGHT_CHANGE: ChangeType = ChangeType("copyright_differences")
JANDEX_CHANGE: ChangeType = ChangeType("jandex_differences")
LINE_ORDERING_CHANGE: ChangeType = ChangeType("line_ordering_differences")
GENERATED_ID_CHANGE: ChangeType = ChangeType("generated_id_differences")
LINE_ENDING_CHANGE: ChangeType = ChangeType("line_ending_differences")
JAVA_VERSION_CHANGE: ChangeType = ChangeType("java_version_differences") # This is skipped because we skip analysis of class files, we might want to add it back in the future
JAVASCRIPT_CHANGE: ChangeType = ChangeType("javascript_file_differences")
MANIFEST_CHANGE: ChangeType = ChangeType("manifest_differences")
DEPENDENCY_METADATA_CHANGE: ChangeType = ChangeType("dependency_metadata_differences")
PATH_CHANGE: ChangeType = ChangeType("path_differences")
WORD_ORDERING_CHANGE: ChangeType = ChangeType("word_ordering_differences")
GIT_COMMIT_CHANGE: ChangeType = ChangeType("git_commit_differences")
GIT_PROPERTIES_CHANGE: ChangeType = ChangeType("git_properties_differences")
CLASS_FILE_CHANGE: ChangeType = ChangeType("class_file_differences")
UNKNOWN_MANIFEST_CHANGE: ChangeType = ChangeType("unknown_manifest_differences")
BINARY_CHANGE: ChangeType = ChangeType("binary_differences")
CLASS_LINE_NUMBER_CHANGE: ChangeType = ChangeType("class_line_number_differences")
JSON_DIFF_CHANGE: ChangeType = ChangeType("json_file_differences")
MANIFEST_REORDER_CHANGE: ChangeType = ChangeType("manifest_ordering_differences")

FILE_DIFF_CHANGES: set[ChangeType] = {
    TIMESTAMP_CHANGE,
    HASH_IN_XML_CHANGE,
    HASH_IN_JSON_CHANGE,
    HASH_FILE_CHANGE,
    POM_CHANGE,
    COPYRIGHT_CHANGE,
    JANDEX_CHANGE,
    LINE_ORDERING_CHANGE,
    GENERATED_ID_CHANGE,
    LINE_ENDING_CHANGE,
    JAVA_VERSION_CHANGE,
    JAVASCRIPT_CHANGE,
    MANIFEST_CHANGE,
    DEPENDENCY_METADATA_CHANGE,
    PATH_CHANGE,
    WORD_ORDERING_CHANGE,
    GIT_COMMIT_CHANGE,
    GIT_PROPERTIES_CHANGE,
    CLASS_FILE_CHANGE,
    UNKNOWN_MANIFEST_CHANGE,
    BINARY_CHANGE,
    CLASS_LINE_NUMBER_CHANGE,
    JSON_DIFF_CHANGE,
    MANIFEST_REORDER_CHANGE,
}

# Special case for unknown changes
UNKNOWN_CHANGE: ChangeType = ChangeType("other_unknown_differences")

def validate_change_types():
    """Validate that all change type constants under 'File diff changes' are included in FILE_DIFF_CHANGES.
    This is to avoid forgetting to add a new change type to FILE_DIFF_CHANGES.
    """
    # Get all variables that are defined after the File diff changes comment
    file_diff_section = False
    change_types = set()

    for name, value in globals().items():
        if name == 'FILE_DIFF_CHANGES':
            break
        if name == 'HASH_IN_XML_CHANGE':  # First change type in the File diff changes section
            file_diff_section = True
        if file_diff_section and name.endswith('_CHANGE'):
            change_types.add(value)

    # Check if all change types are in FILE_DIFF_CHANGES
    missing_types = change_types - FILE_DIFF_CHANGES
    if missing_types:
        raise ValueError(f"Missing change types in FILE_DIFF_CHANGES: {missing_types}")

# Run validation when module is imported
validate_change_types()
