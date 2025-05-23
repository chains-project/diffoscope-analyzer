"""
Here, we define constants for types of diffs in the project.
"""
from typing import NewType

ChangeType = NewType("ChangeType", str)

# Zipinfo
TIMESTAMP_CHANGE: ChangeType = "timestamp_change"
PERMISSION_CHANGE: ChangeType = "permission_change"
OWNER_CHANGE: ChangeType = "owner_change"
GROUP_CHANGE: ChangeType = "group_change"
NUMBER_OF_FILES_CHANGE: ChangeType = "number_of_files_change"
FILE_CONTENT_CHANGE: ChangeType = "file_content_change"
UNKNOWN_FILE_CONTENT_CHANGE: ChangeType = "unknown_file_content_change"
FILE_REORDERED_CHANGE: ChangeType = "file_reordered_change"
FILE_REMOVED_CHANGE: ChangeType = "file_removed_change"
FILE_ADDED_CHANGE: ChangeType = "file_added_change"

# Experimental file diff changes
HASH_IN_XML_CHANGE: ChangeType = "hash_in_xml_change"
HASH_IN_JSON_CHANGE: ChangeType = "hash_in_json_change"
HASH_FILE_CHANGE: ChangeType = "hash_file_change"
POM_CHANGE: ChangeType = "pom_change"
COPYRIGHT_CHANGE: ChangeType = "copyright_change"
JANDEX_CHANGE: ChangeType = "jandex_change"
LINE_ORDERING_CHANGE: ChangeType = "line_ordering_change"
GENERATED_ID_CHANGE: ChangeType = "generated_id_change"
LINE_ENDING_CHANGE: ChangeType = "line_ending_change"
JAVA_VERSION_CHANGE: ChangeType = "java_version_change"
JS_BEAUTIFY_CHANGE: ChangeType = "js_beautify_change"
BUILD_METADATA_CHANGE: ChangeType = "build_metadata_change"
DEPENDENCY_METADATA_CHANGE: ChangeType = "dependency_metadata_change"
PATH_CHANGE: ChangeType = "path_change"
WORD_ORDERING_CHANGE: ChangeType = "word_ordering_change"
GIT_COMMIT_CHANGE: ChangeType = "git_commit_change"
GIT_PROPERTIES_CHANGE: ChangeType = "git_properties_change"
CLASS_FILE_CHANGE: ChangeType = "class_file_change"
UNKNOWN_MANIFEST_CHANGE: ChangeType = "unknown_manifest_change"
HEXDUMP_CHANGE: ChangeType = "hexdump_change"

# Special case for unknown changes
UNKNOWN_CHANGE: ChangeType = "unknown_change"
