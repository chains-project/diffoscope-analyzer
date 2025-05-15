"""
Here, we define constants for types of diffs in the project.
"""

# Zipinfo
TIMESTAMP_CHANGE = "timestamp_change"
PERMISSION_CHANGE = "permission_change"
OWNER_CHANGE = "owner_change"
GROUP_CHANGE = "group_change"
NUMBER_OF_FILES_CHANGE = "number_of_files_change"
FILE_CONTENT_OR_SIZE_CHANGE = "file_content_or_size_change"
FILE_REORDERED_CHANGE = "file_reordered_change"
FILE_REMOVED_CHANGE = "file_removed_change"
FILE_ADDED_CHANGE = "file_added_change"

# Experimental file diff changes
HASH_IN_XML_CHANGE = "hash_in_xml_change"
HASH_IN_JSON_CHANGE = "hash_in_json_change"
HASH_FILE_CHANGE = "hash_file_change"
POM_CHANGE = "pom_change"
COPYRIGHT_CHANGE = "copyright_change"
JANDEX_CHANGE = "jandex_change"
LINE_ORDERING_CHANGE = "line_ordering_change"
GENERATED_ID_CHANGE = "generated_id_change"
LINE_ENDING_CHANGE = "line_ending_change"
JAVA_VERSION_CHANGE = "java_version_change"
JS_BEAUTIFY_CHANGE = "js_beautify_change"
BUILD_METADATA_CHANGE = "build_metadata_change"
PATH_CHANGE = "path_change"
WORD_ORDERING_CHANGE = "word_ordering_change"
GIT_COMMIT_CHANGE = "git_commit_change"

# Special case for unknown changes
UNKNOWN_CHANGE = "unknown_change"
