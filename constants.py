"""
Here, we define constants for types of diffs in the project.
"""

TIMESTAMP_CHANGE = "timestamp_change"
PERMISSION_CHANGE = "permission_change"
OWNER_CHANGE = "owner_change"
GROUP_CHANGE = "group_change"
NUMBER_OF_FILES_CHANGE = "number_of_files_change"
FILE_CONTENT_OR_SIZE_CHANGE = "file_content_or_size_change"
FILE_REORDERED_CHANGE = "file_reordered_change"
FILE_REMOVED_CHANGE = "file_removed_change"
FILE_ADDED_CHANGE = "file_added_change"

# Experimental
HASH_IN_XML_CHANGE = "hash_in_xml_change"
HASH_IN_JSON_CHANGE = "hash_in_json_change"
POM_CHANGE = "pom_change"

# Special case for unknown changes
UNKNOWN_CHANGE = "unknown_change"
