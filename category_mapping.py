"""
Category mapping for change types - maps specific change types to broader categories.
"""
from typing import Dict, Set
from change_types import (
    ChangeType,
    UNKNOWN_CHANGE,
    UNKNOWN_FILE_CONTENT_CHANGE,
    BINARY_CHANGE,
    UNKNOWN_MANIFEST_CHANGE,
    MANIFEST_CHANGE,
    MANIFEST_REORDER_CHANGE,
    CLASS_FILE_CHANGE,
    CLASS_LINE_NUMBER_CHANGE,
    COPYRIGHT_CHANGE,
    TIMESTAMP_CHANGE,
    BUILDINFO_CHANGE,
    PATH_CHANGE,
    GIT_PROPERTIES_CHANGE,
    LINE_ENDING_CHANGE,
    PERMISSION_CHANGE,
    POM_CHANGE,
    GIT_COMMIT_CHANGE,
    DEPENDENCY_METADATA_CHANGE,
    SBOM_CHANGE,
    FILE_ADDED_CHANGE,
    FILE_REMOVED_CHANGE,
    GENERATED_ID_CHANGE,
    FILE_REORDERED_CHANGE,
    LINE_ORDERING_CHANGE,
    WORD_ORDERING_CHANGE,
    JAVASCRIPT_CHANGE,
    JSON_DIFF_CHANGE,
    HASH_FILE_CHANGE,
    HASH_IN_JSON_CHANGE,
    HASH_IN_XML_CHANGE,
    OWNER_CHANGE,
    GROUP_CHANGE,
    FILE_CONTENT_CHANGE,
    JANDEX_CHANGE,
    JAVA_VERSION_CHANGE,
)

# Define broader categories
CATEGORY_UNKNOWN_CHANGES = "Unknown changes"
CATEGORY_MANIFEST = "Manifest changes"
CATEGORY_JVM_BYTECODE = "JVM Bytecode / Class file changes"
CATEGORY_DATE_TIMESTAMP = "Date and timestamp changes"
CATEGORY_BUILD_ENVIRONMENT = "Build environment and build configuration"
CATEGORY_SBOM_DEPENDENCY = "SBOM and dependency metadata changes"
CATEGORY_FILES_ADDED_REMOVED = "Files added or removed"
CATEGORY_GENERATED_IDS_AND_REORDERING = "Generated IDs and reordering"
CATEGORY_OTHER_FILE_CHANGES = "Other file changes"
CATEGORY_HASH_CHANGES = "Hash changes"

# Mapping from change types to categories
CHANGE_TYPE_TO_CATEGORY: Dict[ChangeType, str] = {
    # Unknown changes
    UNKNOWN_CHANGE: CATEGORY_UNKNOWN_CHANGES,
    UNKNOWN_FILE_CONTENT_CHANGE: CATEGORY_UNKNOWN_CHANGES,
    BINARY_CHANGE: CATEGORY_UNKNOWN_CHANGES,

    # Build manifest changes
    UNKNOWN_MANIFEST_CHANGE: CATEGORY_MANIFEST,
    MANIFEST_CHANGE: CATEGORY_MANIFEST,
    MANIFEST_REORDER_CHANGE: CATEGORY_MANIFEST,

    # JVM Bytecode / Class file changes
    CLASS_FILE_CHANGE: CATEGORY_JVM_BYTECODE,
    CLASS_LINE_NUMBER_CHANGE: CATEGORY_JVM_BYTECODE,

    # Date and timestamp changes
    COPYRIGHT_CHANGE: CATEGORY_DATE_TIMESTAMP,
    TIMESTAMP_CHANGE: CATEGORY_DATE_TIMESTAMP,

    # Build environment and build configuration
    BUILDINFO_CHANGE: CATEGORY_BUILD_ENVIRONMENT,
    PATH_CHANGE: CATEGORY_BUILD_ENVIRONMENT,
    GIT_PROPERTIES_CHANGE: CATEGORY_BUILD_ENVIRONMENT,
    LINE_ENDING_CHANGE: CATEGORY_BUILD_ENVIRONMENT,
    PERMISSION_CHANGE: CATEGORY_BUILD_ENVIRONMENT,
    POM_CHANGE: CATEGORY_BUILD_ENVIRONMENT,
    GIT_COMMIT_CHANGE: CATEGORY_BUILD_ENVIRONMENT,

    # SBOM and dependency metadata changes
    DEPENDENCY_METADATA_CHANGE: CATEGORY_SBOM_DEPENDENCY,
    SBOM_CHANGE: CATEGORY_SBOM_DEPENDENCY,

    # Files added or removed
    FILE_ADDED_CHANGE: CATEGORY_FILES_ADDED_REMOVED,
    FILE_REMOVED_CHANGE: CATEGORY_FILES_ADDED_REMOVED,

    # Non-deterministic build
    GENERATED_ID_CHANGE: CATEGORY_GENERATED_IDS_AND_REORDERING,
    FILE_REORDERED_CHANGE: CATEGORY_GENERATED_IDS_AND_REORDERING,
    LINE_ORDERING_CHANGE: CATEGORY_GENERATED_IDS_AND_REORDERING,
    WORD_ORDERING_CHANGE: CATEGORY_GENERATED_IDS_AND_REORDERING,
    JANDEX_CHANGE: CATEGORY_GENERATED_IDS_AND_REORDERING,

    # Other file changes
    JAVASCRIPT_CHANGE: CATEGORY_OTHER_FILE_CHANGES,
    JSON_DIFF_CHANGE: CATEGORY_OTHER_FILE_CHANGES,

    # Dependent on other changes
    HASH_FILE_CHANGE: CATEGORY_HASH_CHANGES,
    HASH_IN_JSON_CHANGE: CATEGORY_HASH_CHANGES,
    HASH_IN_XML_CHANGE: CATEGORY_HASH_CHANGES,

    # Additional change types that weren't explicitly categorized
    OWNER_CHANGE: CATEGORY_BUILD_ENVIRONMENT,
    GROUP_CHANGE: CATEGORY_BUILD_ENVIRONMENT,
    FILE_CONTENT_CHANGE: CATEGORY_UNKNOWN_CHANGES,
    JAVA_VERSION_CHANGE: CATEGORY_JVM_BYTECODE,
}

def get_category_for_change_type(change_type: ChangeType) -> str:
    """Get the broader category for a specific change type."""
    return CHANGE_TYPE_TO_CATEGORY.get(change_type, "Uncategorized")

def group_changes_by_category(change_counts: Dict[ChangeType, int]) -> Dict[str, Dict[ChangeType, int]]:
    """Group change counts by their broader categories."""
    categorized_changes: Dict[str, Dict[ChangeType, int]] = {}

    for change_type, count in change_counts.items():
        category = get_category_for_change_type(change_type)

        if category not in categorized_changes:
            categorized_changes[category] = {}

        categorized_changes[category][change_type] = count

    return categorized_changes

def get_category_totals(change_counts: Dict[ChangeType, int]) -> Dict[str, int]:
    """Get total counts for each category."""
    category_totals: Dict[str, int] = {}

    for change_type, count in change_counts.items():
        category = get_category_for_change_type(change_type)
        category_totals[category] = category_totals.get(category, 0) + count

    return category_totals

def print_categorized_summary(change_counts: Dict[ChangeType, int]):
    """Print a summary of changes grouped by categories."""
    categorized_changes = group_changes_by_category(change_counts)
    category_totals = get_category_totals(change_counts)

    print("\nSummarized categories:")

    # Sort categories by total count (descending)
    sorted_categories = sorted(category_totals.items(), key=lambda x: x[1], reverse=True)

    for category, total_count in sorted_categories:
        print(f"\n{category}: {total_count}")

        if category in categorized_changes:
            # Sort change types within category by count (descending)
            sorted_changes = sorted(categorized_changes[category].items(),
                                  key=lambda x: x[1], reverse=True)

            for change_type, count in sorted_changes:
                # Format change type name for display
                display_name = change_type.replace('_', ' ').title()
                print(f"  - {display_name}: {count}")
