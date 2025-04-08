#!/usr/bin/env python3
"""
Builds an index of packages and versions, marking if they are
reproducible or unreproducible
"""
import sys
from pathlib import Path

def build_index(root_dir_path: Path):
    if not root_dir_path.is_dir():
        print(f"Error: {root_dir_path} is not a directory.")
        return
    index = {}
    for group_id_dir in root_dir_path.iterdir():
        if not group_id_dir.is_dir():
            continue
        group_id = group_id_dir.name
        index[group_id] = {}
        for artifact_id_dir in group_id_dir.iterdir():
            if not artifact_id_dir.is_dir():
                continue
            artifact_id = artifact_id_dir.name
            index[group_id][artifact_id] = {}
            for version_dir in artifact_id_dir.iterdir():
                if not version_dir.is_dir():
                    continue
                version = version_dir.name
                index[group_id][artifact_id][version] = {}
                reproducible = True
                for file in version_dir.iterdir():
                    # If there is any diffoscope file, mark as unreproducible
                    if "diffoscope" in file.name:
                        reproducible = False
                index[group_id][artifact_id][version] = {
                    "reproducible": reproducible,
                }
    return index

def print_index_in_tree_format(index):
    for group_id, artifacts in index.items():
        print(f"{group_id}")
        for artifact_id, versions in artifacts.items():
            print(f" └─{artifact_id}")
            for version, info in versions.items():
                reproducible = "reproducible" if info["reproducible"] else "unreproducible"
                # print(f"   └─{version} ({reproducible})")

def count_total_group_ids(index):
    return len(index)

def count_total_artifacts(index):
    total_artifacts = 0
    for group_id, artifacts in index.items():
        for artifact_id, versions in artifacts.items():
            total_artifacts += 1
    return total_artifacts

def count_reproducible_artifacts(index):
    reproducible_artifacts = 0
    for group_id, artifacts in index.items():
        for artifact_id, versions in artifacts.items():
            for version, info in versions.items():
                if info["reproducible"]:
                    reproducible_artifacts += 1
                    break
    return reproducible_artifacts

def count_ratio_of_reproducible_artifacts(index):
    reproducible_artifacts = count_reproducible_artifacts(index)
    total_artifacts = count_total_artifacts(index)
    ratio = reproducible_artifacts / total_artifacts if total_artifacts > 0 else 0
    return ratio

def count_artifacts_per_group(index):
    distribution = {}
    for group_id, artifacts in index.items():
        artifact_count = len(artifacts)
        if artifact_count not in distribution:
            distribution[artifact_count] = {"count": 0, "groups": []}
        distribution[artifact_count]["count"] += 1
        if len(distribution[artifact_count]["groups"]) < 5:
            distribution[artifact_count]["groups"].append(group_id)
    return distribution


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)

    root_dir_path = Path(sys.argv[1])
    index = build_index(root_dir_path)
    # print_index_in_tree_format(index)
    # print()
    print(f"Ratio of artifacts with at least one reproducible version: {count_ratio_of_reproducible_artifacts(index):.2%}")
    print(f"Total number of group IDs: {count_total_group_ids(index)}")
    print(f"Total number of artifacts: {count_total_artifacts(index)}")
    # print(f"Ratio of artifacts per group ID: {count_total_artifacts(index) / count_total_group_ids(index):.2f}")
    print(f"Total number of reproducible artifacts: {count_reproducible_artifacts(index)}")
    print("\nDistribution of artifacts per group:")
    for artifact_count, data in sorted(count_artifacts_per_group(index).items()):
        groups_str = ", ".join(data["groups"])
        if len(data["groups"]) < data["count"]:
            groups_str += f" ... and {data['count'] - len(data['groups'])} more"
        print(f"Groups with {artifact_count} artifacts ({data['count']}): {groups_str}")
