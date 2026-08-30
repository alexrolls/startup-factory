"""Canonical normalization for protected rootless Podman proofs."""

from __future__ import annotations

import re


def normalize_runtime_proofs(info, inspected, image, fail):
    """Validate and normalize the two machine proofs used by every runtime path.

    Keep this function self-contained: its source is embedded verbatim into the
    isolated runner, while the planner and readiness checker import it normally.
    """

    if not isinstance(info, dict):
        fail("Podman info proof must be an object")
    version = info.get("version")
    host = info.get("host")
    security = host.get("security") if isinstance(host, dict) else None
    mappings = host.get("idMappings") if isinstance(host, dict) else None
    version_text = version.get("Version") if isinstance(version, dict) else None

    def valid_mapping(rows):
        return bool(
            isinstance(rows, list)
            and rows
            and all(
                isinstance(row, dict)
                and set(row) == {"container_id", "host_id", "size"}
                and all(
                    type(row[key]) is int and row[key] >= 0
                    for key in ("container_id", "host_id")
                )
                and type(row["size"]) is int
                and row["size"] > 0
                for row in rows
            )
            and any(row["container_id"] == 0 for row in rows)
        )

    if (
        not isinstance(version_text, str)
        or version_text.split(".", 1)[0] != "5"
        or not isinstance(security, dict)
        or security.get("rootless") is not True
    ):
        fail("runtime-kit requires machine-proved rootless Podman major version 5")
    if (
        not isinstance(mappings, dict)
        or set(mappings) != {"uidmap", "gidmap"}
        or not valid_mapping(mappings.get("uidmap"))
        or not valid_mapping(mappings.get("gidmap"))
    ):
        fail("rootless Podman proof is missing UID/GID namespace mappings")
    if not isinstance(inspected, list) or len(inspected) != 1 or not isinstance(inspected[0], dict):
        fail("Podman image proof must contain exactly one local image")
    repository_digests = inspected[0].get("RepoDigests")
    image_id = inspected[0].get("Id")
    if (
        not isinstance(repository_digests, list)
        or not all(isinstance(item, str) for item in repository_digests)
        or image not in repository_digests
        or not isinstance(image_id, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None
    ):
        fail("local Podman image proof has an invalid or mismatched image identity")
    return (
        {
            "version": version_text,
            "rootless": True,
            "uidmap": mappings["uidmap"],
            "gidmap": mappings["gidmap"],
        },
        {"Id": image_id, "RepoDigests": sorted(set(repository_digests))},
    )
