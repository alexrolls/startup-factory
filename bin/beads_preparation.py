"""Internal task-2 preparation consumer for the unsigned store payload."""

from __future__ import annotations

from .beads_contract import (
    PreparedBeadsStoreExpectedBindingsV1,
    PreparedBeadsStorePayloadInputsV1,
    VerifiedPreparedBeadsStorePayloadV1,
    build_prepared_beads_store_payload_v1,
    validate_prepared_beads_store_payload_v1,
)

__all__: tuple[str, ...] = ()


def _prepare_unsigned_beads_store_payload_v1(
    inputs: PreparedBeadsStorePayloadInputsV1,
    expected: PreparedBeadsStoreExpectedBindingsV1,
) -> VerifiedPreparedBeadsStorePayloadV1:
    """Build then independently reopen the exact bytes handed to task 3."""

    canonical_bytes = build_prepared_beads_store_payload_v1(inputs)
    return validate_prepared_beads_store_payload_v1(canonical_bytes, expected)
