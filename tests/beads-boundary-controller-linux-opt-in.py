#!/usr/bin/env python3
"""Opt-in, real Linux distinct-UID controller transport probe.

Run only on a disposable, operator-provisioned Linux host after installing the
tmpfiles rule and starting the shipped systemd service.  The ordinary offline suite intentionally
skips this proof and never promotes runtime readiness.
"""

from __future__ import annotations

import hashlib
import os
import sys


if os.environ.get("STARTUP_FACTORY_REAL_BEADS_CONTROLLER_PROBE") != "1":
    print(
        "SKIP: set STARTUP_FACTORY_REAL_BEADS_CONTROLLER_PROBE=1 on an "
        "operator-provisioned disposable Linux host"
    )
    raise SystemExit(0)

if not sys.platform.startswith("linux"):
    raise SystemExit("real Beads controller probe requires Linux")
if os.geteuid() != 0:
    raise SystemExit("real Beads controller probe must start as root to drop to the broker UID")

from startup_factory_cli import beads_boundary_controller as controller  # noqa: E402


EXPECTED_OPERATIONS = (
    "prepare_atomic_claim_v1",
    "advance_atomic_claim_v1",
    "record_atomic_claim_receipt_v1",
    "authorize_claim_launch_v1",
    "begin_beads_mutation_v1",
    "finish_beads_mutation_v1",
    "verify_beads_installed_database_selector_v1",
    "authorize_beads_preparation_v1",
    "begin_beads_preparation_v1",
    "observe_beads_store_v1",
    "advance_beads_preparation_v1",
    "derive_beads_status_profile_dynamic_bindings_v1",
    "finish_beads_preparation_v1",
    "verify_current_beads_preparation_v1",
    "verify_historical_beads_preparation_v1",
    "record_beads_change_plan_core_v1",
    "verify_beads_change_plan_core_record_v1",
    "authorize_beads_authority_transition_v1",
    "revoke_beads_authority_epoch_v1",
    "stage_beads_authority_epoch_v1",
    "activate_beads_authority_epoch_v1",
    "verify_active_beads_authority_v1",
    "verify_beads_authority_transition_receipt_v1",
    "authorize_beads_runtime_api_manifest_record_v1",
    "record_beads_protected_runtime_api_manifest_v1",
    "verify_current_beads_protected_runtime_api_manifest_v1",
    "verify_historical_beads_protected_runtime_api_manifest_v1",
    "authorize_beads_adapter_release_manifest_record_v1",
    "record_beads_adapter_release_manifest_v1",
    "verify_current_beads_adapter_release_manifest_v1",
)

if controller.ALLOWED_OPERATIONS != EXPECTED_OPERATIONS:
    raise SystemExit("installed controller operation set differs from the static probe contract")


config = controller.load_controller_config()
controller._validate_transport_group(config)
controller._validate_endpoint_parent(config)
controller._endpoint_metadata(config)

# Drop irreversibly to the exact configured broker identity.  The controller
# service remains the distinct configured controller UID and validates our
# Linux SO_PEERCRED UID on each fresh connection.
os.setgroups([config.transport_gid])
os.setgid(config.transport_gid)
os.setuid(config.broker_uid)
if (
    os.geteuid() != config.broker_uid
    or os.getegid() != config.transport_gid
    or set(os.getgroups()) != {config.transport_gid}
):
    raise SystemExit("failed to enter the exact broker/transport identity")

nonce = os.urandom(32)
repository = "sha256:" + hashlib.sha256(b"real-controller-repository\0" + nonce).hexdigest()
request_sha = "sha256:" + hashlib.sha256(b"real-controller-request\0" + nonce).hexdigest()
_, opened = controller.open_operation(
    "verify_active_beads_authority_v1",
    {
        "repositoryLocatorSha256": repository,
        "requestSha256": request_sha,
    },
)
validated = controller.validate_stored_receipt(
    config,
    operation_id=opened["operationId"],
    stored_receipt_sha256=opened["receiptSha256"],
    expected_state="accepted",
    expected_result_sha256=None,
)
if validated.get("status") != "validated":
    raise SystemExit("controller did not validate the fresh accepted receipt")

print(
    "real Linux Beads controller distinct-UID SOCK_SEQPACKET probe: PASS "
    "(connectivity evidence only; readiness remains separately gated)"
)
