#!/usr/bin/env python3
"""Black-box tests for fail-closed capability supersession and revocation."""

from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
from outbox_capability import (  # noqa: E402
    CapabilityError,
    mint,
    revoke_exact,
    revoke_role,
    revoke_task,
    sign_active_entry,
    sign_entry,
    verify_entry,
)
from review_evidence import (  # noqa: E402
    EvidenceError,
    bind_approval_request,
    bind_request,
    finalize_bound_approval,
)

FEATURE = "FEATURE-1"
TEAM = "factory-one"
ROLE = "principal-architect"
BODY = b"architecture verdict body\n"
BODY_DIGEST = "sha256:" + hashlib.sha256(BODY).hexdigest()


def entry(actor: str = ROLE, *, marker: str = "architecture-approval") -> dict:
    return {
        "schemaVersion": 1,
        "id": "entry-1",
        "team": TEAM,
        "featureId": FEATURE,
        "taskId": "TASK-1",
        "attempt": 1,
        "actor": actor,
        "marker": marker,
        "bodyPath": "/canonical/producer-body.md",
        "targetStatus": None,
        "phase": "pending",
        "createdAt": "2026-09-02T10:00:00Z",
    }


class OutboxCapabilitySupersedeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.base = self.root / "repo"
        self.base.mkdir()
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        subprocess.run(
            ["git", "init", "-q", str(self.base)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def mint_gate(self, role: str = ROLE, ttl_seconds: int = 24 * 60 * 60) -> dict:
        """Mint a gate capability the way launch-team.sh does.

        The instance is `gate:<role>`, which is stable across launches, so a
        relaunch of the same role mints into the same active pointer.
        """
        return mint(
            str(self.base),
            str(self.workspace),
            TEAM,
            FEATURE,
            role,
            "gate",
            "-",
            0,
            "gate:%s" % role,
            ttl_seconds,
        )

    def signed(self, capability: dict, payload: dict | None = None) -> dict:
        return sign_entry(
            payload or entry(),
            BODY,
            capability["id"],
            capability["secret"],
            capability["instance"],
            capability["expiresAt"],
        )

    def verify(self, payload: dict, signature: dict) -> dict:
        enriched = dict(payload)
        enriched["producerCapability"] = signature
        return verify_entry(str(self.base), str(self.workspace), enriched, BODY_DIGEST)

    def test_capability_verifies_while_it_is_the_active_launch(self) -> None:
        capability = self.mint_gate()
        payload = entry()
        verified = self.verify(payload, self.signed(capability, payload))
        self.assertEqual(verified["role"], ROLE)
        self.assertEqual(verified["executionKind"], "gate")

    def test_relaunch_fences_what_the_previous_boot_enqueued(self) -> None:
        first = self.mint_gate()
        payload = entry()
        signature = self.signed(first, payload)

        self.mint_gate()  # relaunch: same instance, replaces the active pointer

        with self.assertRaises(CapabilityError) as caught:
            self.verify(payload, signature)
        self.assertIn("superseded", str(caught.exception))

    def test_three_stale_gate_generations_are_all_fenced(self) -> None:
        roles = ("principal-architect", "sceptical-architect", "senior-security-engineer")
        enqueued = []
        for role in roles:
            capability = self.mint_gate(role)
            payload = entry(actor=role)
            enqueued.append((payload, self.signed(capability, payload)))

        for role in roles:
            self.mint_gate(role)

        for role, (payload, signature) in zip(roles, enqueued):
            with self.subTest(role=role):
                with self.assertRaises(CapabilityError) as caught:
                    self.verify(payload, signature)
                self.assertIn("superseded", str(caught.exception))

    def test_revocation_still_rejects(self) -> None:
        capability = self.mint_gate()
        payload = entry()
        signature = self.signed(capability, payload)

        self.assertEqual(revoke_role(str(self.base), str(self.workspace), TEAM, ROLE), 1)

        with self.assertRaises(CapabilityError) as caught:
            self.verify(payload, signature)
        self.assertIn("revoked", str(caught.exception))

    def test_revocation_outlives_a_later_mint_for_the_same_role(self) -> None:
        """The hole a naive supersession fix would open.

        Revoking clears the active pointer; a later mint recreates it.  Without
        a durable tombstone the revoked capability would then be
        indistinguishable from a merely superseded one and would publish.
        """
        capability = self.mint_gate()
        payload = entry()
        signature = self.signed(capability, payload)

        revoke_role(str(self.base), str(self.workspace), TEAM, ROLE)
        self.mint_gate()  # pointer exists again, naming a different capability

        with self.assertRaises(CapabilityError) as caught:
            self.verify(payload, signature)
        self.assertIn("revoked", str(caught.exception))

    def test_task_revocation_outlives_a_later_mint(self) -> None:
        def mint_task() -> dict:
            return mint(
                str(self.base),
                str(self.workspace),
                TEAM,
                FEATURE,
                ROLE,
                "task",
                "TASK-1",
                1,
                "task:TASK-1:1",
            )

        capability = mint_task()
        payload = entry()
        payload["taskId"] = "TASK-1"
        payload["attempt"] = 1
        signature = self.signed(capability, payload)

        self.assertEqual(
            revoke_task(str(self.base), str(self.workspace), TEAM, "TASK-1"), 1
        )
        mint_task()

        with self.assertRaises(CapabilityError) as caught:
            self.verify(payload, signature)
        self.assertIn("revoked", str(caught.exception))

    def test_all_worktrees_revocation_fences_the_original_checkout(self) -> None:
        subprocess.run(
            [
                "git",
                "-C",
                str(self.base),
                "-c",
                "user.name=Capability Test",
                "-c",
                "user.email=capability@example.invalid",
                "commit",
                "--quiet",
                "--allow-empty",
                "-m",
                "linked-worktree fixture",
            ],
            check=True,
            capture_output=True,
        )
        linked = self.root / "linked"
        subprocess.run(
            [
                "git",
                "-C",
                str(self.base),
                "worktree",
                "add",
                "--quiet",
                "--detach",
                str(linked),
            ],
            check=True,
            capture_output=True,
        )
        linked_workspace = linked / "workspace"
        linked_workspace.mkdir()
        capability = mint(
            str(self.base),
            str(self.workspace),
            TEAM,
            FEATURE,
            "implementer",
            "task",
            "TASK-1",
            1,
            "implementer--task-1--a1",
        )
        payload = entry(actor="implementer", marker="handoff")
        signature = self.signed(capability, payload)

        # The legacy workspace-scoped operation cannot see authority minted by
        # another linked checkout even though lifecycle state is Git-common.
        self.assertEqual(
            revoke_task(
                str(linked), str(linked_workspace), TEAM, "TASK-1"
            ),
            0,
        )
        self.assertEqual(self.verify(payload, signature)["role"], "implementer")

        # The lifecycle-facing mode traverses only this protected Git-common
        # broker, but covers every linked checkout scope within it.
        self.assertEqual(
            revoke_task(
                str(linked),
                str(linked_workspace),
                TEAM,
                "TASK-1",
                all_worktrees=True,
            ),
            1,
        )
        with self.assertRaisesRegex(CapabilityError, "revoked"):
            self.verify(payload, signature)

    def test_new_task_attempt_supersedes_the_stable_task_lane(self) -> None:
        first = mint(
            str(self.base), str(self.workspace), TEAM, FEATURE, "implementer",
            "task", "TASK-1", 1, "task:TASK-1:1",
        )
        payload = entry(actor="implementer", marker="handoff")
        payload.update({"taskId": "TASK-1", "attempt": 1})
        signature = self.signed(first, payload)

        mint(
            str(self.base), str(self.workspace), TEAM, FEATURE, "senior-engineer",
            "task", "TASK-1", 2, "task:TASK-1:2",
        )

        with self.assertRaises(CapabilityError) as caught:
            self.verify(payload, signature)
        self.assertIn("superseded", str(caught.exception))

    def test_exact_revoke_never_removes_a_successor_pointer(self) -> None:
        first = self.mint_gate()
        second = self.mint_gate()
        self.assertEqual(
            revoke_exact(str(self.base), str(self.workspace), first["id"]), 0
        )
        payload = entry()
        verified = self.verify(payload, self.signed(second, payload))
        self.assertEqual(verified["role"], ROLE)

    def test_durably_admitted_exact_package_recovers_after_revoke(self) -> None:
        capability = self.mint_gate()
        payload = entry()
        signature = sign_active_entry(
            str(self.base), str(self.workspace), capability["id"], payload, BODY
        )

        revoke_exact(str(self.base), str(self.workspace), capability["id"])

        self.assertEqual(self.verify(payload, signature)["role"], ROLE)

    def test_admission_does_not_authorize_a_mutated_entry(self) -> None:
        capability = self.mint_gate()
        payload = entry()
        signature = sign_active_entry(
            str(self.base), str(self.workspace), capability["id"], payload, BODY
        )
        revoke_exact(str(self.base), str(self.workspace), capability["id"])
        mutated = dict(payload)
        mutated["createdAt"] = "2026-09-02T10:00:01Z"

        with self.assertRaises(CapabilityError):
            self.verify(mutated, signature)

    def test_publication_admission_requires_the_exact_closed_producer_schema(self) -> None:
        capability = self.mint_gate()
        for name, mutated in (
            ("missing-body-path", {key: value for key, value in entry().items() if key != "bodyPath"}),
            ("unknown-field", {**entry(), "workerChosenPhase": "published"}),
            ("mutated-phase", {**entry(), "phase": "commented"}),
            ("relative-body-path", {**entry(), "bodyPath": "body.md"}),
        ):
            with self.subTest(name=name):
                with self.assertRaises(CapabilityError):
                    sign_active_entry(
                        str(self.base), str(self.workspace), capability["id"], mutated, BODY
                    )

    def test_signature_binds_phase_body_path_and_target_status(self) -> None:
        capability = self.mint_gate()
        payload = entry()
        signature = self.signed(capability, payload)
        for name, value in (
            ("bodyPath", "/canonical/other-body.md"),
            ("targetStatus", "Review"),
        ):
            mutated = dict(payload)
            mutated[name] = value
            with self.subTest(name=name):
                with self.assertRaises(CapabilityError):
                    self.verify(mutated, signature)
        mutated = dict(payload)
        mutated["phase"] = "published"
        with self.assertRaises(CapabilityError):
            self.verify(mutated, signature)

    def test_revoked_admitted_a_approval_cannot_be_rebound_to_request_b(self) -> None:
        request_a = bind_request(
            "[review-request]\nFiles: app.py\n",
            "a" * 40,
            "b" * 40,
            "sha256:" + "c" * 64,
        )
        request_b = bind_request(
            "[review-request]\nFiles: app.py\n",
            "a" * 40,
            "d" * 40,
            "sha256:" + "e" * 64,
        )
        body = bind_approval_request(
            "[architecture-approval]\nFiles: app.py\n\n- principal-architect\n",
            request_a,
        ).encode()
        capability = self.mint_gate()
        payload = entry()
        payload["bodyPath"] = "/canonical/approval-a.md"
        payload["producerCapability"] = sign_active_entry(
            str(self.base), str(self.workspace), capability["id"], payload, body
        )
        revoke_exact(str(self.base), str(self.workspace), capability["id"])
        body_digest = "sha256:" + hashlib.sha256(body).hexdigest()
        self.assertEqual(
            ROLE,
            verify_entry(
                str(self.base), str(self.workspace), payload, body_digest
            )["role"],
        )
        with self.assertRaisesRegex(EvidenceError, "producer binding does not match"):
            finalize_bound_approval(
                body.decode(),
                request_b,
                ROLE,
                capability["id"] + ":" + capability["instance"],
            )

    def test_expiry_bounds_an_active_capability(self) -> None:
        capability = self.mint_gate(ttl_seconds=60)
        payload = entry()
        signature = self.signed(capability, payload)

        import outbox_capability

        original = outbox_capability.time.time
        outbox_capability.time.time = lambda: original() + 120
        try:
            with self.assertRaises(CapabilityError) as caught:
                self.verify(payload, signature)
        finally:
            outbox_capability.time.time = original
        self.assertIn("expired", str(caught.exception))

    def test_cleared_pointer_without_a_tombstone_fails_closed(self) -> None:
        """Legacy state predating tombstones must not become publishable."""
        capability = self.mint_gate()
        payload = entry()
        signature = self.signed(capability, payload)

        broker = self.base / ".git" / "startup-factory-broker"
        pointers = sorted((broker / "outbox-active").glob("*.id"))
        self.assertEqual(len(pointers), 1)
        pointers[0].unlink()

        with self.assertRaises(CapabilityError) as caught:
            self.verify(payload, signature)
        self.assertIn("not active", str(caught.exception))

    def test_revocation_covers_a_capability_superseded_before_it(self) -> None:
        """Revoking fences off the identity, not just the newest capability.

        A revoke can only see whichever capability the active pointer names, so
        an earlier boot's capability -- already superseded, still holding an
        undrained artifact -- would never be tombstoned by id. launch-team.sh
        restarts a role by revoking and relaunching, so "superseded, then
        revoked, then relaunched" is an ordinary sequence, not an edge case.
        """
        first = self.mint_gate()
        payload = entry()
        signature = self.signed(first, payload)

        self.mint_gate()  # a relaunch supersedes the boot that enqueued
        revoke_role(str(self.base), str(self.workspace), TEAM, ROLE)
        self.mint_gate()  # a further relaunch recreates the active pointer

        with self.assertRaises(CapabilityError) as caught:
            self.verify(payload, signature)
        self.assertIn("revoked", str(caught.exception))

    def test_a_capability_minted_after_a_revocation_still_publishes(self) -> None:
        """Fencing an identity must not disable it forever."""
        revoke_role(str(self.base), str(self.workspace), TEAM, ROLE)
        capability = self.mint_gate()
        payload = entry()
        self.assertEqual(self.verify(payload, self.signed(capability, payload))["role"], ROLE)

    def tombstones(self) -> Path:
        return self.base / ".git" / "startup-factory-broker" / "outbox-revoked"

    def test_a_group_readable_tombstone_is_treated_as_revoked(self) -> None:
        """Revocation evidence that cannot be trusted must not let work publish."""
        capability = self.mint_gate()
        payload = entry()
        signature = self.signed(capability, payload)
        revoke_role(str(self.base), str(self.workspace), TEAM, ROLE)
        self.mint_gate()

        marker = self.tombstones() / (capability["id"] + ".revoked")
        marker.chmod(0o644)

        with self.assertRaises(CapabilityError) as caught:
            self.verify(payload, signature)
        self.assertIn("owner-only", str(caught.exception))

    def test_a_symlinked_tombstone_is_treated_as_revoked(self) -> None:
        capability = self.mint_gate()
        payload = entry()
        signature = self.signed(capability, payload)
        revoke_role(str(self.base), str(self.workspace), TEAM, ROLE)
        self.mint_gate()

        marker = self.tombstones() / (capability["id"] + ".revoked")
        marker.unlink()
        marker.symlink_to(self.base / "elsewhere")

        with self.assertRaises(CapabilityError) as caught:
            self.verify(payload, signature)
        self.assertIn("symlink", str(caught.exception))

    def test_a_directory_in_place_of_a_tombstone_is_treated_as_revoked(self) -> None:
        capability = self.mint_gate()
        payload = entry()
        signature = self.signed(capability, payload)
        revoke_role(str(self.base), str(self.workspace), TEAM, ROLE)
        self.mint_gate()

        marker = self.tombstones() / (capability["id"] + ".revoked")
        marker.unlink()
        marker.mkdir()

        with self.assertRaises(CapabilityError) as caught:
            self.verify(payload, signature)
        self.assertIn("regular file", str(caught.exception))

    def test_a_forged_signature_is_rejected_while_active(self) -> None:
        capability = self.mint_gate()
        payload = entry()
        signature = self.signed(capability, payload)

        forged = dict(signature)
        forged["signature"] = "hmac-sha256:" + "0" * 64
        with self.assertRaises(CapabilityError) as caught:
            self.verify(payload, forged)
        self.assertIn("signature mismatch", str(caught.exception))

    def test_a_capability_cannot_publish_for_another_role(self) -> None:
        capability = self.mint_gate()

        payload = entry(actor="team-lead")
        with self.assertRaises(CapabilityError) as caught:
            self.verify(payload, self.signed(capability, payload))
        self.assertIn("does not match the verified capability role", str(caught.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
