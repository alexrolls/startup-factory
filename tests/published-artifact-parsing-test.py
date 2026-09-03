#!/usr/bin/env python3
"""Reading a published artifact must see what the role wrote, not the transport.

The publication path appends `delivery-id: <id>` as the last line of every
artifact it writes.  Anything that reads a published body from the tail — the
role signature, a "last line" heuristic — sees that trailer unless it is removed
first.  When the signature resolves to the delivery id instead of a role, every
gate on a [task] looks foreign to the planner, the [task] is dropped from every
queue, and the board relaunches the same reviewer forever without ever reaching
the merge queue.  These tests pin that, and the `Files:` evidence the integrator
compares against the reviewed diff.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))

from review_evidence import (  # noqa: E402
    parse_files_evidence,
    strip_publication_trailer,
)


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "bin" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


dispatch_plan = load("startup_factory_dispatch_plan", "dispatch-plan.py")

DELIVERY = "delivery-id: delivery-" + "0" * 32


def published(body: str) -> str:
    """Mirror what the publication path appends to an authored body."""
    return body + "\n\n" + DELIVERY


class StripPublicationTrailerTest(unittest.TestCase):
    def test_trailer_is_removed_so_the_tail_is_what_the_role_wrote(self):
        body = published("[security-approval]\nverdict: APPROVED\n\n— security-reviewer")
        self.assertEqual(strip_publication_trailer(body).splitlines()[-1], "— security-reviewer")

    def test_body_without_a_trailer_is_unchanged(self):
        body = "[team-lead-approval]\nverdict: APPROVED\n\n— team-lead"
        self.assertEqual(strip_publication_trailer(body), body)

    def test_a_delivery_id_inside_the_body_is_not_stripped(self):
        body = "[andon]\ndelivery-id: delivery-abc failed to publish\n\n— team-lead"
        self.assertIn("failed to publish", strip_publication_trailer(body))

    def test_trailing_blank_lines_do_not_hide_the_trailer(self):
        body = published("[architecture-approval]\n\n— principal-architect") + "\n\n\n"
        self.assertEqual(strip_publication_trailer(body).splitlines()[-1], "— principal-architect")


class ApprovalSignerTest(unittest.TestCase):
    def signer(self, body: str):
        return dispatch_plan.approval_signer({"comments": [{"body": body}]}, 0)

    def test_published_approval_resolves_to_its_role_not_the_delivery_id(self):
        for role in ("team-lead", "principal-architect", "sceptical-architect", "security-reviewer"):
            with self.subTest(role=role):
                body = published(f"[approval]\nverdict: APPROVED\n\n— {role}")
                self.assertEqual(self.signer(body), role)

    def test_specialized_role_stating_its_protocol_mapping_resolves_to_itself(self):
        body = published("[security-approval]\n\n— senior-security-engineer (as security-reviewer)")
        self.assertEqual(self.signer(body), "senior-security-engineer")

    def test_unsigned_body_has_no_signer(self):
        self.assertIsNone(self.signer(published("[progress]\nstage: review")))


class ParseFilesEvidenceTest(unittest.TestCase):
    EXPECTED = {"README.md", "app/widget.py", "scripts/deploy.sh"}

    def test_canonical_comma_form(self):
        body = published("[review-request]\nFiles: README.md, app/widget.py, scripts/deploy.sh")
        self.assertEqual(parse_files_evidence(body), self.EXPECTED)

    def test_prose_labels_and_middot_separators_state_the_same_set(self):
        for line in (
            "Files approved (exact): README.md · app/widget.py · scripts/deploy.sh",
            "Approved files (verified set-equal to the diff): README.md · app/widget.py · scripts/deploy.sh",
            "Files: README.md app/widget.py scripts/deploy.sh",
        ):
            with self.subTest(line=line):
                self.assertEqual(parse_files_evidence(published(f"[x]\n{line}")), self.EXPECTED)

    def test_backticked_paths_are_unwrapped(self):
        body = "Files: `README.md`, `app/widget.py`, `scripts/deploy.sh`"
        self.assertEqual(parse_files_evidence(body), self.EXPECTED)

    def test_a_path_containing_a_space_survives_the_comma_form(self):
        body = "Files: docs/release notes.md, app/widget.py"
        self.assertEqual(parse_files_evidence(body), {"docs/release notes.md", "app/widget.py"})

    def test_absent_evidence_is_distinguishable_from_empty_evidence(self):
        # The two failures read differently to the author, so they must not
        # collapse: None = no line at all, empty set = a line declaring nothing.
        self.assertIsNone(parse_files_evidence("[architecture-approval]\nverdict: APPROVED"))
        self.assertEqual(parse_files_evidence("[architecture-approval]\nFiles:   "), set())

    def test_a_prose_sentence_beginning_with_files_is_not_evidence(self):
        # No colon terminating the label, so there is no declared set to read.
        self.assertIsNone(parse_files_evidence("Files changed in this round were reviewed"))

    def test_canonical_label_wins_over_surrounding_prose(self):
        # Widening the accepted labels must not change what an artifact that
        # already carries a canonical line means, wherever the prose sits.
        body = (
            "[team-lead-approval]\n"
            "Approved files (quoting the request): see the line below\n"
            "Files: README.md, app/widget.py, scripts/deploy.sh\n"
        )
        self.assertEqual(parse_files_evidence(body), self.EXPECTED)

    def test_wrong_set_is_still_a_wrong_set(self):
        # The parser is permissive about *form*; the caller's set-equality against
        # the reviewed diff is what actually binds, and this must not blur it.
        body = "Files approved (exact): README.md · app/wrong.py"
        self.assertNotEqual(parse_files_evidence(body), self.EXPECTED)


class ReviewPackageEmitsCopyableEvidenceTest(unittest.TestCase):
    def test_the_generated_line_parses_back_to_the_same_set(self):
        # review-package.sh prints `Files: a, b, c` for roles to copy verbatim;
        # whatever it emits must round-trip through the parser that gates merges.
        generated = "Files: " + ", ".join(sorted(ParseFilesEvidenceTest.EXPECTED))
        self.assertEqual(parse_files_evidence(generated), ParseFilesEvidenceTest.EXPECTED)


if __name__ == "__main__":
    unittest.main()
