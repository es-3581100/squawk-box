from __future__ import annotations

from pathlib import Path
import json
import tempfile
import unittest

from squawk_box.errors import IntakeRejected, ReplayBlocked
from squawk_box.ledger import LedgerStore
from squawk_box.model import Cursor, new_id
from squawk_box.render import write_projections


AS_OF = "2026-10-06T12:00:00Z"


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "ledger"
        self.store = LedgerStore(self.root)
        self.store.initialize(build_id="test-build")
        self.n = 0

    def tearDown(self):
        self.tmp.cleanup()

    def submit(self, body, reporter_type="manager", reporter_id="mgr"):
        self.n += 1
        return self.store.submit(
            reporter_type=reporter_type,
            reporter_id=reporter_id,
            submission_id=f"sub-{self.n}",
            body=body,
        )

    def create_task(self, external="chunk-1"):
        task = new_id("task")
        self.submit({
            "kind": "task.created",
            "kindVersion": 1,
            "subject": {"type": "task", "id": task},
            "payload": {"externalKey": external, "title": "Task One", "objective": "prove history"},
        }, reporter_type="human", reporter_id="user")
        return task

    def test_idempotent_submission_and_conflict(self):
        task = new_id("task")
        body = {
            "kind": "task.created", "kindVersion": 1,
            "subject": {"type": "task", "id": task},
            "payload": {"externalKey": "chunk-x"},
        }
        first = self.store.submit(reporter_type="human", reporter_id="user", submission_id="same", body=body)
        second = self.store.submit(reporter_type="human", reporter_id="user", submission_id="same", body=body)
        self.assertEqual(first["eventId"], second["eventId"])
        changed = json.loads(json.dumps(body))
        changed["payload"]["externalKey"] = "different"
        with self.assertRaisesRegex(IntakeRejected, "SUBMISSION_ID_REUSE_CONFLICT"):
            self.store.submit(reporter_type="human", reporter_id="user", submission_id="same", body=changed)

    def test_manager_owned_reporter_fields_rejected(self):
        task = new_id("task")
        with self.assertRaises(IntakeRejected):
            self.store.submit(
                reporter_type="human", reporter_id="actual", submission_id="s1",
                body={
                    "kind": "task.created", "kindVersion": 1,
                    "reportedBy": {"type": "human", "id": "forged"},
                    "subject": {"type": "task", "id": task}, "payload": {"externalKey": "x"},
                },
            )

    def test_reporter_capability_matrix(self):
        task = new_id("task")
        with self.assertRaises(IntakeRejected):
            self.store.submit(
                reporter_type="agentRun", reporter_id=new_id("agentRun"), submission_id="s1",
                body={"kind": "task.created", "kindVersion": 1, "subject": {"type": "task", "id": task}, "payload": {"externalKey": "x"}},
            )

    def test_task_attempt_history_and_semantic_anomaly(self):
        task = self.create_task()
        attempt = new_id("attempt")
        self.submit({
            "kind": "attempt.started", "kindVersion": 1,
            "subject": {"type": "attempt", "id": attempt},
            "payload": {"taskId": task, "ordinal": 1, "changedDimensions": []},
        })
        self.submit({
            "kind": "attempt.completed", "kindVersion": 1,
            "subject": {"type": "attempt", "id": attempt},
            "payload": {"outcome": "FAILED_RETRYABLE", "result": {"reason": "transport"}},
        })
        # Legal at intake, illegal at reduction: reducer preserves anomaly and indeterminate subject.
        self.submit({
            "kind": "task.status_changed", "kindVersion": 1,
            "subject": {"type": "task", "id": task},
            "payload": {"status": "COMPLETE"},
        }, reporter_type="human", reporter_id="user")
        state = self.store.replay(as_of=AS_OF)
        self.assertEqual(state["entities"]["attempts"][attempt]["status"], "FAILED_RETRYABLE")
        self.assertIn(task, state["indeterminateSubjects"])
        self.assertEqual(state["entities"]["tasks"][task]["status"], "PLANNED")

    def test_artifact_version_change_stales_claim(self):
        artifact = new_id("artifact")
        v1, v2, claim = new_id("artifactVersion"), new_id("artifactVersion"), new_id("claim")
        self.submit({"kind":"artifact.registered","kindVersion":1,"subject":{"type":"artifact","id":artifact},"payload":{"logicalName":"schema","path":"docs/schema.json"}})
        self.submit({"kind":"artifact.version_observed","kindVersion":1,"subject":{"type":"artifactVersion","id":v1},"payload":{"artifactId":artifact,"pathAtObservation":"docs/schema.json","size":1,"byteDigest":{"digestType":"artifact_bytes","algorithm":"sha256","value":"a"*64},"persistenceClass":"DURABLE"}})
        self.submit({"kind":"claim.asserted","kindVersion":1,"subject":{"type":"claim","id":claim},"payload":{"statement":"schema is reviewed","evidenceBindings":[v1]}})
        self.submit({"kind":"claim.assessed","kindVersion":1,"subject":{"type":"claim","id":claim},"payload":{"supportState":"SUPPORTED"}})
        self.submit({"kind":"artifact.version_observed","kindVersion":1,"subject":{"type":"artifactVersion","id":v2},"payload":{"artifactId":artifact,"pathAtObservation":"docs/schema.json","size":2,"byteDigest":{"digestType":"artifact_bytes","algorithm":"sha256","value":"b"*64},"persistenceClass":"DURABLE"}})
        state = self.store.replay(as_of=AS_OF)
        self.assertEqual(state["entities"]["claims"][claim]["supportState"], "SUPPORTED")
        self.assertEqual(state["entities"]["claims"][claim]["freshness"], "STALE")
        self.assertEqual(state["entities"]["artifacts"][artifact]["currentVersionId"], v2)

    def test_authority_expiration_depends_on_as_of(self):
        auth = new_id("authorityObservation")
        self.submit({
            "kind":"authority.observed","kindVersion":1,
            "subject":{"type":"authorityObservation","id":auth},
            "payload":{"source":"human_message","scope":"deploy/**","state":"AUTHORIZED","expiresAt":"2026-10-06T11:00:00Z"},
        })
        before = self.store.replay(as_of="2026-10-06T10:00:00Z")
        after = self.store.replay(as_of="2026-10-06T12:00:00Z")
        self.assertEqual(before["entities"]["authorityObservations"][auth]["currentState"], "AUTHORIZED")
        self.assertEqual(after["entities"]["authorityObservations"][auth]["currentState"], "EXPIRED")

    def test_corrupt_complete_record_blocks_until_repair_overlay(self):
        task = self.create_task()
        segment = self.root / "events" / "000001.jsonl"
        with segment.open("ab") as f:
            f.write(b'{"this":"is broken" nope}\n')
        with self.assertRaises(ReplayBlocked):
            self.store.replay(as_of=AS_OF)
        line_no = len(segment.read_bytes().splitlines())
        repair = self.store.record_repair(
            action="QUARANTINE", cursor=Cursor(1, line_no), event_id=None,
            reason="fixture corruption", authorized_by="test-human",
        )
        state = self.store.replay(as_of=AS_OF)
        self.assertIn(task, state["entities"]["tasks"])
        self.assertEqual(state["repairs"]["activeQuarantines"], 1)
        self.store.record_repair(
            action="REVOKE_QUARANTINE", cursor=None, event_id=None,
            reason="prove revoke blocks again", authorized_by="test-human", target_repair_id=repair["repairId"],
        )
        with self.assertRaises(ReplayBlocked):
            self.store.replay(as_of=AS_OF)

    def test_torn_tail_is_not_an_event(self):
        self.create_task()
        segment = self.root / "events" / "000001.jsonl"
        with segment.open("ab") as f:
            f.write(b'{"partial"')
        state = self.store.replay(as_of=AS_OF)
        self.assertTrue(any(w["type"] == "TORN_TAIL_IGNORED" for w in state["warnings"]))

    def test_payload_content_addressing_and_purge(self):
        ref = self.store.put_payload(b"secret-value", media_type="text/plain")
        digest = ref["digest"]["value"]
        path = self.root / ref["locator"]
        self.assertTrue(path.exists())
        self.store.purge_payload(digest, reason="secret", secret_class="token", authorized_by="human", submission_id="purge-1")
        self.assertFalse(path.exists())
        state = self.store.replay(as_of=AS_OF)
        self.assertEqual(len(state["records"]["payloadPurges"]), 1)

    def test_self_contained_html_escapes_untrusted_script_text(self):
        claim = new_id("claim")
        evil = "</script><script>alert('x')</script>"
        self.submit({"kind":"claim.asserted","kindVersion":1,"subject":{"type":"claim","id":claim},"payload":{"statement":evil}})
        paths = write_projections(self.store, as_of=AS_OF)
        data = paths["html"].read_text(encoding="utf-8")
        self.assertNotIn(evil, data)
        self.assertIn("\\u003c/script", data)
        self.assertIn("Content-Security-Policy", data)

    def test_replay_is_deterministic_for_same_as_of(self):
        self.create_task()
        one = self.store.replay(as_of=AS_OF)
        two = self.store.replay(as_of=AS_OF)
        self.assertEqual(one, two)

    def test_valid_event_correction_changes_effect_not_history(self):
        task = new_id("task")
        original = self.store.submit(
            reporter_type="human", reporter_id="user", submission_id="orig",
            body={
                "kind":"task.created","kindVersion":1,
                "subject":{"type":"task","id":task},
                "payload":{"externalKey":"chunk-correct","title":"Wrong title"},
            },
        )
        self.store.submit(
            reporter_type="manager", reporter_id="mgr", submission_id="correction",
            body={
                "kind":"event.correction_recorded","kindVersion":1,
                "subject":{"type":"event","id":original["eventId"]},
                "payload":{
                    "targetEventId":original["eventId"],
                    "replacement":{
                        "kind":"task.created","kindVersion":1,
                        "subject":{"type":"task","id":task},
                        "payload":{"externalKey":"chunk-correct","title":"Correct title"}
                    }
                },
            },
        )
        state = self.store.replay(as_of=AS_OF)
        self.assertEqual(state["entities"]["tasks"][task]["title"], "Correct title")
        raw = [e for e,_ in self.store.iter_parseable_events(include_corrupt=False) if e["eventId"] == original["eventId"]][0]
        self.assertEqual(raw["payload"]["title"], "Wrong title")

    def test_duplicate_event_id_blocks_replay(self):
        task = self.create_task()
        segment = self.root / "events" / "000001.jsonl"
        first = segment.read_bytes().splitlines(keepends=True)[0]
        with segment.open("ab") as f:
            f.write(first)
        with self.assertRaisesRegex(ReplayBlocked, "duplicate eventId"):
            self.store.replay(as_of=AS_OF)
        self.assertTrue(task)

    def test_unauthorized_repair_overlay_blocks_replay(self):
        self.create_task()
        bad = {
            "schemaVersion":"donsquad-ledger/repair-v1",
            "repairId":"rpr_" + "a"*32,
            "action":"QUARANTINE",
            "cursor":{"segment":1,"line":1},
            "reason":"not actually human-authorized",
            "authorizedBy":{"type":"agentRun","ref":"run_bad"},
            "authorizedAt":"2026-10-06T00:00:00Z"
        }
        with (self.root / "repairs.jsonl").open("ab") as f:
            f.write((json.dumps(bad,separators=(",",":")) + "\n").encode())
        with self.assertRaisesRegex(ReplayBlocked, "lacks human authorization"):
            self.store.replay(as_of=AS_OF)

    def test_event_size_is_bounded_without_truncation(self):
        claim = new_id("claim")
        with self.assertRaisesRegex(IntakeRejected, "EVENT_TOO_LARGE"):
            self.store.submit(
                reporter_type="agentRun", reporter_id=new_id("agentRun"), submission_id="huge",
                body={
                    "kind":"claim.asserted","kindVersion":1,
                    "subject":{"type":"claim","id":claim},
                    "payload":{"statement":"x" * (70 * 1024)},
                },
            )
        self.assertEqual(list(self.store.iter_parseable_events(include_corrupt=False)), [])

    def test_event_registry_schema_matches_runtime_capabilities(self):
        from squawk_box.model import KIND_REPORTERS
        registry = json.loads((Path(__file__).parents[1] / "schemas" / "event-kinds-v1.json").read_text())
        expected = {f"{kind}@{version}": sorted(reporters) for (kind,version),reporters in KIND_REPORTERS.items()}
        actual = {key: sorted(value) for key,value in registry["kinds"].items()}
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
