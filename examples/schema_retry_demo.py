"""Build a small ledger demonstrating semantic continuity across a transport-only retry."""
from pathlib import Path
import shutil

from squawk_box.ledger import LedgerStore
from squawk_box.model import new_id
from squawk_box.render import write_projections

root = Path(".demo-ledger")
if root.exists():
    shutil.rmtree(root)
store = LedgerStore(root)
store.initialize(build_id="operational-schema-demo")
seq = 0

def submit(body, reporter_type="manager", reporter_id="manager"):
    global seq
    seq += 1
    return store.submit(reporter_type=reporter_type, reporter_id=reporter_id, submission_id=f"demo-{seq}", body=body)

task = new_id("task")
a2 = new_id("attempt")
a3 = new_id("attempt")
failure = new_id("failure")
artifact = new_id("artifact")
version = new_id("artifactVersion")

submit({"kind":"task.created","kindVersion":1,"subject":{"type":"task","id":task},"payload":{"externalKey":"chunk-08.1e","title":"Operational schema materialization","objective":"Create exact frozen schema bytes"}}, "human", "user")
submit({"kind":"task.status_changed","kindVersion":1,"subject":{"type":"task","id":task},"payload":{"status":"READY"}}, "human", "user")
submit({"kind":"task.status_changed","kindVersion":1,"subject":{"type":"task","id":task},"payload":{"status":"ACTIVE"}}, "human", "user")
submit({"kind":"attempt.started","kindVersion":1,"subject":{"type":"attempt","id":a2},"payload":{"taskId":task,"ordinal":2,"changedDimensions":[],"continuity":{"asserted":{"sameSemanticDesign":{"value":True,"assertedBy":"run_demo","basisRefs":["frozen-design"]}}}}})
submit({"kind":"failure.recorded","kindVersion":1,"subject":{"type":"failure","id":failure},"relations":[{"rel":"affects","target":{"type":"attempt","id":a2}}],"payload":{"taskId":task,"attemptId":a2,"failureDomain":"TRANSPORT","symptom":"72,492-byte schema exceeded 50KB emission guard","rootCauseState":"KNOWN","rootCause":"transport guard","survivedRefs":["118-definition-tree","sha256:ecfd2f2a"],"status":"OPEN"}})
submit({"kind":"attempt.completed","kindVersion":1,"subject":{"type":"attempt","id":a2},"payload":{"outcome":"FAILED_RETRYABLE","result":{"semanticCompilation":"COMPLETE","materialization":"INCOMPLETE"}}})
submit({"kind":"task.status_changed","kindVersion":1,"subject":{"type":"task","id":task},"payload":{"status":"NEEDS_RETRY"}}, "human", "user")
submit({"kind":"task.status_changed","kindVersion":1,"subject":{"type":"task","id":task},"payload":{"status":"ACTIVE"}}, "human", "user")
submit({"kind":"attempt.started","kindVersion":1,"subject":{"type":"attempt","id":a3},"relations":[{"rel":"retries","target":{"type":"attempt","id":a2}}],"payload":{"taskId":task,"ordinal":3,"retryOf":a2,"changedDimensions":["TRANSPORT"],"continuity":{"derived":{"sameTask":True,"sameAgentRun":True,"sameSession":True,"sameInputs":True,"sameDesignRefs":True},"asserted":{"sameSemanticDesign":{"value":True,"assertedBy":"run_demo","basisRefs":["frozen-design"]}}}}})
submit({"kind":"artifact.registered","kindVersion":1,"subject":{"type":"artifact","id":artifact},"payload":{"logicalName":"operational schema","artifactType":"json-schema","path":"docs/governance/startup-verification.schema.operational.v1.2.json"}})
submit({"kind":"artifact.version_observed","kindVersion":1,"subject":{"type":"artifactVersion","id":version},"relations":[{"rel":"produced_by","target":{"type":"attempt","id":a3}}],"payload":{"artifactId":artifact,"pathAtObservation":"docs/governance/startup-verification.schema.operational.v1.2.json","size":72492,"byteDigest":{"digestType":"artifact_bytes","algorithm":"sha256","value":"ecfd2f2a8c49bec6283de60fbc747e606d815c150c546f9d9907e4a9c74fdd97"},"persistenceClass":"DURABLE","createdByAttempt":a3}})
submit({"kind":"failure.status_changed","kindVersion":1,"subject":{"type":"failure","id":failure},"payload":{"status":"RESOLVED","resolution":"bounded chunk transport"}})
submit({"kind":"attempt.completed","kindVersion":1,"subject":{"type":"attempt","id":a3},"payload":{"outcome":"SUCCEEDED","result":{"semanticCompilation":"UNCHANGED","materialization":"COMPLETE"}}})
submit({"kind":"task.status_changed","kindVersion":1,"subject":{"type":"task","id":task},"payload":{"status":"COMPLETE"}}, "human", "user")

paths = write_projections(store, as_of="2026-10-06T12:00:00Z")
print(paths["html"])
