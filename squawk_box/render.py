from __future__ import annotations

from pathlib import Path
from typing import Any
import html
import json

from .ledger import LedgerStore
from .model import canonical_json


def _script_json(value: Any) -> str:
    # Safe inside <script type="application/json">: no raw '<' can terminate the tag.
    return canonical_json(value).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def build_search_index(state: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for group, entities in state["entities"].items():
        if not isinstance(entities, dict):
            continue
        for entity_id, entity in entities.items():
            if not isinstance(entity, dict):
                continue
            bits = [entity_id, group]
            for key in ("externalKey", "title", "statement", "logicalName", "currentPath", "status", "supportState", "freshness", "failureDomain", "source"):
                value = entity.get(key)
                if isinstance(value, str):
                    bits.append(value)
            rows.append({"id": entity_id, "group": group, "text": " ".join(bits)[:4096]})
    return rows


def _timeline_summary(event: dict[str, Any]) -> str:
    payload = event.get("payload", {})
    kind = event.get("kind")
    if kind == "task.status_changed":
        return f"task status → {payload.get('status', '')}"
    if kind == "attempt.started":
        changed = ", ".join(payload.get("changedDimensions", [])) or "none"
        return f"attempt {payload.get('ordinal', '?')} started; changed dimensions: {changed}"
    if kind == "attempt.completed":
        result = payload.get("result", {})
        details = []
        for key in ("semanticCompilation", "materialization"):
            if result.get(key) is not None:
                details.append(f"{key}={result[key]}")
        suffix = f"; {'; '.join(details)}" if details else ""
        return f"attempt outcome → {payload.get('outcome', '')}{suffix}"
    if kind == "failure.recorded":
        return f"{payload.get('failureDomain', 'UNKNOWN')} failure: {payload.get('symptom', '')}"
    if kind == "failure.status_changed":
        resolution = payload.get("resolution")
        return f"failure status → {payload.get('status', '')}" + (f"; {resolution}" if resolution else "")
    if kind == "artifact.version_observed":
        digest = payload.get("byteDigest", {}).get("value", "")
        digest_text = f" sha256 {digest[:12]}…" if digest else ""
        return f"{payload.get('size', '?')} bytes{digest_text}"
    if kind == "artifact.registered":
        return f"artifact registered: {payload.get('logicalName', '')}"
    if kind == "task.created":
        return f"task created: {payload.get('externalKey', '')}"
    return ""


def _timeline(store: LedgerStore) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for event, cursor in store.iter_parseable_events(include_corrupt=False):
        rows.append({
            "eventId": event.get("eventId"),
            "kind": event.get("kind"),
            "kindVersion": event.get("kindVersion"),
            "recordedAt": event.get("recordedAt"),
            "reportedBy": event.get("reportedBy"),
            "subject": event.get("subject"),
            "cursor": cursor.to_dict(),
            "summary": _timeline_summary(event),
        })
    return rows


def build_story_index(state: dict[str, Any]) -> list[dict[str, Any]]:
    """Derive compact task stories without changing canonical history."""
    entities = state["entities"]
    tasks = entities["tasks"]
    attempts = entities["attempts"]
    failures = entities["failures"]
    artifacts = entities["artifacts"]
    versions = entities["artifactVersions"]
    stories: list[dict[str, Any]] = []

    for task_id, task in tasks.items():
        attempt_ids = [x for x in task.get("attemptIds", []) if x in attempts]
        ordered_attempts = sorted(
            (attempts[x] for x in attempt_ids),
            key=lambda a: (a.get("ordinal", 0), a.get("startedAt", ""), a["id"]),
        )
        story: dict[str, Any] = {
            "taskId": task_id,
            "externalKey": task.get("externalKey", ""),
            "title": task.get("title", task.get("externalKey", task_id)),
            "objective": task.get("objective", ""),
            "status": task.get("status", ""),
            "steps": [],
        }
        story["steps"].append({
            "kind": "task",
            "entityId": task_id,
            "title": "Task",
            "facts": [
                {"label": "Status", "value": task.get("status", ""), "provenance": "derived"},
                {"label": "Objective", "value": task.get("objective", ""), "provenance": "recorded"},
            ],
        })

        for attempt in ordered_attempts:
            attempt_id = attempt["id"]
            result = attempt.get("result", {}) if isinstance(attempt.get("result"), dict) else {}
            facts = [
                {"label": "Outcome", "value": attempt.get("status", ""), "provenance": "derived"},
                {"label": "Ordinal", "value": attempt.get("ordinal"), "provenance": "recorded"},
            ]
            if attempt.get("retryOf"):
                facts.append({"label": "Retry of", "value": attempt["retryOf"], "ref": attempt["retryOf"], "provenance": "recorded"})
            changed = attempt.get("changedDimensions", [])
            if changed:
                facts.append({"label": "Changed dimensions", "value": ", ".join(changed), "provenance": "recorded"})
            for key, label in (("semanticCompilation", "Semantic compilation"), ("materialization", "Materialization")):
                if result.get(key) is not None:
                    facts.append({"label": label, "value": result[key], "provenance": "recorded result"})

            continuity = attempt.get("continuity", {})
            if isinstance(continuity, dict):
                derived = continuity.get("derived", {})
                if isinstance(derived, dict):
                    for key, value in derived.items():
                        facts.append({
                            "label": f"Continuity · {key}",
                            "value": value,
                            "provenance": "derived/recorded comparison",
                        })
                asserted = continuity.get("asserted", {})
                if isinstance(asserted, dict):
                    for key, assertion in asserted.items():
                        if not isinstance(assertion, dict):
                            continue
                        asserted_by = assertion.get("assertedBy", "unknown")
                        basis = assertion.get("basisRefs", [])
                        provenance = f"asserted by {asserted_by}"
                        if basis:
                            provenance += f"; basis: {', '.join(str(x) for x in basis)}"
                        facts.append({
                            "label": f"Continuity · {key}",
                            "value": assertion.get("value"),
                            "provenance": provenance,
                        })

            story["steps"].append({
                "kind": "attempt",
                "entityId": attempt_id,
                "title": f"Attempt {attempt.get('ordinal', '?')}",
                "facts": facts,
            })

            related_failures = [
                failure for failure in failures.values()
                if failure.get("attemptId") == attempt_id
            ]
            for failure in sorted(related_failures, key=lambda x: x["id"]):
                failure_facts = [
                    {"label": "Domain", "value": failure.get("failureDomain", "UNKNOWN"), "provenance": "recorded"},
                    {"label": "Status", "value": failure.get("status", ""), "provenance": "derived"},
                    {"label": "Symptom", "value": failure.get("symptom", ""), "provenance": "recorded"},
                ]
                if failure.get("rootCause"):
                    failure_facts.append({"label": "Root cause", "value": failure["rootCause"], "provenance": "recorded"})
                if failure.get("survivedRefs"):
                    failure_facts.append({"label": "Survived", "value": ", ".join(str(x) for x in failure["survivedRefs"]), "provenance": "recorded"})
                if failure.get("invalidatedRefs"):
                    failure_facts.append({"label": "Invalidated", "value": ", ".join(str(x) for x in failure["invalidatedRefs"]), "provenance": "recorded"})
                if failure.get("resolution"):
                    failure_facts.append({"label": "Resolution", "value": failure["resolution"], "provenance": "recorded"})
                story["steps"].append({
                    "kind": "failure",
                    "entityId": failure["id"],
                    "title": f"Failure · {failure.get('failureDomain', 'UNKNOWN')}",
                    "facts": failure_facts,
                })

            related_versions = [
                version for version in versions.values()
                if version.get("createdByAttempt") == attempt_id
            ]
            for version in sorted(related_versions, key=lambda x: x["id"]):
                artifact = artifacts.get(version.get("artifactId"), {})
                digest = version.get("byteDigest", {}).get("value", "")
                story["steps"].append({
                    "kind": "artifactVersion",
                    "entityId": version["id"],
                    "title": f"Artifact · {artifact.get('logicalName', version['id'])}",
                    "facts": [
                        {"label": "Path", "value": version.get("pathAtObservation", ""), "provenance": "observed"},
                        {"label": "Size", "value": f"{version.get('size', 0):,} bytes", "provenance": "observed"},
                        {"label": "SHA-256", "value": digest, "provenance": "observed byte identity"},
                        {"label": "Persistence", "value": version.get("persistenceClass", ""), "provenance": "recorded"},
                    ],
                })

        story["steps"].append({
            "kind": "task-final",
            "entityId": task_id,
            "title": "Current task state",
            "facts": [
                {"label": "Status", "value": task.get("status", ""), "provenance": "derived"},
                {"label": "Attempt count", "value": len(ordered_attempts), "provenance": "derived"},
            ],
        })
        stories.append(story)

    return sorted(stories, key=lambda x: (x.get("externalKey", ""), x["taskId"]))


def write_projections(store: LedgerStore, *, as_of: str | None = None) -> dict[str, Path]:
    state = store.replay(as_of=as_of)
    out = store.generated_dir
    briefs = out / "briefs"
    out.mkdir(parents=True, exist_ok=True)
    briefs.mkdir(parents=True, exist_ok=True)

    state_path = out / "current-state.json"
    graph_path = out / "graph-index.json"
    search_path = out / "search-index.json"
    html_path = out / "ledger.html"
    timeline = _timeline(store)
    search_index = build_search_index(state)
    stories = build_story_index(state)
    stories_path = out / "build-stories.json"

    state_path.write_text(json.dumps(state, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    graph_path.write_text(json.dumps(state["graph"], indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    search_path.write_text(json.dumps(search_index, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    stories_path.write_text(json.dumps(stories, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

    _write_briefs(briefs, state, stories)
    html_path.write_text(_render_html(state, timeline, search_index, stories), encoding="utf-8")
    return {
        "state": state_path,
        "graph": graph_path,
        "search": search_path,
        "stories": stories_path,
        "html": html_path,
        "briefs": briefs,
    }


def _write_briefs(root: Path, state: dict[str, Any], stories: list[dict[str, Any]]) -> None:
    summary = state["summary"]
    tasks = state["entities"]["tasks"]
    decisions = state["entities"]["decisions"]
    failures = state["entities"]["failures"]
    authorities = state["entities"]["authorityObservations"]
    artifacts = state["entities"]["artifacts"]
    claims = state["entities"]["claims"]

    active_decisions = [d for d in decisions.values() if d.get("status") in {"ACCEPTED", "EXPERIMENTAL"}]
    unresolved_failures = [failures[x] for x in summary["unresolvedFailures"] if x in failures]
    stale_claims = [claims[x] for x in summary["staleClaims"] if x in claims]
    active_tasks = [tasks[x] for x in summary["activeTasks"] if x in tasks]

    current = [
        "# Current Build Brief",
        "",
        f"Reducer: `{state['reducerVersion']}`  ",
        f"As of: `{state['asOf']}`  ",
        f"Source cursor: `{state['sourceCursor']}`",
        "",
        "## Directives",
        "",
        "No directive is synthesized by the reducer. Only human/DonSquad-authored handoff records may supply directive text.",
        "",
        "## Derived state",
        "",
        f"- Active tasks: {len(active_tasks)}",
        f"- Unresolved failures: {len(unresolved_failures)}",
        f"- Stale claims: {len(stale_claims)}",
        f"- Authority blockers: {len(summary['authorityBlockers'])}",
        f"- Latest checkpoint: `{summary['latestCheckpoint']}`",
        "",
        "### Active tasks",
    ]
    current.extend(f"- `{t['id']}` `{t.get('externalKey','')}` - {t.get('status')} - {t.get('title','')}" for t in active_tasks)
    current.extend(["", "### Active decisions"])
    current.extend(f"- `{d['id']}` - {d.get('status')} - {d.get('title', d.get('statement',''))}" for d in active_decisions)
    current.extend(["", "### Unresolved failures"])
    current.extend(f"- `{f['id']}` - {f.get('failureDomain','UNKNOWN')} - {f.get('symptom','')}" for f in unresolved_failures)
    current.extend(["", "### Claims needing revalidation"])
    current.extend(f"- `{c['id']}` - {c.get('statement','')}" for c in stale_claims)
    (root / "current-build.md").write_text("\n".join(current) + "\n", encoding="utf-8")

    (root / "active-decisions.md").write_text(
        "# Active Decisions\n\n" + "\n".join(f"- `{d['id']}` {d.get('title', d.get('statement',''))}" for d in active_decisions) + "\n",
        encoding="utf-8",
    )
    (root / "open-blockers.md").write_text(
        "# Open Blockers\n\n" + "\n".join(f"- `{f['id']}` {f.get('symptom','')}" for f in unresolved_failures) + "\n",
        encoding="utf-8",
    )
    (root / "authority-status.md").write_text(
        "# Authority Status\n\n" + "\n".join(
            f"- `{a['id']}` observed={a.get('observedState')} current={a.get('currentState')} scope={a.get('scope','')} source={a.get('source','')}"
            for a in authorities.values()
        ) + "\n",
        encoding="utf-8",
    )
    (root / "artifact-manifest.md").write_text(
        "# Artifact Manifest\n\n" + "\n".join(
            f"- `{a['id']}` {a.get('logicalName','')} currentVersion=`{a.get('currentVersionId')}` path=`{a.get('currentPath')}`"
            for a in artifacts.values()
        ) + "\n",
        encoding="utf-8",
    )

    handoffs = state["records"]["handoffs"]
    directive_handoffs = [h for h in handoffs if h.get("reportedBy", {}).get("type") in {"human", "donsquad"}]
    latest = directive_handoffs[-1] if directive_handoffs else None
    next_text = ["# Next Owner Handoff", ""]
    if latest:
        next_text.extend([
            f"Authored by: `{latest['reportedBy']['type']}:{latest['reportedBy']['id']}`",
            "",
            "## Directive",
            "",
            str(latest.get("payload", {}).get("directive", "No directive text recorded.")),
        ])
    else:
        next_text.append("No human/DonSquad-authored handoff directive is recorded.")
    (root / "next-owner-handoff.md").write_text("\n".join(next_text) + "\n", encoding="utf-8")

    story_lines = [
        "# Build Stories",
        "",
        "> Derived navigation projection. History and evidence remain canonical in the event ledger.",
        "",
    ]
    for story in stories:
        story_lines.extend([
            f"## {story.get('externalKey') or story['taskId']} — {story.get('title', '')}",
            "",
            f"- Task: `{story['taskId']}`",
            f"- Status: **{story.get('status', '')}**",
            f"- Objective: {story.get('objective', '')}",
            "",
        ])
        for index, step in enumerate(story.get("steps", []), 1):
            story_lines.append(f"### {index}. {step.get('title', step.get('kind', 'Step'))}")
            if step.get("entityId"):
                story_lines.append(f"- Entity: `{step['entityId']}`")
            for fact in step.get("facts", []):
                value = fact.get("value")
                if value is None or value == "":
                    continue
                provenance = fact.get("provenance", "")
                suffix = f" _[{provenance}]_" if provenance else ""
                story_lines.append(f"- **{fact.get('label', 'Fact')}**: {value}{suffix}")
            story_lines.append("")
    (root / "build-stories.md").write_text("\n".join(story_lines) + "\n", encoding="utf-8")


def _render_html(
    state: dict[str, Any],
    timeline: list[dict[str, Any]],
    search_index: list[dict[str, Any]],
    stories: list[dict[str, Any]],
) -> str:
    data = {"state": state, "timeline": timeline, "search": search_index, "stories": stories}
    css = r"""
:root{font-family:Inter,ui-sans-serif,system-ui,sans-serif;color:#e7e9ee;background:#111318;--panel:#191d24;--line:#303642;--muted:#9da7b6;--accent:#84b6ff;--bad:#ff8c8c;--warn:#ffd27a;--good:#8ce6ad}
*{box-sizing:border-box}body{margin:0;background:#111318;color:#e7e9ee}header{position:sticky;top:0;z-index:5;background:#151920;border-bottom:1px solid var(--line);padding:12px 18px}.brand{font-weight:750;font-size:18px}.meta{display:flex;gap:16px;flex-wrap:wrap;margin-top:6px;color:var(--muted);font-size:12px}.layout{display:grid;grid-template-columns:230px 1fr;min-height:calc(100vh - 62px)}nav{border-right:1px solid var(--line);padding:16px;position:sticky;top:62px;height:calc(100vh - 62px);overflow:auto}nav button{width:100%;text-align:left;padding:9px 10px;margin:2px 0;background:transparent;color:#dbe1ea;border:0;border-radius:7px;cursor:pointer}nav button:hover,nav button.active{background:#252b35}main{padding:20px;min-width:0}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px}.card,.entity,.event,.story{background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:12px}.card .n{font-size:24px;font-weight:700}.muted{color:var(--muted)}.bad{color:var(--bad)}.warn{color:var(--warn)}.good{color:var(--good)}h1,h2,h3,h4{margin-top:0}code{color:#cde0ff}.toolbar{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap}input,select{background:#11151c;border:1px solid var(--line);color:#e7e9ee;border-radius:7px;padding:8px}.list{display:grid;gap:8px}dl.fields{display:grid;grid-template-columns:minmax(150px,230px) minmax(0,1fr);gap:0;border-top:1px solid var(--line);margin:10px 0 0}dl.fields dt,dl.fields dd{margin:0;padding:8px 0;border-bottom:1px solid var(--line)}dl.fields dt{color:var(--muted);padding-right:14px}dl.fields dd{overflow-wrap:anywhere}.provenance{display:block;color:var(--muted);font-size:11px;margin-top:2px}.pill{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:2px 8px;font-size:11px;margin-right:5px}.rel{font-size:12px;padding:4px 0}.quote{border-left:3px solid var(--warn);padding-left:10px;color:#d2d6de;white-space:pre-wrap}.notice{border:1px solid #5b4b2a;background:#251f15;padding:10px;border-radius:8px;margin-bottom:14px}.search-results{display:grid;gap:6px}.search-hit{padding:9px;border:1px solid var(--line);border-radius:7px;background:var(--panel);cursor:pointer}.story ol{display:grid;gap:10px;padding-left:26px}.story li{padding-left:4px}.story-step{border-left:3px solid #34465f;padding:10px 12px;background:#141922;border-radius:0 8px 8px 0}.relationships{margin-top:18px}details{margin-top:14px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#10141a;border:1px solid var(--line);padding:10px;border-radius:7px}@media(max-width:800px){.layout{grid-template-columns:1fr}nav{position:static;height:auto;border-right:0;border-bottom:1px solid var(--line);display:flex;gap:4px;overflow:auto}nav button{width:auto;white-space:nowrap}dl.fields{grid-template-columns:1fr}dl.fields dt{border-bottom:0;padding-bottom:2px}dl.fields dd{padding-top:2px}}
"""
    js = r"""
const D=JSON.parse(document.getElementById('ledger-data').textContent);const S=D.state;
const groups={Tasks:'tasks',Attempts:'attempts',Artifacts:'artifacts',Decisions:'decisions',Claims:'claims',Failures:'failures',Authority:'authorityObservations',Agents:'agentRuns',Checkpoints:'checkpoints'};
const $=q=>document.querySelector(q);const el=(tag,cls,txt)=>{const n=document.createElement(tag);if(cls)n.className=cls;if(txt!==undefined)n.textContent=String(txt);return n};
function entityById(id){for(const [g,m] of Object.entries(S.entities)){if(m&&m[id])return [g,m[id]]}return null}
function link(id,label){const a=el('a','',label||id);a.href='#e-'+encodeURIComponent(id);return a}
function clear(){const m=$('#content');m.replaceChildren();return m}
function present(v){return !(v===undefined||v===null||v===''||(Array.isArray(v)&&v.length===0))}
function valueText(v){if(Array.isArray(v))return v.join(', ');if(typeof v==='boolean')return v?'YES':'NO';if(typeof v==='object')return JSON.stringify(v);return String(v)}
function fieldList(entries){const dl=el('dl','fields');for(const entry of entries){if(!present(entry.value))continue;const dt=el('dt','',entry.label+': ');const dd=el('dd');if(entry.ref){dd.append(link(entry.ref,entry.display||valueText(entry.value)))}else{dd.append(document.createTextNode(valueText(entry.value)))}if(entry.provenance)dd.append(el('small','provenance',' ['+entry.provenance+']'));dl.append(dt,dd)}return dl}
function typedFields(group,o){
  if(group==='tasks')return [
    {label:'Status',value:o.status},{label:'Objective',value:o.objective},{label:'Owner role',value:o.ownerRole},
    {label:'Parent task',value:o.parentTask,ref:o.parentTask},{label:'Attempts',value:(o.attemptIds||[]).length},
    {label:'Blockers',value:o.blockers},{label:'Scope',value:o.scope},{label:'Constraints',value:o.constraints}
  ];
  if(group==='attempts'){const r=o.result||{};return [
    {label:'Outcome',value:o.status},{label:'Task',value:o.taskId,ref:o.taskId},{label:'Ordinal',value:o.ordinal},
    {label:'Retry of',value:o.retryOf,ref:o.retryOf},{label:'Changed dimensions',value:o.changedDimensions},
    {label:'Semantic compilation',value:r.semanticCompilation},{label:'Materialization',value:r.materialization},
    {label:'Started',value:o.startedAt},{label:'Ended',value:o.endedAt}
  ]}
  if(group==='artifacts')return [
    {label:'Type',value:o.artifactType},{label:'Lifecycle',value:o.lifecycleState},{label:'Presence',value:o.presence},
    {label:'Current version',value:o.currentVersionId,ref:o.currentVersionId},{label:'Current path',value:o.currentPath},
    {label:'Version count',value:(o.versionIds||[]).length}
  ];
  if(group==='artifactVersions'){const d=o.byteDigest||{};return [
    {label:'Artifact',value:o.artifactId,ref:o.artifactId},{label:'Path',value:o.pathAtObservation},
    {label:'Size',value:present(o.size)?Number(o.size).toLocaleString()+' bytes':''},{label:'SHA-256',value:d.value},
    {label:'Digest type',value:d.digestType},{label:'Persistence',value:o.persistenceClass},
    {label:'Created by attempt',value:o.createdByAttempt,ref:o.createdByAttempt}
  ]}
  if(group==='failures')return [
    {label:'Status',value:o.status},{label:'Failure domain',value:o.failureDomain},{label:'Symptom',value:o.symptom},
    {label:'Root cause state',value:o.rootCauseState},{label:'Root cause',value:o.rootCause},
    {label:'Task',value:o.taskId,ref:o.taskId},{label:'Attempt',value:o.attemptId,ref:o.attemptId},
    {label:'Survived',value:o.survivedRefs},{label:'Invalidated',value:o.invalidatedRefs},{label:'Resolution',value:o.resolution}
  ];
  if(group==='decisions')return [
    {label:'Status',value:o.status},{label:'Statement',value:o.statement},{label:'Rationale',value:o.rationale},
    {label:'Supporting evidence changed',value:o.supportingEvidenceChanged}
  ];
  if(group==='claims')return [
    {label:'Support',value:o.supportState},{label:'Freshness',value:o.freshness},{label:'Statement',value:o.statement},
    {label:'Last validation',value:o.lastValidation},{label:'Evidence bindings',value:o.evidenceBindings}
  ];
  if(group==='authorityObservations')return [
    {label:'Observed state',value:o.observedState},{label:'Current state',value:o.currentState},
    {label:'Scope',value:o.scope},{label:'Source',value:o.source},{label:'Expires',value:o.expiresAt}
  ];
  if(group==='agentRuns')return [
    {label:'Status',value:o.status},{label:'Role',value:o.role},{label:'Model',value:o.modelIdentity},
    {label:'Session',value:o.sessionId,ref:o.sessionId},{label:'Started',value:o.startedAt},{label:'Ended',value:o.endedAt}
  ];
  if(group==='checkpoints')return [
    {label:'Name',value:o.name},{label:'Recorded',value:o.recordedAt},{label:'Next action',value:o.nextRecommendedAction}
  ];
  return Object.entries(o).filter(([k])=>!['lastEventId','lastCursor'].includes(k)).map(([k,v])=>({label:k,value:v}));
}
function overview(){const m=clear();m.append(el('h1','', 'Build Overview'));const note=el('div','notice');note.textContent='Ledger state is derived history. A recorded PASS/APPROVED/AUTHORIZED string is not itself execution or permission.';m.append(note);const c=el('div','cards');const sum=S.summary;for(const [label,val,cls] of [['Active tasks',sum.activeTasks.length,''],['Unresolved failures',sum.unresolvedFailures.length,'bad'],['Stale claims',sum.staleClaims.length,'warn'],['Authority blockers',sum.authorityBlockers.length,'warn'],['Replay anomalies',S.anomalies.length,S.anomalies.length?'bad':'good']]){const x=el('div','card');x.append(el('div','muted',label));x.append(el('div','n '+cls,val));c.append(x)}m.append(c);m.append(el('h2','','Current scope'));m.append(fieldList([{label:'Reducer version',value:S.reducerVersion},{label:'As of',value:S.asOf},{label:'Source cursor',value:S.sourceCursor},{label:'Latest checkpoint',value:sum.latestCheckpoint}]));}
function timeline(){const m=clear();m.append(el('h1','', 'Timeline'));const list=el('div','list');for(const e of [...D.timeline].reverse()){const row=el('article','event');const h=el('h3');h.append(link(e.eventId,e.kind+'@'+e.kindVersion));row.append(h);row.append(fieldList([{label:'Recorded',value:e.recordedAt},{label:'Cursor',value:e.cursor.segment+':'+e.cursor.line},{label:'Subject',value:e.subject?.id,ref:e.subject?.id,display:e.subject?e.subject.type+':'+e.subject.id:''},{label:'Change',value:e.summary}]));list.append(row)}m.append(list)}
function entityTitle(o,id){return o.externalKey||o.logicalName||o.title||o.statement||id}
function listGroup(title,g){const m=clear();m.append(el('h1','',title));const list=el('div','list');for(const [id,o] of Object.entries(S.entities[g]||{})){const row=el('article','entity');const h=el('h3');h.append(link(id,entityTitle(o,id)));row.append(h);row.append(fieldList(typedFields(g,o)));list.append(row)}m.append(list)}
function storyView(){const m=clear();m.append(el('h1','', 'Build Story'));const note=el('div','notice');note.textContent='Derived navigation projection. Recorded facts retain provenance labels; canonical history remains the event ledger.';m.append(note);if(!D.stories.length){m.append(el('p','muted','No task stories are available.'));return}for(const story of D.stories){const article=el('article','story');const h=el('h2');h.append(link(story.taskId,(story.externalKey||story.taskId)+' — '+story.title));article.append(h);article.append(fieldList([{label:'Status',value:story.status},{label:'Objective',value:story.objective},{label:'Task',value:story.taskId,ref:story.taskId}]));const ol=el('ol');for(const step of story.steps){const li=el('li');const box=el('section','story-step');const sh=el('h3');if(step.entityId){sh.append(link(step.entityId,step.title||step.kind))}else{sh.textContent=step.title||step.kind}box.append(sh);box.append(fieldList((step.facts||[]).map(f=>({label:f.label,value:f.value,ref:f.ref,provenance:f.provenance}))));li.append(box);ol.append(li)}article.append(ol);m.append(article)}}
function searchView(){const m=clear();m.append(el('h1','', 'Search'));const bar=el('div','toolbar');const input=el('input');input.placeholder='ID, path, hash, task key, text...';input.style.minWidth='320px';bar.append(input);m.append(bar);const out=el('div','search-results');m.append(out);function run(){out.replaceChildren();const q=input.value.trim().toLowerCase();if(!q)return;for(const hit of D.search.filter(x=>x.text.toLowerCase().includes(q)).slice(0,200)){const r=el('div','search-hit');r.append(link(hit.id,hit.id));r.append(el('span','muted','  '+hit.group+'  '+hit.text.slice(0,220)));out.append(r)}}input.addEventListener('input',run);input.focus()}
function relatedSection(m,title,ids){const presentIds=(ids||[]).filter(Boolean);if(!presentIds.length)return;m.append(el('h2','',title));const list=el('div','list');for(const id of presentIds){const found=entityById(id);const row=el('div','entity');row.append(link(id,found?entityTitle(found[1],id):id));list.append(row)}m.append(list)}
function entityView(id){const found=entityById(id);const m=clear();if(!found){m.append(el('h1','','Entity not found'));m.append(el('code','',id));return}const [group,o]=found;m.append(el('h1','',entityTitle(o,id)));m.append(el('div','muted',group+' | '+id));m.append(fieldList(typedFields(group,o)));if(group==='tasks')relatedSection(m,'Attempts',o.attemptIds);if(group==='artifacts')relatedSection(m,'Artifact versions',o.versionIds);if(group==='attempts'){const fs=Object.values(S.entities.failures||{}).filter(x=>x.attemptId===id).map(x=>x.id);const av=Object.values(S.entities.artifactVersions||{}).filter(x=>x.createdByAttempt===id).map(x=>x.id);relatedSection(m,'Failures',fs);relatedSection(m,'Produced artifact versions',av)}const inc=S.graph.incoming[id]||[],out=S.graph.outgoing[id]||[];const rels=el('section','relationships');rels.append(el('h2','','Outgoing relationships'));for(const r of out){const x=el('div','rel');x.append(el('span','pill',r.rel));x.append(link(r.target.id,r.target.type+':'+r.target.id));rels.append(x)}rels.append(el('h2','','Incoming backreferences'));for(const r of inc){const x=el('div','rel');x.append(link(r.source.id,r.source.type+':'+r.source.id));x.append(el('span','pill',r.rel));rels.append(x)}m.append(rels);const details=el('details');details.append(el('summary','','Raw derived entity'));const pre=el('pre','quote');pre.textContent=JSON.stringify(o,null,2);details.append(pre);m.append(details)}
function route(){const hash=decodeURIComponent(location.hash||'');document.querySelectorAll('nav button').forEach(x=>x.classList.remove('active'));if(hash.startsWith('#e-'))return entityView(hash.slice(3));const name=hash.slice(1)||'Overview';const b=[...document.querySelectorAll('nav button')].find(x=>x.dataset.view===name);if(b)b.classList.add('active');if(name==='Overview')overview();else if(name==='Timeline')timeline();else if(name==='Build Story')storyView();else if(name==='Search')searchView();else if(groups[name])listGroup(name,groups[name]);else overview()}
for(const b of document.querySelectorAll('nav button'))b.addEventListener('click',()=>{location.hash=b.dataset.view});window.addEventListener('hashchange',route);route();
"""
    nav_items = ['Overview','Build Story','Timeline','Tasks','Attempts','Artifacts','Decisions','Claims','Failures','Authority','Agents','Checkpoints','Search']
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<title>Squawk Box Build Ledger</title><style>{css}</style></head>
<body><header><div class="brand">Squawk Box | Dynamic Build Ledger</div><div class="meta"><span>reducer {html.escape(state['reducerVersion'])}</span><span>asOf {html.escape(state['asOf'])}</span><span>source {html.escape(str(state['sourceCursor']))}</span></div></header>
<div class="layout"><nav aria-label="Ledger views">{''.join(f'<button data-view="{x}">{x}</button>' for x in nav_items)}</nav><main id="content" aria-live="polite"></main></div>
<script id="ledger-data" type="application/json">{_script_json(data)}</script><script>{js}</script></body></html>"""
