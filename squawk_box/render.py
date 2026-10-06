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
        })
    return rows


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

    state_path.write_text(json.dumps(state, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    graph_path.write_text(json.dumps(state["graph"], indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    search_path.write_text(json.dumps(search_index, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

    _write_briefs(briefs, state)
    html_path.write_text(_render_html(state, timeline, search_index), encoding="utf-8")
    return {
        "state": state_path,
        "graph": graph_path,
        "search": search_path,
        "html": html_path,
        "briefs": briefs,
    }


def _write_briefs(root: Path, state: dict[str, Any]) -> None:
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


def _render_html(state: dict[str, Any], timeline: list[dict[str, Any]], search_index: list[dict[str, Any]]) -> str:
    data = {"state": state, "timeline": timeline, "search": search_index}
    css = r"""
:root{font-family:Inter,ui-sans-serif,system-ui,sans-serif;color:#e7e9ee;background:#111318;--panel:#191d24;--line:#303642;--muted:#9da7b6;--accent:#84b6ff;--bad:#ff8c8c;--warn:#ffd27a;--good:#8ce6ad}
*{box-sizing:border-box}body{margin:0;background:#111318;color:#e7e9ee}header{position:sticky;top:0;z-index:5;background:#151920;border-bottom:1px solid var(--line);padding:12px 18px}.brand{font-weight:750;font-size:18px}.meta{display:flex;gap:16px;flex-wrap:wrap;margin-top:6px;color:var(--muted);font-size:12px}.layout{display:grid;grid-template-columns:220px 1fr;min-height:calc(100vh - 62px)}nav{border-right:1px solid var(--line);padding:16px;position:sticky;top:62px;height:calc(100vh - 62px);overflow:auto}nav button{width:100%;text-align:left;padding:9px 10px;margin:2px 0;background:transparent;color:#dbe1ea;border:0;border-radius:7px;cursor:pointer}nav button:hover,nav button.active{background:#252b35}main{padding:20px;min-width:0}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px}.card,.entity,.event{background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:12px}.card .n{font-size:24px;font-weight:700}.muted{color:var(--muted)}.bad{color:var(--bad)}.warn{color:var(--warn)}.good{color:var(--good)}h1,h2,h3{margin-top:0}code{color:#cde0ff}.toolbar{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap}input,select{background:#11151c;border:1px solid var(--line);color:#e7e9ee;border-radius:7px;padding:8px}.list{display:grid;gap:8px}.kv{display:grid;grid-template-columns:minmax(130px,220px) 1fr;gap:6px 12px;font-size:13px}.kv>div:nth-child(odd){color:var(--muted)}a{color:var(--accent);text-decoration:none}.pill{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:2px 8px;font-size:11px;margin-right:5px}.rel{font-size:12px;padding:4px 0}.hidden{display:none!important}.quote{border-left:3px solid var(--warn);padding-left:10px;color:#d2d6de;white-space:pre-wrap}.notice{border:1px solid #5b4b2a;background:#251f15;padding:10px;border-radius:8px;margin-bottom:14px}.search-results{display:grid;gap:6px}.search-hit{padding:9px;border:1px solid var(--line);border-radius:7px;background:var(--panel);cursor:pointer}@media(max-width:800px){.layout{grid-template-columns:1fr}nav{position:static;height:auto;border-right:0;border-bottom:1px solid var(--line);display:flex;gap:4px;overflow:auto}nav button{width:auto;white-space:nowrap}}
"""
    js = r"""
const D=JSON.parse(document.getElementById('ledger-data').textContent);const S=D.state;
const groups={Tasks:'tasks',Artifacts:'artifacts',Decisions:'decisions',Claims:'claims',Failures:'failures',Authority:'authorityObservations',Agents:'agentRuns',Checkpoints:'checkpoints'};
const $=q=>document.querySelector(q);const el=(tag,cls,txt)=>{const n=document.createElement(tag);if(cls)n.className=cls;if(txt!==undefined)n.textContent=String(txt);return n};
function entityById(id){for(const [g,m] of Object.entries(S.entities)){if(m&&m[id])return [g,m[id]]}return null}
function link(id,label){const a=el('a','',label||id);a.href='#e-'+encodeURIComponent(id);return a}
function clear(){const m=$('#content');m.replaceChildren();return m}
function kv(obj, keys){const box=el('div','kv');for(const k of keys){box.append(el('div','',k));const v=el('div');const x=obj?.[k];v.textContent=typeof x==='object'?JSON.stringify(x):String(x??'');box.append(v)}return box}
function overview(){const m=clear();m.append(el('h1','', 'Build Overview'));const note=el('div','notice');note.textContent='Ledger state is derived history. A recorded PASS/APPROVED/AUTHORIZED string is not itself execution or permission.';m.append(note);const c=el('div','cards');const sum=S.summary;for(const [label,val,cls] of [['Active tasks',sum.activeTasks.length,''],['Unresolved failures',sum.unresolvedFailures.length,'bad'],['Stale claims',sum.staleClaims.length,'warn'],['Authority blockers',sum.authorityBlockers.length,'warn'],['Replay anomalies',S.anomalies.length,S.anomalies.length?'bad':'good']]){const x=el('div','card');x.append(el('div','muted',label));x.append(el('div','n '+cls,val));c.append(x)}m.append(c);m.append(el('h2','','Current scope'));m.append(kv({reducerVersion:S.reducerVersion,asOf:S.asOf,sourceCursor:S.sourceCursor,latestCheckpoint:sum.latestCheckpoint},['reducerVersion','asOf','sourceCursor','latestCheckpoint']));}
function timeline(){const m=clear();m.append(el('h1','', 'Timeline'));const list=el('div','list');for(const e of [...D.timeline].reverse()){const row=el('div','event');const top=el('div');top.append(link(e.eventId,e.kind+'@'+e.kindVersion));top.append(el('span','muted','  '+e.recordedAt+'  '+e.cursor.segment+':'+e.cursor.line));row.append(top);if(e.subject){const s=el('div','muted');s.append(document.createTextNode('subject '));s.append(link(e.subject.id,e.subject.type+':'+e.subject.id));row.append(s)}list.append(row)}m.append(list)}
function listGroup(title,g){const m=clear();m.append(el('h1','',title));const list=el('div','list');for(const [id,o] of Object.entries(S.entities[g]||{})){const row=el('div','entity');const h=el('h3');h.append(link(id,o.externalKey||o.logicalName||o.title||o.statement||id));row.append(h);row.append(kv(o,['status','supportState','freshness','currentState','currentVersionId','currentPath','failureDomain','source']));list.append(row)}m.append(list)}
function searchView(){const m=clear();m.append(el('h1','', 'Search'));const bar=el('div','toolbar');const input=el('input');input.placeholder='ID, path, hash, task key, text...';input.style.minWidth='320px';bar.append(input);m.append(bar);const out=el('div','search-results');m.append(out);function run(){out.replaceChildren();const q=input.value.trim().toLowerCase();if(!q)return;for(const hit of D.search.filter(x=>x.text.toLowerCase().includes(q)).slice(0,200)){const r=el('div','search-hit');r.append(link(hit.id,hit.id));r.append(el('span','muted','  '+hit.group+'  '+hit.text.slice(0,220)));out.append(r)}}input.addEventListener('input',run);input.focus()}
function entityView(id){const found=entityById(id);const m=clear();if(!found){m.append(el('h1','','Entity not found'));m.append(el('code','',id));return}const [group,o]=found;m.append(el('h1','',o.externalKey||o.logicalName||o.title||o.statement||id));m.append(el('div','muted',group+' | '+id));m.append(el('h2','','Current derived fields'));const pre=el('pre','quote');pre.textContent=JSON.stringify(o,null,2);m.append(pre);const inc=S.graph.incoming[id]||[],out=S.graph.outgoing[id]||[];m.append(el('h2','','Outgoing relationships'));for(const r of out){const x=el('div','rel');x.append(el('span','pill',r.rel));x.append(link(r.target.id,r.target.type+':'+r.target.id));m.append(x)}m.append(el('h2','','Incoming backreferences'));for(const r of inc){const x=el('div','rel');x.append(link(r.source.id,r.source.type+':'+r.source.id));x.append(el('span','pill',r.rel));m.append(x)}}
function route(){const hash=decodeURIComponent(location.hash||'');document.querySelectorAll('nav button').forEach(x=>x.classList.remove('active'));if(hash.startsWith('#e-'))return entityView(hash.slice(3));const name=hash.slice(1)||'Overview';const b=[...document.querySelectorAll('nav button')].find(x=>x.dataset.view===name);if(b)b.classList.add('active');if(name==='Overview')overview();else if(name==='Timeline')timeline();else if(name==='Search')searchView();else if(groups[name])listGroup(name,groups[name]);else overview()}
for(const b of document.querySelectorAll('nav button'))b.addEventListener('click',()=>{location.hash=b.dataset.view});window.addEventListener('hashchange',route);route();
"""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<title>Squawk Box Build Ledger</title><style>{css}</style></head>
<body><header><div class="brand">Squawk Box | Dynamic Build Ledger</div><div class="meta"><span>reducer {html.escape(state['reducerVersion'])}</span><span>asOf {html.escape(state['asOf'])}</span><span>source {html.escape(str(state['sourceCursor']))}</span></div></header>
<div class="layout"><nav>{''.join(f'<button data-view="{x}">{x}</button>' for x in ['Overview','Timeline','Tasks','Artifacts','Decisions','Claims','Failures','Authority','Agents','Checkpoints','Search'])}</nav><main id="content"></main></div>
<script id="ledger-data" type="application/json">{_script_json(data)}</script><script>{js}</script></body></html>"""
