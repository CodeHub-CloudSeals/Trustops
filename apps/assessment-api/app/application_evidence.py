"""Optional REA capture ingestion and a reviewer-gated LangGraph workflow.

Client REA captures and bounded server HTTP inspections use the same reviewed evidence workflow.
No shell, browser actions or LLM tools run in this workflow. Capture claims remain source-attributed.
"""
from __future__ import annotations

import copy
import hashlib
import html
import json
import time
from datetime import datetime
from typing import Literal, TypedDict
from urllib.parse import urlsplit, urlunsplit

from langgraph.checkpoint.base import BaseCheckpointSaver, CheckpointTuple
from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel, ConfigDict, Field, model_validator


class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid')


def safe_url(value: str) -> str:
    u = urlsplit(value)
    if u.scheme not in ('http', 'https') or not u.hostname or u.username or u.password:
        raise ValueError('Only HTTP(S) metadata URLs without credentials are accepted')
    return urlunsplit((u.scheme, u.netloc, u.path, '', ''))[:1000]


class Script(Strict):
    url: str = Field(max_length=1000)
    reported_hash: str | None = Field(default=None, max_length=150)


class Network(Strict):
    url: str = Field(max_length=1000)
    method: str = Field(pattern=r'^[A-Z]{1,16}$')
    status: int | None = Field(default=None, ge=100, le=599)


class PageMetadata(Strict):
    title: str = Field(max_length=300)
    http_status: int = Field(ge=100, le=599)
    content_type: str = Field(max_length=200)
    security_headers: dict[str, str] = Field(max_length=6)

    @model_validator(mode='after')
    def selected_headers(self):
        from .website_inspection import HEADERS
        if any(k not in HEADERS or len(v) > 1000 for k, v in self.security_headers.items()):
            raise ValueError('Only bounded selected response headers are accepted')
        return self


class Capture(Strict):
    schema_version: Literal['trustops.rea.capture.v1']
    producer: Literal['rea-agents', 'trustops-http-inspector']
    producer_version: str = Field(min_length=1, max_length=40)
    rea_evidence_id: str = Field(pattern=r'^ev_[a-f0-9]{64}$')
    source_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    target_url: str = Field(max_length=1000)
    started_at: datetime
    ended_at: datetime
    observation_ms: int = Field(ge=1, le=600_000)
    dom_nodes: int = Field(ge=0, le=1_000_000)
    scripts: list[Script] = Field(max_length=200)
    requests: list[Network] = Field(max_length=300)
    limitations: list[str] = Field(max_length=60)
    page: PageMetadata | None = None

    @model_validator(mode='after')
    def validate_scope(self):
        if self.producer == 'trustops-http-inspector' and self.page is None:
            raise ValueError('HTTP inspection requires page metadata')
        self.target_url = safe_url(self.target_url)
        for entry in [*self.scripts, *self.requests]:
            entry.url = safe_url(entry.url)
        if not self.started_at.tzinfo or not self.ended_at.tzinfo or self.ended_at < self.started_at:
            raise ValueError('A valid timezone-aware observation window is required')
        if self.ended_at.timestamp() > time.time() + 300 or (self.ended_at - self.started_at).total_seconds() > 610:
            raise ValueError('Invalid capture time window')
        if any(len(s) > 1000 for s in self.limitations):
            raise ValueError('Limitation too long')
        return self


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False).encode()).hexdigest()


class SnapshotSaver(BaseCheckpointSaver):
    """JSON-only checkpoints inside the existing durable single-writer inventory snapshot.

    The checkpoint object is generated on the server, never accepted from an API payload.
    No pickle/msgpack deserialization. The API's Store lock serializes graph operations.
    """
    def __init__(self, storage):
        super().__init__()
        self.storage = storage

    def get_tuple(self, config):
        records = self.storage.get('records', {})
        cid = config['configurable'].get('checkpoint_id') or self.storage.get('latest')
        r = records.get(cid)
        if not r:
            return None
        return CheckpointTuple(config=r['config'], checkpoint=copy.deepcopy(r['checkpoint']), metadata=r['metadata'],
                               parent_config=r['parent'], pending_writes=[tuple(w) for w in r['writes']])

    def put(self, config, checkpoint, metadata, new_versions):
        cfg = {'configurable': {'thread_id': config['configurable']['thread_id'], 'checkpoint_ns': '', 'checkpoint_id': checkpoint['id']}}
        rec = {'config': cfg, 'checkpoint': checkpoint, 'metadata': metadata, 'parent': None, 'writes': []}
        # Fail closed if a future framework version introduces non-JSON state.
        rec = json.loads(json.dumps(rec, allow_nan=False))
        self.storage.setdefault('records', {})[checkpoint['id']] = rec
        self.storage['latest'] = checkpoint['id']
        return cfg

    def put_writes(self, config, writes, task_id, task_path=''):
        record = self.storage['records'][config['configurable']['checkpoint_id']]
        for channel, value in writes:
            # Errors are diagnostics, not deserializable exception objects.
            if isinstance(value, BaseException):
                value = type(value).__name__
            record['writes'].append(json.loads(json.dumps([task_id, channel, value], allow_nan=False)))


class State(TypedDict, total=False):
    capture: dict
    observations: list
    findings: list
    missing_information: list
    limitations: list
    status: str
    decision: str
    report: dict


BASE_LIMITATIONS = [
    'Observations are reported by the supplied client-side REA capture; collector identity is not cryptographically attested.',
    'Network coverage is limited to the observation window. Earlier or unexercised activity is unknown.',
    'Request/response bodies, cookies, tokens, storage contents and script source text are excluded by this connector.',
    'Browser metadata does not establish backend permissions, data retention, encryption at rest, model safety or compliance.',
]


def build_graph(storage):
    def validate(state):
        c = Capture.model_validate(state['capture']).model_dump(mode='json')
        return {'capture': c, 'status': 'analysing'}

    def observe(state):
        c = state['capture']
        observations = [
            {'id': 'OBS-1', 'kind': 'capture_fact', 'text': f"REA capture reports {c['dom_nodes']} DOM nodes.", 'source': 'capture.dom_nodes'},
            {'id': 'OBS-2', 'kind': 'capture_fact', 'text': f"{len(c['scripts'])} script metadata records retained.", 'source': 'capture.scripts'},
            {'id': 'OBS-3', 'kind': 'capture_fact', 'text': f"{len(c['requests'])} network requests retained during the capture window.",
             'source': 'capture.requests'},
        ]
        if c['producer'] == 'trustops-http-inspector':
            observations[0]['text'] = f"HTTP response HTML contains {c['dom_nodes']} parsed elements."
            page = c['page']
            observations.extend([
                {'id': 'OBS-4', 'kind': 'capture_fact', 'text': f"Page title: {page['title'] or '(no title in returned HTML)'}",
                 'source': 'capture.page.title'},
                {'id': 'OBS-5', 'kind': 'capture_fact', 'text': f"Final page returned HTTP {page['http_status']}.", 'source': 'capture.page.http_status'},
                {'id': 'OBS-6', 'kind': 'capture_fact',
                 'text': f"{len(page['security_headers'])} selected security response headers present; effectiveness needs review.",
                 'source': 'capture.page.security_headers'},
            ])
        failed = [i for i, r in enumerate(c['requests']) if r['status'] is not None and r['status'] >= 400]
        findings = []
        if failed:
            findings.append({'id': 'TECH-1', 'severity': 'medium', 'type': 'observed_failure', 'title': 'HTTP failures recorded',
                             'detail': f'{len(failed)} captured request(s) returned HTTP 4xx/5xx; operational impact needs review.',
                             'evidence_refs': [f'capture.requests[{i}]' for i in failed],
                             'recommendation': 'Inspect the corresponding server logs and repeat the affected user journey.'})
        missing = [
            {'id': 'REQ-1', 'title': 'Backend access controls', 'reason': 'Not verifiable from browser metadata.',
             'action': 'Provide service identity, role configuration and an authorization test record.'},
            {'id': 'REQ-2', 'title': 'Data handling and retention', 'reason': 'Bodies and server storage were outside this capture.',
             'action': 'Provide the data-flow diagram, retention configuration and encryption settings.'},
            {'id': 'REQ-3', 'title': 'AI model and human oversight',
             'reason': 'A browser capture does not prove that a model ran or that review controls exist.',
             'action': 'Provide model configuration, execution logs and reviewer/approval evidence where applicable.'},
        ]
        base = BASE_LIMITATIONS if c['producer'] == 'rea-agents' else [
            'Capture metadata is source-attributed; importing a JSON file does not attest collector identity.',
            'HTTP observations cannot establish backend permissions, data retention, model safety or compliance.',
        ]
        return {'observations': observations, 'findings': findings, 'missing_information': missing,
                'limitations': list(dict.fromkeys(base + c['limitations'])), 'status': 'awaiting_review'}

    def review(state):
        if state.get('decision') not in ('validated', 'rejected'):
            raise ValueError('An explicit reviewer decision is required')
        return {'status': 'reviewed' if state['decision'] == 'validated' else 'rejected'}

    def draft(state):
        return {'status': 'reviewed_draft', 'report': {k: state[k] for k in ('capture', 'observations', 'findings', 'missing_information', 'limitations')}}

    graph = StateGraph(State)
    for name, fn in [('validate_capture', validate), ('analyse_metadata', observe), ('human_review', review), ('report_draft', draft)]:
        graph.add_node(name, fn)
    graph.add_edge(START, 'validate_capture')
    graph.add_edge('validate_capture', 'analyse_metadata')
    graph.add_edge('analyse_metadata', 'human_review')
    graph.add_conditional_edges('human_review', lambda s: 'report_draft' if s['status'] == 'reviewed' else END)
    graph.add_edge('report_draft', END)
    return graph.compile(checkpointer=SnapshotSaver(storage), interrupt_before=['human_review'])


def execute(run, review=None):
    graph = build_graph(run.setdefault('checkpoints', {}))
    config = {'configurable': {'thread_id': run['run_id']}}
    if review:
        graph.update_state(config, {'decision': review}, as_node='analyse_metadata')
        value = None
    else:
        value = {'capture': run['capture']}
    for update in graph.stream(value, config, stream_mode='updates'):
        for name in update:
            if not name.startswith('__'):
                run.setdefault('events', []).append({'step': name, 'at': time.time(), 'status': 'completed'})
    run['state'] = dict(graph.get_state(config).values)
    run['status'] = run['state']['status']
    # This bounded workflow resumes only its latest state; don't duplicate captures in an unbounded history.
    latest = run['checkpoints']['latest']
    run['checkpoints']['records'] = {latest: run['checkpoints']['records'][latest]}
    return run


def source_digest(run):
    return digest({'evidence_sha256': run['evidence_sha256'], 'state': run['state']})


def view(run, staff=False):
    out = {k: copy.deepcopy(run[k]) for k in ('run_id', 'evidence_id', 'evidence_sha256', 'status', 'capture', 'events', 'engine')}
    out.update({k: copy.deepcopy(run['state'].get(k, [])) for k in ('observations', 'findings', 'missing_information', 'limitations')})
    out['source_digest'] = source_digest(run)
    out['published'] = [{k: v for k, v in r.items() if k not in ('html', 'review_reason', 'published_by')} for r in run.get('releases', [])]
    if staff:
        out['review'] = run.get('review')
    return out


def render_report(run, system_name, version):
    e = lambda value: html.escape(str(value), quote=True)
    s, c = run['state'], run['capture']
    collector = 'Public-page HTTP inspection' if c['producer'] == 'trustops-http-inspector' else 'REA browser capture'
    rows = ''.join(f"<tr><td>{e(r['method'])}</td><td>{e(r['url'])}</td><td>{e(r['status'] if r['status'] else 'Unknown')}</td></tr>" for r in c['requests'])
    scripts = ''.join(f"<li>{e(r['url'])} <small>{e(r['reported_hash'] or 'Producer hash unavailable')}</small></li>" for r in c['scripts'])
    observed = ''.join(f"<li>{e(o['text'])} <small>Source: {e(o['source'])}</small></li>" for o in s['observations'])
    findings = ''.join(f"<article><h3>{e(f['title'])}</h3><p>{e(f['detail'])}</p>"
                       f"<p>Evidence: {e(', '.join(f['evidence_refs']))}</p><p>Action: {e(f['recommendation'])}</p></article>" for f in s['findings'])
    requests = ''.join(f"<article><h3>{e(m['title'])}</h3><p>{e(m['reason'])}</p>"
                       f"<p>Next action: {e(m['action'])}</p></article>" for m in s['missing_information'])
    no_failures = '<p>No HTTP failures were recorded in the retained requests. This does not establish application health or security.</p>'
    limits = ''.join(f'<li>{e(x)}</li>' for x in s['limitations'])
    return f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Application evidence report — {e(system_name)}</title><style>body{{font:16px system-ui;color:#143d46;background:#eef5f6;margin:0}}
main{{max-width:1000px;margin:32px auto;background:white;padding:42px;border-radius:18px}}
h1{{font-size:36px}}
h2{{border-top:1px solid #d5e5e7;padding-top:24px}}
small{{display:block;color:#526e75;overflow-wrap:anywhere}}
table{{width:100%;border-collapse:collapse}}
td,th{{text-align:left;padding:10px;border-bottom:1px solid #dae6e8;overflow-wrap:anywhere}}
article{{padding:12px 18px;background:#f4f8f9;margin:12px 0}}
.badge{{color:#007c83;font-weight:bold}}
@media print{{body{{background:white}}
main{{margin:0;padding:12px}}
}}
</style>
<main><p class="badge">CLOUDSEALS TRUSTOPS · REVIEWED APPLICATION EVIDENCE · VERSION {version}</p><h1>{e(system_name)}</h1>
<p>Technical observations, scope limits and evidence requests. Reviewed for publication; not a security certification or compliance determination.</p>
<p>Target: {e(c['target_url'])}<br>Capture window: {e(c['started_at'])} → {e(c['ended_at'])}<br>Source: {e(collector)} {e(c['producer_version'])}</p>
<small>Capture evidence: {e(c['rea_evidence_id'])}<br>
Attached-file SHA-256: {e(run['evidence_sha256'])}<br>Reviewed source digest: {e(source_digest(run))}</small>
<h2>What was observed</h2><ul>{observed}</ul><h3>Scripts</h3><ul>{scripts or '<li>No script metadata retained; absence is not proof of no scripts.</li>'}</ul>
<h3>Network observations</h3>
<table><thead><tr><th>Method</th><th>URL (queries excluded)</th><th>HTTP status</th></tr></thead>
<tbody>{rows or '<tr><td colspan="3">No requests retained in this window.</td></tr>'}</tbody></table>
<h2>Findings requiring attention</h2>{findings or no_failures}
<h2>Missing information & recommended actions</h2>{requests}<h2>What could not be verified</h2><ul>{limits}</ul></main></html>'''


class ImportRequest(Strict):
    evidence_id: str = Field(min_length=1, max_length=100)


class WebsiteInspectionRequest(Strict):
    url: str = Field(min_length=1, max_length=1000)
    authorized: Literal[True]


class ReviewRequest(Strict):
    decision: Literal['validated', 'rejected']
    reason: str = Field(min_length=1, max_length=2000)
    source_digest: str = Field(pattern=r'^[a-f0-9]{64}$')


class PublishRequest(Strict):
    source_digest: str = Field(pattern=r'^[a-f0-9]{64}$')
    reason: str = Field(min_length=1, max_length=2000)


def register_routes(app, ctx):
    from fastapi import Depends, Response

    def runs(aid):
        return ctx._inv(aid).setdefault('technical_runs', {})

    def find(p, aid, rid):
        ctx.get_assessment(p, aid)
        run = runs(aid).get(rid)
        if not run:
            raise ctx.err(404, 'not_found', 'Application evidence workflow not found')
        return run

    def clean_source(run, aid):
        ev = ctx.STORE.evidence.get(run['evidence_id'])
        if not ev or ev['assessment_id'] != aid or ev['state'] != 'clean' or ev['sha256'] != run['evidence_sha256']:
            raise ctx.err(409, 'source_unavailable', 'The original clean evidence is required')
        try:
            raw = ctx.OBJECTS.get(ev['tenant_id'], 'evidence', ev['evidence_id'])
        except Exception:
            raise ctx.err(503, 'evidence_unavailable', 'The original evidence could not be read; retry before reviewing or publishing') from None
        if hashlib.sha256(raw).hexdigest() != ev['sha256']:
            raise ctx.err(409, 'source_changed', 'The attached source bytes changed')

    @app.get('/v1/assessments/{aid}/application-evidence')
    def list_runs(aid: str, p=Depends(ctx.principal)):
        ctx.get_assessment(p, aid)
        with ctx.STORE.lock:
            return {'items': [view(r, p.is_staff) for r in runs(aid).values()], 'collector': 'optional_client_side_rea',
                    'capture_schema': 'trustops.rea.capture.v1'}

    @app.post('/v1/assessments/{aid}/website-inspection')
    def inspect_url(aid: str, body: WebsiteInspectionRequest, p=Depends(ctx.principal)):
        from .website_inspection import InspectionError, inspect_website
        ctx.get_assessment(p, aid)
        ctx.require(p, 'customer_admin', 'customer_architect', 'cloudseals_admin', 'cloudseals_assessor', 'cloudseals_reviewer')
        ctx.agent_throttle(p, 'website-inspection')
        with ctx.STORE.lock:
            if len(runs(aid)) >= 30:
                raise ctx.err(409, 'capture_limit', 'At most 30 application captures may be attached to an assessment')
        try:
            capture = Capture.model_validate(inspect_website(body.url)).model_dump(mode='json')
        except InspectionError as exc:
            raise ctx.err(422, 'website_inspection_failed', str(exc)) from None
        ctx.audit(p, 'website.inspected', aid)
        return {'capture': capture, 'next_step': 'Upload this capture through evidence safety checks before attaching it for review.'}

    @app.post('/v1/assessments/{aid}/application-evidence', status_code=201)
    def import_capture(aid: str, body: ImportRequest, p=Depends(ctx.principal)):
        a = ctx.get_assessment(p, aid)
        ctx.require(p, 'customer_admin', 'customer_architect', 'cloudseals_admin', 'cloudseals_assessor', 'cloudseals_reviewer')
        with ctx.STORE.lock:
            ev = ctx.STORE.evidence.get(body.evidence_id)
            if not ev or ev['assessment_id'] != aid or ev['state'] != 'clean' or ev['content_type'] != 'application/json':
                raise ctx.err(422, 'clean_capture_required', 'Upload a clean REA capture JSON for this assessment first')
            try:
                raw = ctx.OBJECTS.get(a['tenant_id'], 'evidence', body.evidence_id)
            except Exception:
                raise ctx.err(503, 'evidence_unavailable', 'The evidence store could not return this capture; retry later') from None
            if len(raw) > 1_000_000 or hashlib.sha256(raw).hexdigest() != ev['sha256']:
                raise ctx.err(422, 'invalid_capture', 'The capture size or evidence digest is invalid')
            try:
                capture = Capture.model_validate_json(raw).model_dump(mode='json')
            except ValueError:
                raise ctx.err(422, 'invalid_capture', 'Capture must match trustops.rea.capture.v1; no analysis was saved') from None
            for old in runs(aid).values():
                if old['evidence_sha256'] == ev['sha256']:
                    return view(old, p.is_staff)
            if len(runs(aid)) >= 30:
                raise ctx.err(409, 'capture_limit', 'At most 30 application captures may be attached to an assessment')
            run = {'run_id': ctx.uuid.uuid4().hex, 'evidence_id': body.evidence_id, 'evidence_sha256': ev['sha256'],
                   'capture': capture, 'engine': 'langgraph', 'events': [], 'releases': []}
            execute(run)
            runs(aid)[run['run_id']] = run
            ctx.audit(p, 'application_evidence.imported', f"{aid}/{run['run_id']}")
            return view(run, p.is_staff)

    @app.post('/v1/assessments/{aid}/application-evidence/{rid}/review')
    def review_capture(aid: str, rid: str, body: ReviewRequest, p=Depends(ctx.principal)):
        ctx.require(p, 'cloudseals_reviewer')
        with ctx.STORE.lock:
            run = find(p, aid, rid)
            if source_digest(run) != body.source_digest:
                raise ctx.err(409, 'source_changed', 'Reload the evidence before reviewing it')
            if run['status'] != 'awaiting_review':
                raise ctx.err(409, 'review_completed', 'This capture already has a review decision; import a new capture for another version')
            clean_source(run, aid)
            # Work on a copy: a graph error never leaves a partly reviewed saved assessment.
            fresh = copy.deepcopy(run)
            execute(fresh, body.decision)
            fresh['review'] = {'reviewed_by': p.sub, 'reason': body.reason, 'reviewed_at': time.time()}
            runs(aid)[rid] = fresh
            ctx.audit(p, f'application_evidence.{body.decision}', f'{aid}/{rid}')
            return view(fresh, True)

    @app.post('/v1/assessments/{aid}/application-evidence/{rid}/publish')
    def publish_capture(aid: str, rid: str, body: PublishRequest, p=Depends(ctx.principal)):
        ctx.require(p, 'cloudseals_reviewer')
        with ctx.STORE.lock:
            run = find(p, aid, rid)
            if source_digest(run) != body.source_digest:
                raise ctx.err(409, 'source_changed', 'The preview changed; reload before publication')
            if run['status'] != 'reviewed_draft' or not run.get('review'):
                raise ctx.err(409, 'review_required', 'A reviewer must validate this capture before publication')
            clean_source(run, aid)
            if not run['releases']:
                doc = render_report(run, ctx.STORE.assessments[aid]['ai_system_name'], 1)
                run['releases'].append({'report_id': ctx.uuid.uuid4().hex, 'version': 1, 'published_at': time.time(),
                                        'source_digest': source_digest(run), 'content_digest': hashlib.sha256(doc.encode()).hexdigest(),
                                        'html': doc, 'published_by': p.sub, 'review_reason': body.reason})
                ctx.audit(p, 'application_evidence.published', f'{aid}/{rid}')
            return view(run, True)

    @app.get('/v1/assessments/{aid}/application-evidence/{rid}/report')
    def download_report(aid: str, rid: str, preview: bool = False, p=Depends(ctx.principal)):
        with ctx.STORE.lock:
            run = find(p, aid, rid)
            if preview:
                ctx.require(p, 'cloudseals_reviewer', 'cloudseals_admin', 'cloudseals_assessor')
                if run['status'] != 'reviewed_draft':
                    raise ctx.err(409, 'review_required', 'Validate the evidence before generating its report preview')
                doc = render_report(run, ctx.STORE.assessments[aid]['ai_system_name'], 1)
                doc = doc.replace('REVIEWED APPLICATION EVIDENCE', 'UNPUBLISHED PREVIEW · REVIEWED APPLICATION EVIDENCE')
                status = 'draft'
            else:
                if not run['releases']:
                    raise ctx.err(403, 'report_not_published', 'The application evidence report has not been published')
                doc, status = run['releases'][-1]['html'], 'published'
            return Response(doc, media_type='text/html', headers={'Content-Disposition': f'attachment; filename="application-evidence-{rid}.html"',
                            'X-Report-Status': status, 'X-Content-Digest': hashlib.sha256(doc.encode()).hexdigest()})
