"""Server-owned output shapes. Schema-constrained decoding supplements, never replaces, grounding/policy validators."""
from __future__ import annotations


def obj(properties):
    return {'type': 'object', 'properties': properties, 'required': list(properties), 'additionalProperties': False}


def array(items, limit=40, minimum=0):
    return {'type': 'array', 'items': items, 'maxItems': limit, 'minItems': minimum}


def text(limit=1500):
    return {'type': 'string', 'minLength': 1, 'maxLength': limit}


def enum(values):
    return {'type': 'string', 'enum': list(values)} if values else {'type': 'string'}


def complete(client, system, user, max_tokens, schema):
    method = getattr(client, 'complete_json', None)
    return method(system, user, max_tokens=max_tokens, schema=schema) if callable(method) else client.complete(system, user, max_tokens=max_tokens)


READY = obj({'ok': {'type': 'boolean', 'const': True}})
NULL_TEXT = {'type': ['string', 'null']}
INVENTORY = obj({'use_cases': array(obj({
    'name': text(200), 'description': text(), 'business_owner': NULL_TEXT, 'technical_owner': NULL_TEXT,
    'model_type': NULL_TEXT, 'foundation_models_used': array(text(200), 20),
    'decision_authority': {'enum': ['autonomous', 'human_in_loop', 'advisory', None]},
    'data_sources': array(text(200), 20), 'risk_tier': enum(['prohibited', 'high_risk', 'limited_risk', 'minimal_risk']),
    'risk_tier_rationale': text(), 'extraction_confidence': {'type': 'number', 'minimum': 0, 'maximum': 1},
    'source_quotes': array(text(1500), 5, 1),
}))})


def gaps(requirements, case_ids):
    return obj({'findings': array(obj({
        'framework_clause': enum(sorted(requirements)), 'finding_title': text(80), 'finding_description': text(),
        'severity': enum(['critical', 'high', 'medium', 'low', 'info']), 'recommendation_summary': text(),
        'estimated_effort_days': {'type': 'integer', 'minimum': 0, 'maximum': 365},
        'suggested_timeline': enum(['0-90', '90-180', '180-365']),
        'evidence_use_case_ids': array(enum(sorted(case_ids)), 40, 1), 'evidence_quotes': array(text(), 5),
    }), 60)})


def maturity(principles, ids):
    return obj({'scores': obj({p: {'type': 'number', 'minimum': 1, 'maximum': 5} for p in principles}),
                'rationale': obj({p: text() for p in principles}),
                'evidence_refs': obj({p: array(enum(sorted(ids)), 12) for p in principles}),
                'improvement_priorities': array(text(400), 4), 'notes_for_architect': text(2000)})


def roadmap(gap_ids, framework_ids):
    return obj({'roadmap_items': array(obj({
        'item_id': text(100), 'title': text(200), 'description': text(1200),
        'gap_ids_addressed': array(enum(sorted(gap_ids)), 60), 'frameworks_addressed': array(enum(sorted(framework_ids)), 5),
        'priority': {'type': 'integer', 'minimum': 1, 'maximum': 99},
        'effort_days': {'type': 'number', 'minimum': 0.5, 'maximum': 2000},
        'timeline_band': enum(['0-90', '90-180', '180-365', '365+']), 'responsible_role': text(120),
        'dependencies': array(text(100), 40), 'success_criteria': array(text(300), 4, 2),
        'estimated_cost_band': enum(['low', 'medium', 'high']),
    })), 'executive_summary': text(1200)})


FIELDS = ['receipt_id', 'invoice_id', 'amount_minor', 'currency', 'reference', 'remittance.reference']
RATIONALE = text(700)
WORKERS = {
    'ledgersight.intake': obj({'valid': {'type': 'boolean'}, 'anomalies': array(text(300), 10), 'rationale': RATIONALE}),
    'ledgersight.match': obj({'selected_invoice_id': NULL_TEXT, 'confidence': {'type': 'number', 'minimum': 0, 'maximum': 1},
                             'evidence_fields': array(enum(FIELDS), 6), 'rationale': RATIONALE}),
    'ledgersight.reconciliation': obj({'explanation': RATIONALE, 'evidence_fields': array(enum(FIELDS), 6)}),
    'ledgersight.cash_allocation': obj({'recommendation': enum(['prepare_proposal', 'hold', 'no_proposal']),
                                       'invoice_id': NULL_TEXT, 'rationale': RATIONALE}),
    'ledgersight.exception': obj({'queue': enum(['none', 'controller_review', 'operations_review', 'data_quality']), 'summary': RATIONALE}),
    'ledgersight.audit': obj({'summary': RATIONALE, 'evidence_refs': array(text(150), 50)}),
}


def worker(agent_id, source):
    """Constrain identifiers to this call's supplied records; semantic checks remain independent."""
    import copy
    schema = copy.deepcopy(WORKERS[agent_id])
    props = schema['properties']
    if agent_id == 'ledgersight.match':
        props['selected_invoice_id'] = {'enum': [i['invoice_id'] for i in source['candidate_invoices']] + [None]}
    elif agent_id == 'ledgersight.cash_allocation':
        props['invoice_id'] = {'enum': [*source['eligible_invoice_ids'], None]}
    elif agent_id == 'ledgersight.audit':
        props['evidence_refs'] = array(enum([source['receipt_id'], source['input_digest'], *source['candidate_invoice_ids']]), 50)
    return schema
