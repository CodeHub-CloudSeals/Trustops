"""Scripted stand-in for the language model, used only by the browser tests so the model-backed pages can be exercised
without cloud credentials. It answers the five model-backed agents the way a well-behaved model would."""
import json
import re

PRINCIPLES = ["model_agnostic", "neuro_symbolic", "digital_twin", "evidence_fabric", "model_welfare"]


class ScriptedModel:
    model_id = "scripted-browser-test"
    is_demo = True

    def complete(self, system, user, max_tokens=600):
        if "Inventory Agent" in system:
            return json.dumps({"use_cases": [
                {"name": "Credit scoring model", "description": "Scores loan applicants and approves low-risk applications automatically.",
                 "business_owner": "Retail Lending", "technical_owner": "Data Science", "model_type": "classification", "foundation_models_used": [],
                 "decision_authority": "autonomous", "data_sources": ["credit bureau data"], "risk_tier": "high_risk",
                 "risk_tier_rationale": "Creditworthiness assessment is listed in Annex III.", "extraction_confidence": 0.92,
                 "source_quotes": ["credit scoring model assigns loan applicants a score"]},
                {"name": "Customer service chatbot", "description": "Answers customer questions about accounts.", "business_owner": "Customer Care",
                 "technical_owner": None, "model_type": "LLM", "foundation_models_used": ["Claude"], "decision_authority": "advisory", "data_sources": [],
                 "risk_tier": "limited_risk", "risk_tier_rationale": "Chatbots carry transparency duties.", "extraction_confidence": 0.55,
                 "source_quotes": ["chatbot answers customer questions about accounts"]}]})
        if "Gap Analysis Agent" in system:
            ids = re.findall(r'"use_case_id": "(uc_[0-9a-f]+)"', user)
            return json.dumps({"findings": [{
                "framework_clause": "Article_5", "finding_title": "No documented Article 5 prohibition screening",
                "finding_description": "The register describes automatic approvals but contains no screening against prohibited practices.",
                "severity": "critical", "recommendation_summary": "Run and document an Article 5 screening for each use case.",
                "estimated_effort_days": 8, "suggested_timeline": "0-90", "evidence_use_case_ids": ids[:1],
                "evidence_quotes": ["credit scoring model assigns loan applicants a score"]}]})
        if "Maturity Scorer" in system:
            ids = re.findall(r'"(?:use_case_id|gap_id)": "([a-z]+_[0-9a-f]+)"', user)
            return json.dumps({"scores": dict(zip(PRINCIPLES, [1.5, 1.0, 2.0, 3.0, 1.5])),
                               "rationale": {p: f"Little documented practice for {p.replace('_', ' ')} in the register." for p in PRINCIPLES},
                               "evidence_refs": {p: ids[:1] for p in PRINCIPLES} | {"evidence_fabric": []},
                               "improvement_priorities": ["P2 Neuro-Symbolic: add rule-based guardrails"], "notes_for_architect": "One document supplied."})
        if "Roadmap Agent" in system:
            gids = re.findall(r'"gap_id": "(gap_[0-9a-f]+)"', user)
            return json.dumps({"roadmap_items": [
                {"item_id": "a", "title": "Run and document an Article 5 screening", "description": "Screen every AI use case against prohibited practices.",
                 "frameworks_addressed": ["eu_ai_act"], "gap_ids_addressed": gids[:1], "priority": 1, "effort_days": 8, "timeline_band": "90-180",
                 "responsible_role": "Legal / Compliance", "dependencies": [], "success_criteria": ["Screening completed", "Counsel sign-off recorded"],
                 "estimated_cost_band": "low"}], "executive_summary": "One critical gap needs action within 90 days."})
        if "Architecture Overlay Agent" in system:
            ids = re.findall(r'"use_case_id": "(uc_[0-9a-f]+)"', user)[:1]
            node = lambda i, label, kind="system", **kw: {"id": i, "label": label, "kind": kind, **kw}  # noqa: E731
            return json.dumps({
                "current": {"nodes": [node("App", "Credit application", evidence_refs=ids), node("Model", "Credit scoring model", "model", evidence_refs=ids),
                                      node("Audit", "Decision audit trail", "unknown")], "edges": [{"from": "App", "to": "Model"}, {"from": "Model", "to": "Audit", "dashed": True}]},
                "target": {"nodes": [node("App", "Credit application"), node("Abs", "Model abstraction API", principle="P1"), node("Rules", "Policy rules engine", principle="P2"),
                                     node("Reg", "Model registry", "control", principle="P3"), node("Fab", "Signed evidence store", "control", principle="P4"),
                                     node("Mon", "Drift monitoring", "control", principle="P5")],
                           "edges": [{"from": "App", "to": "Abs"}, {"from": "Abs", "to": "Rules"}, {"from": "Abs", "to": "Reg"}, {"from": "Rules", "to": "Fab"}, {"from": "Reg", "to": "Mon"}]},
                "gap_commentary": "Decisions go straight from the application to the model.\n\nNothing records which model version decided.",
                "key_differences": ["Current: direct model call -> Target: abstraction API", "Current: no audit trail -> Target: signed evidence store", "Current: no monitoring -> Target: drift monitoring"]})
        if "executive narrative" in system:
            return json.dumps({"executive_summary": "One credit scoring use case is high risk.\n\nMaturity is early.", "key_themes": ["Document screening"]})
        raise ValueError("not scripted")
