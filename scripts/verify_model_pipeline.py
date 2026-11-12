"""Real-model acceptance with synthetic inputs only. Does not import API/STORE or publish reports."""
import argparse
import io
import json
import os
import sys
import time
from pathlib import Path
from urllib.request import ProxyHandler, build_opener

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'apps' / 'assessment-api'))
from app import llm, model_schemas, studio, swaska, trustops_runtime, use_cases

DOCUMENT = ('Synthetic engineering AI register. The customer support chatbot answers account FAQs using an approved FAQ knowledge base. '
            'Support owns the chatbot. It cannot change accounts or issue refunds. A support specialist reviews escalated requests. '
            'The supplied register contains no model monitoring results, retention configuration or recorded release tests.')


class RecordingClient:
    def __init__(self, client):
        self.client, self.model_id, self.calls = client, client.model_id, []
        self.response = None
        owner = self
        upstream = client._opener

        class SyntheticAuditTransport:
            def open(self, request, timeout):
                with upstream.open(request, timeout=timeout) as response:
                    raw = response.read(2_000_001)
                owner.response = json.loads(raw)
                return io.BytesIO(raw)
        client._opener = SyntheticAuditTransport()

    def complete(self, system, user, max_tokens=600):
        return self._record(system, user, max_tokens, None)

    def complete_json(self, system, user, max_tokens=600, *, schema):
        return self._record(system, user, max_tokens, schema)

    def _record(self, system, user, max_tokens, schema):
        start = time.monotonic()
        self.response = None
        record = {'system': system, 'user': user, 'max_tokens': max_tokens, 'schema': schema}
        self.calls.append(record)
        try:
            output = model_schemas.complete(self.client, system, user, max_tokens, schema) if schema else self.client.complete(system, user, max_tokens)
            record['output'] = output
            return output
        except Exception as exc:
            record['error_type'] = type(exc).__name__
            raise
        finally:
            record['seconds'] = round(time.monotonic() - start, 2)
            record['synthetic_provider_response'] = self.response
            print('SYNTHETIC_MODEL_CALL ' + json.dumps(record), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', required=True)
    parser.add_argument('--payments-only', action='store_true', help='Retest bounded payment reasoning after document acceptance')
    args = parser.parse_args()
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    summary = {'scope': 'Real inference on synthetic inputs; review statuses are test fixtures. No API/STORE/customer data/publication/ERP writes.',
               'payments_only': args.payments_only, 'provider': llm.provider(), 'model': llm.configured_model_id(), 'steps': [], 'passed': False}
    client = RecordingClient(swaska.default_client())
    started = time.monotonic()

    def stage(name, fn):
        before = time.monotonic()
        summary['current_step'] = name
        value = fn()
        if isinstance(value, dict) and value.get('status') in ('failed', 'partial', 'unavailable'):
            raise ValueError(name + '_not_completed')
        summary['steps'].append({'step': name, 'passed': True, 'seconds': round(time.monotonic() - before, 2),
                                 'items': len(value.get('items', [])) if isinstance(value, dict) else None})
        print(json.dumps(summary['steps'][-1]), flush=True)
        return value

    try:
        if llm.provider() != 'ollama':
            raise ValueError('Acceptance requires the private self-hosted model')
        opener = build_opener(ProxyHandler({}))
        deadline = time.monotonic() + 90
        while True:
            try:
                with opener.open(os.environ.get('TAAD_OLLAMA_URL', 'http://127.0.0.1:11434') + '/api/tags', timeout=2):
                    break
            except Exception:
                if time.monotonic() > deadline:
                    raise TimeoutError('model_startup') from None
                time.sleep(1)
        probe = stage('json_connection', lambda: json.loads(model_schemas.complete(client, 'Return exactly {"ok":true}.', 'Synthetic acceptance probe.', 256, model_schemas.READY)))
        assert probe == {'ok': True}
        if not args.payments_only:
            inv = stage('document_inventory', lambda: use_cases.run_inventory(client, [
                {'evidence_id': 'synthetic-acceptance-e1', 'filename': 'synthetic-ai-register.txt', 'text': DOCUMENT}]))
            assert inv['items']
            cases = inv['items']
            gaps = stage('framework_gaps', lambda: use_cases.run_gap_analysis(client, 'eu_ai_act', cases))['items']
            maturity = stage('maturity', lambda: studio.run_maturity(client, cases, gaps))['maturity']
            assert maturity is not None
            roadmap = stage('roadmap', lambda: studio.run_roadmap(client, gaps, maturity))
            assert roadmap['items'] and not roadmap['uncovered_gaps']
            # Explicit local fixtures exercise report rendering, never an authenticated approval or publication.
            for item in [*cases, *gaps, maturity, *roadmap['items']]:
                item['status'] = 'VALIDATED'
            html, _ = studio.build_report_html({'ai_system_name': 'SYNTHETIC MODEL ACCEPTANCE — NOT CUSTOMER APPROVAL', 'industry': 'banking'},
                'Engineering fixture', cases, gaps, maturity, roadmap['items'], None, 'engineering acceptance fixture')
            html = html.replace('<body>', '<body><p>ENGINEERING TEST FIXTURE ONLY. NO CUSTOMER APPROVAL OR PUBLICATION.</p>')
            (out / 'synthetic-report.html').write_text(html)
            summary['steps'].append({'step': 'report_render', 'passed': True, 'bytes': len(html.encode())})
        receipt = {'receipt_id': 'SYNTHETIC-R1', 'amount_minor': 25000, 'currency': 'USD', 'reference': 'SYNTHETIC-INV1'}
        invoices = [{'invoice_id': 'SYNTHETIC-I1', 'amount_minor': 25000, 'currency': 'USD', 'reference': 'SYNTHETIC-INV1'}]
        run = stage('six_payment_workers', lambda: trustops_runtime.run_agents('synthetic-tenant', 'synthetic-engineer', receipt,
                    invoices, {'reference': 'SYNTHETIC-INV1'}, client=client))
        assert len(run['agent_trace']) == 6 and all('recommendation' in step for step in run['agent_trace'])
        assert run['policy_decision']['decision'] == 'ALLOW', 'Unique exact match was unnecessarily escalated'
        assert run['agent_trace'][1]['recommendation']['selected_invoice_id'] == 'SYNTHETIC-I1'
        assert run['proposal']['invoice_id'] == 'SYNTHETIC-I1'
        summary['passed'] = True
    except Exception as exc:
        summary.update(error_type=type(exc).__name__, error_code=getattr(exc, 'code', None))
    finally:
        summary['seconds'] = round(time.monotonic() - started, 2)
        summary['model_calls'] = len(client.calls)
        (out / 'model-acceptance.json').write_text(json.dumps(summary, indent=2))
        # These are explicitly synthetic prompts/outputs, written locally and logged only by this synthetic acceptance script.
        (out / 'synthetic-model-calls.json').write_text(json.dumps(client.calls, indent=2))
        print(json.dumps(summary), flush=True)
    return 0 if summary['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
