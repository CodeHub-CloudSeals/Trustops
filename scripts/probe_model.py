"""Verify the explicitly configured model using synthetic text only; never print secrets or model output."""
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'apps' / 'assessment-api'))

from app import llm, model_schemas, swaska


def main():
    result = {'provider': llm.provider() or None, 'model_id': llm.configured_model_id(), 'live_verified': False}
    start = time.perf_counter()
    try:
        client = swaska.default_client()
        if client is None:
            raise ValueError('No model provider configured')
        raw = model_schemas.complete(client, 'Return exactly the JSON object {"ok":true}.', 'Synthetic connection check. No customer data.', 256, model_schemas.READY)
        if json.loads(raw) != {'ok': True}:
            raise ValueError('Unexpected probe result')
        result['live_verified'] = True
    except Exception as exc:
        # Exceptions can contain keys or provider request bodies. Classify locally, never echo them.
        text = str(exc).lower()
        reason = 'not_configured' if not result['provider'] else 'billing_hold' if 'dunning' in text or 'billing' in text else 'authentication_or_access' if any(
            x in text for x in ('401', '403', 'credential', 'api_key', 'api key')) else 'quota' if '429' in text else 'connection_or_output'
        result.update(reason=reason, error_type=type(exc).__name__)
    result['elapsed_seconds'] = round(time.perf_counter() - start, 2)
    print(json.dumps(result))
    return 0 if result['live_verified'] else 1


if __name__ == '__main__':
    sys.exit(main())
