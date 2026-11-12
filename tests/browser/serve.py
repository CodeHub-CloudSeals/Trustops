"""Starts the real application for browser tests, with the scripted model plugged into the model-backed agents."""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / p) for p in ("packages/question-engine", "packages/reporting", "apps/assessment-api", ".")]
os.environ.update(TAAD_SEED="1", TAAD_ENV="local", TAAD_AUTH_MODE="dev")

import uvicorn  # noqa: E402
from app import main  # noqa: E402

from tests.browser.scripted_model import ScriptedModel  # noqa: E402

main.SWASKA_CLIENT = ScriptedModel()
uvicorn.run(main.app, host="127.0.0.1", port=int(sys.argv[1]), log_level="warning")
