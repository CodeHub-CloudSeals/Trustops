"""The Docker image must contain every file the API reads at import time (a missing file crashes the container on boot)."""
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def dockerfile_copies() -> list[tuple[list[str], str]]:
    text = (ROOT / "Dockerfile").read_text().replace("\\\n", " ")
    return [(m.group(1).split()[:-1], m.group(1).split()[-1]) for m in re.finditer(r"^COPY (.+)$", text, re.M)]


def test_image_layout_boots_the_app(tmp_path):
    for sources, dest in dockerfile_copies():
        for src in sources:
            if (ROOT / src).is_dir():
                shutil.copytree(ROOT / src, tmp_path / dest)
            else:
                shutil.copy(ROOT / src, tmp_path / (dest if dest not in (".", "./") else src))
    code = ("import sys;from app.main import app;from fastapi.testclient import TestClient;"
            "r=TestClient(app).get('/health');assert r.status_code==200, r.text")
    env = {"PYTHONPATH": ":".join(str(tmp_path / p) for p in ("packages/question-engine", "packages/reporting", "apps/assessment-api")),
           "TAAD_ENV": "local", "TAAD_AUTH_MODE": "dev", "PATH": "/usr/bin:/bin"}
    r = subprocess.run([sys.executable, "-c", code], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-1500:]
