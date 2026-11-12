from app import persist
from app.main import STORE

from tests.conftest import BANK, fill_required, new_assessment


def test_state_survives_restart(env, tmp_path):
    c, h = env
    aid = new_assessment(c, h, "admin@t-bank")
    fill_required(c, h, "admin@t-bank", aid, BANK)
    c.post(f"/v1/assessments/{aid}/submit", headers=h("admin@t-bank", **{"Idempotency-Key": "s"}))
    db = str(tmp_path / "taad.db")
    persist.save(STORE, f'sqlite:///{db}')
    for name in vars(STORE):
        v = getattr(STORE, name)
        if hasattr(v, "clear"):
            v.clear()
    assert c.get("/v1/assessments", headers=h("admin@t-bank")).status_code == 401  # state really gone
    assert persist.load(STORE, f'sqlite:///{db}')
    r = c.get(f"/v1/assessments/{aid}", headers=h("admin@t-bank")).json()
    assert r["status"] == "Submitted" and r["progress"]["required_answered"] == r["progress"]["required_total"]
    assert STORE.answers and all(isinstance(k, tuple) for k in STORE.answers)


def test_resume_lists_saved_answers_and_audit_feed(env):
    c, h = env
    aid = new_assessment(c, h, "admin@t-bank")
    from tests.conftest import put
    put(c, h, "admin@t-bank", aid, "Q-BASE-002", "banking")
    items = c.get(f"/v1/assessments/{aid}/answers", headers=h("admin@t-bank")).json()["items"]
    assert items[0]["question_id"] == "Q-BASE-002" and items[0]["etag"] == "1"
    feed = c.get("/v1/admin/activity", headers=h("architect@cloudseals")).json()["items"]
    assert any(a["action"] == "answer.put" for a in feed)
    assert c.get("/v1/admin/activity", headers=h("admin@t-bank")).status_code == 403


def test_concurrent_writer_detected_and_reloaded(env, tmp_path):
    import pytest
    c, h = env
    url = f"sqlite:///{tmp_path / 'c.db'}"
    new_assessment(c, h, "admin@t-bank", key="a")
    persist.save(STORE, url)
    persist._versions[url] = 1                       # we believe version 1 ...
    persist.save(STORE, url)                         # -> 2 (our write)
    persist._versions[url] = 1                       # ... but a stale writer thinks it is still 1
    new_assessment(c, h, "admin@t-bank", key="b")
    with pytest.raises(persist.PersistConflict):
        persist.save(STORE, url)
    assert len(STORE.assessments) == 1               # reloaded the authoritative state, dropping the stale write


def test_first_admin_bootstrap_marker_survives_restart(env, tmp_path):
    url = f"sqlite:///{tmp_path / 'bootstrap.db'}"
    STORE.admin_bootstrap.update({"completed_at": 1234.0, "sub": "first-admin-sub"})
    persist.save(STORE, url)
    STORE.admin_bootstrap.clear()
    assert persist.load(STORE, url)
    assert STORE.admin_bootstrap == {"completed_at": 1234.0, "sub": "first-admin-sub"}


class FakeGcs:
    """In-memory bucket that honours generation preconditions like the real service."""

    def __init__(self):
        self.objects = {}   # name -> (generation, text)
        self.counter = 0

    def bucket(self, name):
        return FakeBucket(self)


class FakeBlob:
    def __init__(self, gcs, name, gen=None, text=None):
        self.gcs, self.name, self.generation, self._text = gcs, name, gen, text

    def download_as_text(self):
        return self._text

    def upload_from_string(self, text, content_type=None, if_generation_match=None):
        from google.api_core.exceptions import PreconditionFailed
        cur = self.gcs.objects.get(self.name)
        if (cur[0] if cur else 0) != if_generation_match:
            raise PreconditionFailed("generation mismatch")
        self.gcs.counter += 1
        self.gcs.objects[self.name] = (self.gcs.counter, text)
        self.generation = self.gcs.counter


class FakeBucket:
    def __init__(self, gcs):
        self.gcs = gcs

    def get_blob(self, name):
        cur = self.gcs.objects.get(name)
        return FakeBlob(self.gcs, name, cur[0], cur[1]) if cur else None

    def blob(self, name):
        return FakeBlob(self.gcs, name)


def test_gcs_state_roundtrip_and_concurrent_writer_detected(env):
    import pytest
    c, h = env
    gcs = FakeGcs()
    persist.set_gcs_client(gcs)
    try:
        uri = "gs://bucket/state.json"
        aid = new_assessment(c, h, "admin@t-bank")
        persist.save(STORE, uri)                     # first write: object must not exist yet
        persist.save(STORE, uri)                     # later writes carry the generation they read
        for name in vars(STORE):
            v = getattr(STORE, name)
            if hasattr(v, "clear"):
                v.clear()
        assert persist.load(STORE, uri) and aid in STORE.assessments
        other = FakeBucket(gcs).blob("state.json")   # another instance writes in between
        other.upload_from_string("{}", if_generation_match=gcs.objects["state.json"][0])
        with pytest.raises(persist.PersistConflict):
            persist.save(STORE, uri)
        assert persist._versions[uri] == gcs.objects["state.json"][0]   # local version caught up with the winner; the retry succeeds
        persist.save(STORE, uri)
    finally:
        persist.set_gcs_client(None)
