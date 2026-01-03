from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_and_rules():
    r = client.get('/health')
    assert r.status_code == 200
    j = r.json()
    assert 'status' in j and j['status'] == 'ok'

    r2 = client.get('/admin/rules')
    assert r2.status_code == 200
    jr = r2.json()
    assert 'rules' in jr and isinstance(jr['rules'], list)

