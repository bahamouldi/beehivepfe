from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_rate_limit():
    # use X-Real-IP header to identify client
    headers = {'X-Real-IP': '1.2.3.4'}
    allowed = 0
    # default limiter in code: 60 requests per 60s
    for i in range(65):
        r = client.post('/echo', data='ping', headers=headers)
        if r.status_code == 200:
            allowed += 1
        else:
            assert r.status_code == 429
            break
    assert allowed > 0
    assert allowed <= 60

