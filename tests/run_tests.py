import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

print('health ->', client.get('/health').json())
print('index ->', client.get('/').json())

r = client.post('/echo', data='hello world')
print('echo benign ->', r.status_code, r.text)

r = client.post('/echo', data='1 OR 1=1; DROP TABLE users;')
print('echo sqli ->', r.status_code, r.json())

r = client.post('/echo', data='<script>alert(1)</script>')
print('echo xss ->', r.status_code, r.json())
