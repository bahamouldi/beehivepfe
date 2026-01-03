#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Activate venv if present
if [ -d ".venv" ]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

echo "[1/6] Ensure container is running or start it"
if docker container inspect beewaf_sklearn >/dev/null 2>&1; then
  docker container restart beewaf_sklearn && echo "restarted beewaf_sklearn"
else
  docker run -d --name beewaf_sklearn -p 8000:8000 beewaf:sklearn && echo "started beewaf_sklearn"
fi

echo "[2/6] Wait for service to become healthy"
sleep 5
echo "--- /health ---"
curl -sS http://127.0.0.1:8000/health || true

echo "[3/6] Run integration script (tests/test_waf.sh)"
if [ -x "./tests/test_waf.sh" ]; then
  ./tests/test_waf.sh || echo "integration script failed"
else
  echo "tests/test_waf.sh not found or not executable"
fi

echo "[4/6] Run pytest"
pytest -q || echo "pytest failed"

echo "[5/6] Example HTTP checks"
echo "benign request (should return 200):"
curl -s -X POST http://127.0.0.1:8000/echo -d 'hello' -H "Content-Type: text/plain" -w '\nHTTP_CODE:%{http_code}\n' || true

echo "sqli attempt (should be blocked 403):"
curl -s -X POST http://127.0.0.1:8000/echo -d "1 OR 1=1; DROP TABLE users;" -H "Content-Type: text/plain" -w '\nHTTP_CODE:%{http_code}\n' || true

echo "xss attempt (should be blocked 403):"
curl -s -X POST http://127.0.0.1:8000/echo -d '<script>alert(1)</script>' -H "Content-Type: text/plain" -w '\nHTTP_CODE:%{http_code}\n' || true

echo "[6/6] Tail container logs (last 200 lines)"
docker logs --tail 200 beewaf_sklearn || true

echo "Done"
