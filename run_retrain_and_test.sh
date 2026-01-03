#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# activate venv if present
if [ -d ".venv" ]; then
  source .venv/bin/activate
fi

echo "[1/5] Increase CSV field size and retrain model"
python3 - <<'PY'
import csv
csv.field_size_limit(10_000_000)
from waf.anomaly import train_from_file
print(train_from_file('data/train_kaggle.csv','models/model.pkl'))
PY

echo "[2/5] Restart or run the Docker container"
if docker container inspect beewaf_sklearn >/dev/null 2>&1; then
  docker container restart beewaf_sklearn && echo "restarted beewaf_sklearn"
else
  docker run -d --name beewaf_sklearn -p 8000:8000 beewaf:sklearn && echo "started beewaf_sklearn"
fi

echo "[3/5] Wait for service to become healthy (10s)"
sleep 10

echo "[4/5] Run integration script"
if [ -x "./tests/test_waf.sh" ]; then
  ./tests/test_waf.sh || echo "integration script failed (exit $?)"
else
  echo "tests/test_waf.sh not executable or not found"
fi

echo "[5/5] Run pytest"
pytest -q || echo "pytest failed (exit $?)"

echo "Done"
