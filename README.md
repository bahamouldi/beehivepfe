# BeeWAF
Minimal WAF prototype implemented with FastAPI.

Quick start (local):

pip3 install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000

Run tests:
./tests/test_waf.sh

Kubernetes and Jenkins artifacts are in `k8s/` and `Jenkinsfile`.

Project status
 - Prototype WAF implemented with regex rules, anomaly detector (IsolationForest if available), rate limiter and ClamAV adapter.
 - Model persistence: `models/model.pkl` is saved after training.
 - Docker images: `Dockerfile.final` and `Dockerfile.runtime` present. `beewaf:sklearn` image built for local tests.

How to build & run (recommended - local)
```
cd /home/kali/seethroughwalls
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Docker (build & run)
```
docker build -t beewaf:runtime -f Dockerfile.final .
docker run -d --name beewaf_run -p 8000:8000 beewaf:runtime
```

Kubernetes (example)
```
# adjust image name in k8s/deployment.yaml if pushing to registry
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl rollout status deployment/beewaf
kubectl get svc beewaf-svc
```

CI (Jenkins)
 - `Jenkinsfile` contains a full pipeline: install, unit tests, build image, integration test, optional push and deploy stages.
 - Configure `DOCKER_REGISTRY` and credentials in Jenkins to enable image push and deployment stages.

Next steps / recommendations
 - Replace synthetic datasets with larger labeled corpora (CSIC-2010 downloaded support is included), retrain model and version it under `models/`.
 - Use a persistent volume (PVC) for `models` when deploying to Kubernetes instead of `emptyDir`.
 - Add Prometheus metrics and structured logging for observability.
 - Harden admin endpoints with authentication and secure secrets (Kubernetes Secrets / Vault).

