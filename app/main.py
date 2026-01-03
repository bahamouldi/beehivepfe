from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import logging
import os

from waf import rules
from waf import anomaly
from waf.ratelimit import RateLimiter

app = FastAPI()
log = logging.getLogger("beewaf")
logging.basicConfig(level=logging.INFO)

rate_limiter = RateLimiter(max_requests=10, window_seconds=60)
MODEL_PATH = os.environ.get('BEEWAF_MODEL_PATH','models/model.pkl')
TRAIN_DATA = os.environ.get('BEEWAF_TRAIN_DATA','data/train_demo.csv')

@app.on_event("startup")
def startup_event():
    log.info('Startup: attempting to load persisted model')
    loaded = anomaly.load_model(MODEL_PATH)
    if not loaded:
        log.info('No persisted model found, training from %s', TRAIN_DATA)
        res = anomaly.train_from_file(TRAIN_DATA, save_path=MODEL_PATH)
        log.info('Training result: %s', res)
    else:
        log.info('Loaded persisted model from %s', MODEL_PATH)

@app.middleware("http")
async def waf_middleware(request: Request, call_next):
    client = request.client.host if request.client else 'unknown'
    path = request.url.path
    body = await request.body()
    body_text = body.decode('utf-8', errors='ignore') if body else ''

    allowed, remaining = rate_limiter.allow_request(client)
    if not allowed:
        return JSONResponse(status_code=429, content={"blocked": True, "reason": "rate-limit"})

    blocked, reason = rules.check_regex_rules(path, body_text, dict(request.headers))
    if blocked:
        log.info('Blocked by regex rule: %s %s %s', client, path, reason)
        return JSONResponse(status_code=403, content={"blocked": True, "reason": reason})

    # anomaly detection
    try:
        if anomaly.is_anomaly_for_request(path, body_text, dict(request.headers)):
            log.info('Blocked by anomaly detector: %s %s', client, path)
            return JSONResponse(status_code=403, content={"blocked": True, "reason": "anomaly"})
    except Exception:
        log.exception('Anomaly detector error')

    # passthrough
    response = await call_next(request)
    return response

@app.get('/health')
def health():
    ok = os.path.exists(MODEL_PATH)
    return {"status": "ok", "anomaly_detector_trained": ok, "rules_count": len(rules.list_rules())}


@app.get('/admin/rules')
def admin_rules():
    return {"rules": rules.list_rules()}
@app.post('/admin/retrain')
def retrain():
    res = anomaly.train_from_file(TRAIN_DATA, save_path=MODEL_PATH)
    if not res.get('ok'):
        raise HTTPException(status_code=500, detail=res)
    return res

@app.get('/')
def index():
    return {"service": "BeeWAF", "status":"running"}

@app.post('/echo')
async def echo(request: Request):
    body = await request.body()
    return JSONResponse(content=(body.decode('utf-8', errors='ignore') if body else ''))
