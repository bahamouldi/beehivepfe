from fastapi import FastAPI, Request, HTTPException, Depends, Header
from fastapi.responses import JSONResponse, Response
from fastapi.security import APIKeyHeader
import logging
import os
import secrets
import time
import json
from datetime import datetime
from pythonjsonlogger import jsonlogger
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

from waf import rules
from waf import anomaly
from waf.ratelimit import RateLimiter

# JSON Logging Configuration for ELK Stack
class CustomJsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super(CustomJsonFormatter, self).add_fields(log_record, record, message_dict)
        log_record['@timestamp'] = datetime.utcnow().isoformat() + 'Z'
        log_record['service'] = 'beewaf'
        log_record['level'] = record.levelname
        log_record['logger_name'] = record.name

def setup_logging():
    logger = logging.getLogger("beewaf")
    logger.setLevel(logging.INFO)
    
    # Console handler with JSON format (for Docker logs -> Logstash)
    console_handler = logging.StreamHandler()
    formatter = CustomJsonFormatter(
        '%(message)s'
    )
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Also configure root logger for uvicorn
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    root_logger.addHandler(console_handler)
    
    return logger

log = setup_logging()

# Prometheus Metrics
REQUESTS_TOTAL = Counter(
    'beewaf_requests_total',
    'Total number of requests',
    ['method', 'endpoint', 'status']
)
BLOCKED_TOTAL = Counter(
    'beewaf_blocked_total',
    'Total number of blocked requests',
    ['reason']
)
REQUEST_LATENCY = Histogram(
    'beewaf_request_latency_seconds',
    'Request latency in seconds',
    ['method', 'endpoint']
)
ACTIVE_REQUESTS = Gauge(
    'beewaf_active_requests',
    'Number of active requests'
)
RULES_COUNT = Gauge(
    'beewaf_rules_count',
    'Number of WAF rules loaded'
)
MODEL_LOADED = Gauge(
    'beewaf_model_loaded',
    'Whether the anomaly detection model is loaded (1=yes, 0=no)'
)

app = FastAPI()

rate_limiter = RateLimiter(max_requests=10, window_seconds=60)
MODEL_PATH = os.environ.get('BEEWAF_MODEL_PATH','models/model.pkl')
TRAIN_DATA = os.environ.get('BEEWAF_TRAIN_DATA','data/train_demo.csv')

# API Key Authentication
API_KEY = os.environ.get('BEEWAF_API_KEY', 'changeme-default-key-not-secure')
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(api_key: str = Depends(api_key_header)):
    if api_key is None:
        raise HTTPException(status_code=401, detail="Missing API Key")
    if not secrets.compare_digest(api_key, API_KEY):
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return api_key

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
    # Update Prometheus metrics
    RULES_COUNT.set(len(rules.list_rules()))
    MODEL_LOADED.set(1 if os.path.exists(MODEL_PATH) else 0)

@app.middleware("http")
async def waf_middleware(request: Request, call_next):
    start_time = time.time()
    ACTIVE_REQUESTS.inc()
    
    # Get real client IP (check X-Original-IP, X-Real-IP or X-Forwarded-For header first for proxy/load balancer)
    x_original_ip = request.headers.get('X-Original-IP')
    x_real_ip = request.headers.get('X-Real-IP')
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    if x_original_ip:
        client = x_original_ip
    elif x_real_ip:
        client = x_real_ip
    elif x_forwarded_for:
        client = x_forwarded_for.split(',')[0].strip()
    else:
        client = request.client.host if request.client else 'unknown'
    path = request.url.path
    method = request.method
    query_string = str(request.url.query) if request.url.query else ''
    
    # Combine path and query for WAF checking
    full_path = f"{path}?{query_string}" if query_string else path
    
    # Skip metrics endpoint from WAF processing
    if path == '/metrics':
        ACTIVE_REQUESTS.dec()
        return await call_next(request)
    
    body = await request.body()
    body_text = body.decode('utf-8', errors='ignore') if body else ''
    
    # Store body for later use (avoid double reading)
    async def receive():
        return {"type": "http.request", "body": body}
    
    request._receive = receive

    allowed, remaining = rate_limiter.allow_request(client)
    if not allowed:
        log.warning('Request blocked', extra={
            'event': 'blocked',
            'client_ip': client,
            'method': method,
            'path': path,
            'reason': 'rate-limit',
            'status_code': 429
        })
        BLOCKED_TOTAL.labels(reason='rate-limit').inc()
        REQUESTS_TOTAL.labels(method=method, endpoint=path, status='429').inc()
        REQUEST_LATENCY.labels(method=method, endpoint=path).observe(time.time() - start_time)
        ACTIVE_REQUESTS.dec()
        return JSONResponse(status_code=429, content={"blocked": True, "reason": "rate-limit"})

    blocked, reason = rules.check_regex_rules(full_path, body_text, dict(request.headers))
    if blocked:
        log.warning('Request blocked', extra={
            'event': 'blocked',
            'client_ip': client,
            'method': method,
            'path': path,
            'reason': reason,
            'status_code': 403,
            'body_preview': body_text[:200] if body_text else ''
        })
        BLOCKED_TOTAL.labels(reason=reason).inc()
        REQUESTS_TOTAL.labels(method=method, endpoint=path, status='403').inc()
        REQUEST_LATENCY.labels(method=method, endpoint=path).observe(time.time() - start_time)
        ACTIVE_REQUESTS.dec()
        return JSONResponse(status_code=403, content={"blocked": True, "reason": reason})

    # anomaly detection
    try:
        if anomaly.is_anomaly_for_request(full_path, body_text, dict(request.headers)):
            log.warning('Request blocked', extra={
                'event': 'blocked',
                'client_ip': client,
                'method': method,
                'path': path,
                'reason': 'anomaly',
                'status_code': 403
            })
            BLOCKED_TOTAL.labels(reason='anomaly').inc()
            REQUESTS_TOTAL.labels(method=method, endpoint=path, status='403').inc()
            REQUEST_LATENCY.labels(method=method, endpoint=path).observe(time.time() - start_time)
            ACTIVE_REQUESTS.dec()
            return JSONResponse(status_code=403, content={"blocked": True, "reason": "anomaly"})
    except Exception:
        log.exception('Anomaly detector error')

    # passthrough
    response = await call_next(request)
    latency = time.time() - start_time
    log.info('Request processed', extra={
        'event': 'request',
        'client_ip': client,
        'method': method,
        'path': path,
        'status_code': response.status_code,
        'latency_ms': round(latency * 1000, 2)
    })
    REQUESTS_TOTAL.labels(method=method, endpoint=path, status=str(response.status_code)).inc()
    REQUEST_LATENCY.labels(method=method, endpoint=path).observe(latency)
    ACTIVE_REQUESTS.dec()
    return response

@app.get('/health')
def health():
    ok = os.path.exists(MODEL_PATH)
    return {"status": "ok", "anomaly_detector_trained": ok, "rules_count": len(rules.list_rules())}

@app.get('/metrics')
def metrics():
    """Prometheus metrics endpoint"""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get('/admin/rules', dependencies=[Depends(verify_api_key)])
def admin_rules():
    return {"rules": rules.list_rules()}

@app.post('/admin/retrain', dependencies=[Depends(verify_api_key)])
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
