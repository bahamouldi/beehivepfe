#!/bin/bash
set -e
BASE=http://127.0.0.1:8000
sleep 1
curl -s $BASE/health | jq || true
# benign request
curl -s -X POST $BASE/echo -d 'hello world' -H 'Content-Type: text/plain'
# SQLi attempt
curl -s -X POST $BASE/echo -d "1 OR 1=1; DROP TABLE users;" -H 'Content-Type: text/plain' -w '\nHTTP_CODE:%{http_code}\n'
# XSS attempt
curl -s -X POST $BASE/echo -d "<script>alert(1)</script>" -H 'Content-Type: text/plain' -w '\nHTTP_CODE:%{http_code}\n'
