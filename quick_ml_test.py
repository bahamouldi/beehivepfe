#!/usr/bin/env python3
"""Test rapide du modèle ML"""
import sys
sys.path.insert(0, '/home/kali/seethroughwalls')

from waf.anomaly import load_model, is_anomaly_for_request

print("🤖 BeeWAF ML Model Quick Test\n")

# Charger le modèle
try:
    model = load_model("/home/kali/seethroughwalls/models/model.pkl")
    print(f"✅ Model loaded: {model.type}")
except Exception as e:
    print(f"❌ Error: {e}")
    sys.exit(1)

# Tests simples
tests = [
    ("Normal", "search=hello", "/api/search", False),
    ("SQLi", "id=1' OR 1=1--", "/user", True),
    ("XSS", "<script>alert(1)</script>", "/comment", True),
    ("CMDI", "; cat /etc/passwd", "/exec", True),
    ("Normal", "username=john", "/login", False),
]

print("\n📊 Testing:")
passed = 0
for name, body, path, expect_anomaly in tests:
    result = is_anomaly_for_request(body, path, '{"user-agent":"test"}')
    status = "✅" if result == expect_anomaly else "❌"
    result_str = "ANOMALY" if result else "NORMAL"
    print(f"{status} {name:10} → {result_str}")
    if result == expect_anomaly:
        passed += 1

print(f"\n📈 Score: {passed}/{len(tests)} ({passed*100//len(tests)}%)")
