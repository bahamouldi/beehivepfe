# 🐝 BeeWAF — Web Application Firewall

**Production-ready Web Application Firewall avec ML et ELK Stack**

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 📋 Table des Matières

- [Fonctionnalités](#-fonctionnalités)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Utilisation](#-utilisation)
- [Tests](#-tests)
- [Déploiement](#-déploiement)
- [Monitoring](#-monitoring)
- [Configuration](#-configuration)

## ✨ Fonctionnalités

### 🛡️ Protection Multi-Couches

| Fonctionnalité | Description | Status |
|----------------|-------------|--------|
| **249 Règles Regex** | Detection de 19 types d'attaques | ✅ |
| **Machine Learning** | IsolationForest pour anomalies | ✅ |
| **Rate Limiting** | 10 req/min par IP (configurable) | ✅ |
| **ClamAV Scanner** | Scan antivirus des uploads | ✅ |
| **ELK Stack** | Logging centralisé + Dashboards | ✅ |
| **Prometheus** | Métriques temps réel | ✅ |
| **TLS/HTTPS** | Certificats SSL via Nginx | ✅ |

### 🔒 Types d'Attaques Détectées

- SQL Injection (30 patterns)
- XSS / Cross-Site Scripting (27 patterns)
- Command Injection (33 patterns)
- Path Traversal / LFI (16 patterns)
- SSRF (27 patterns)
- XXE (4 patterns)
- LDAP Injection (14 patterns)
- NoSQL Injection (19 patterns)
- JNDI / Log4Shell (17 patterns)
- SSTI (9 patterns)
- Deserialization (5 patterns)
- Prototype Pollution (8 patterns)
- Et bien d'autres...

## 🏗️ Architecture

```
┌─────────────┐    HTTPS    ┌──────────┐    HTTP    ┌──────────┐
│   Client    │────────────▶│  Nginx   │───────────▶│  BeeWAF  │
│  (Browser)  │             │ (Reverse │            │ (FastAPI)│
└─────────────┘             │  Proxy)  │            └──────────┘
                            └──────────┘                   │
                                 │                         │
                                 │                         ▼
                            ┌─────────────────────────────────┐
                            │         ELK Stack               │
                            │  ┌──────────────────────────┐   │
                            │  │ Filebeat → Logstash →    │   │
                            │  │ Elasticsearch → Kibana   │   │
                            │  └──────────────────────────┘   │
                            └─────────────────────────────────┘
```

## 🚀 Installation

### Option 1: Stack Complet avec ELK (Recommandé)

```bash
# Cloner le repository
git clone https://github.com/bahamouldi/beehivepfe.git
cd beehivepfe

# Construire l'image Docker
docker build -t beewaf:sklearn .

# Lancer le stack complet (6 containers)
docker-compose -f docker-compose-elk.yaml up -d

# Vérifier les containers
docker ps | grep beewaf
```

**Accès:**
- WAF: https://localhost (HTTPS) ou http://localhost (redirigé)
- Kibana Dashboard: http://localhost:5601
- Prometheus Metrics: http://localhost:8000/metrics
- Health Check: http://localhost:8000/health

### Option 2: Installation Locale (Développement)

```bash
# Créer un environnement virtuel
python3 -m venv .venv
source .venv/bin/activate  # Linux/Mac
# ou .venv\Scripts\activate  # Windows

# Installer les dépendances
pip install --upgrade pip
pip install -r requirements.txt

# Lancer le serveur
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

## 📖 Utilisation

### Health Check

```bash
curl http://localhost:8000/health
```

**Réponse:**
```json
{
  "status": "ok",
  "anomaly_detector_trained": true,
  "rules_count": 249
}
```

### Tester une Attaque SQLi

```bash
curl -k -X POST https://localhost/echo -d "' OR 1=1--"
```

**Réponse:**
```json
{
  "blocked": true,
  "reason": "regex-sqli"
}
```

### Tester une Attaque XSS

```bash
curl -k -X POST https://localhost/echo -d "<script>alert(1)</script>"
```

**Réponse:**
```json
{
  "blocked": true,
  "reason": "regex-xss"
}
```

### Requête Normale (doit passer)

```bash
curl -k "https://localhost/?search=hello"
```

**Réponse:**
```json
{
  "service": "BeeWAF",
  "status": "running"
}
```

## 🧪 Tests

### Tests Unitaires

```bash
pytest -v
```

### Tests d'Intégration

```bash
./tests/test_waf.sh
```

### Tests Manuels Complets

```bash
# SQL Injection
curl -k "https://localhost/?id=1%27%20OR%20%271%27=%271"

# XSS
curl -k "https://localhost/?q=%3Cscript%3Ealert(1)%3C/script%3E"

# Command Injection
curl -k "https://localhost/?cmd=;cat%20/etc/passwd"

# Path Traversal
curl -k "https://localhost/?file=../../../etc/passwd"

# SSRF
curl -k "https://localhost/?url=http://169.254.169.254/latest/meta-data"
```

**Toutes ces commandes doivent retourner HTTP 403 avec `{"blocked":true}`**

## 🚢 Déploiement

### Docker Compose

```bash
# Stack minimal (WAF + Nginx)
docker-compose up -d

# Stack complet (WAF + Nginx + ELK)
docker-compose -f docker-compose-elk.yaml up -d

# Vérifier les logs
docker logs beewaf_sklearn -f
```

### Kubernetes

```bash
# Créer le secret TLS
kubectl create secret tls beewaf-tls-secret \
  --cert=k8s/tls/tls.crt \
  --key=k8s/tls/tls.key

# Déployer
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml

# Vérifier le déploiement
kubectl get pods -l app=beewaf
kubectl get svc beewaf-svc
kubectl rollout status deployment/beewaf
```

### CI/CD Jenkins

Le pipeline Jenkins (`Jenkinsfile`) inclut:

1. **Checkout** - Clone du code
2. **Install** - Installation des dépendances
3. **Unit Tests** - pytest
4. **Build Docker Image** - Construction de l'image
5. **Integration Test** - Tests d'intégration
6. **Push Image** - (optionnel) Push vers registry
7. **Deploy to K8s** - (optionnel) Déploiement

Configuration requise:
- Variable `DOCKER_REGISTRY` pour le push
- Credentials Docker Registry dans Jenkins
- `KUBECONFIG` pour le déploiement K8s

## 📊 Monitoring

### Kibana Dashboard

Accès: http://localhost:5601/app/dashboards#/view/beewaf-soc-dashboard

**8 Visualisations:**
- 🎯 Attacks by Reason (Pie Chart)
- 📈 Attacks Over Time (Line Chart)
- 🌐 Top Client IPs (Table)
- 🛡️ Total Blocked (Metric)
- 📊 By HTTP Method (Bar Chart)
- ⚔️ Attack Types (Pie Chart)
- 📝 Total Requests (Metric)
- 📋 HTTP Status Codes (Pie Chart)

### Prometheus Metrics

Endpoint: http://localhost:8000/metrics

**Métriques disponibles:**
```
beewaf_requests_total{method, endpoint, status}
beewaf_blocked_total{reason}
beewaf_request_latency_seconds{method, endpoint}
beewaf_active_requests
beewaf_rules_count
beewaf_model_loaded
```

### Elasticsearch

```bash
# Vérifier l'index
curl http://localhost:9200/beewaf-logs-*/_count

# Voir les dernières attaques
curl http://localhost:9200/beewaf-logs-*/_search?size=5&sort=@timestamp:desc
```

## ⚙️ Configuration

### Variables d'Environnement

Créer un fichier `.env`:

```bash
# API Key pour les endpoints admin
BEEWAF_API_KEY=your-secure-api-key

# Chemins des modèles
BEEWAF_MODEL_PATH=models/model.pkl
BEEWAF_TRAIN_DATA=data/train_synthetic.csv

# Rate Limiting
BEEWAF_RATE_LIMIT_MAX=10
BEEWAF_RATE_LIMIT_WINDOW=60

# Elasticsearch (pour ELK)
ELASTICSEARCH_HOSTS=http://elasticsearch:9200
```

### Endpoints Admin

**Liste des règles:**
```bash
curl http://localhost:8000/admin/rules \
  -H "X-API-Key: your-api-key"
```

**Réentraîner le modèle ML:**
```bash
curl -X POST http://localhost:8000/admin/retrain \
  -H "X-API-Key: your-api-key"
```

### Désactiver le Rate Limit

Modifier dans `app/main.py`:
```python
# Ligne 78
rate_limiter = RateLimiter(max_requests=1000, window_seconds=60)
```

## 📊 Statistiques du Projet

| Métrique | Valeur |
|----------|--------|
| **Règles Regex** | 249 |
| **Catégories d'Attaques** | 19 |
| **Containers Docker** | 6 |
| **Datasets Training** | 126,184 lignes |
| **Taille Modèle ML** | 387 KB |
| **Visualisations Kibana** | 8 |
| **Code Coverage** | 95%+ |

## 🤝 Contribution

Les contributions sont les bienvenues ! Veuillez:

1. Forker le projet
2. Créer une branche (`git checkout -b feature/AmazingFeature`)
3. Commiter (`git commit -m 'Add AmazingFeature'`)
4. Pousser (`git push origin feature/AmazingFeature`)
5. Ouvrir une Pull Request

## 📝 License

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## 🙏 Remerciements

- Dataset CSIC-2010 pour l'entraînement ML
- Elastic Stack pour le logging
- FastAPI pour le framework web
- scikit-learn pour l'anomaly detection

## 📧 Contact

**GitHub:** [@bahamouldi](https://github.com/bahamouldi)
**Repository:** [beehivepfe](https://github.com/bahamouldi/beehivepfe)

---

**Fait avec ❤️ et Python | BeeWAF © 2026**

