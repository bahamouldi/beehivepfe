import os
import csv
import json
import pickle
import math
from typing import List, Dict, Any

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except Exception:
    SKLEARN_AVAILABLE = False

try:
    import joblib
except Exception:
    joblib = None

import numpy as np

FEATURE_KEYS = ['body_len','special_chars','sql_keywords','xss_keywords','header_count']
SQL_WORDS = ['select','union','insert','update','delete','where','drop','or 1=1']
XSS_WORDS = ['<script>','javascript:','onerror','onload','alert(']


def vectorize_record(path: str, body: str, headers_json: str) -> List[float]:
    body = (body or "")
    headers = {}
    try:
        headers = json.loads(headers_json.replace("'","\"")) if headers_json else {}
    except Exception:
        # best-effort parse
        headers = {}
    body_len = len(body)
    special_chars = sum(1 for c in body if not c.isalnum() and not c.isspace())
    body_lower = body.lower()
    sql_count = sum(body_lower.count(w) for w in SQL_WORDS)
    xss_count = sum(body_lower.count(w) for w in XSS_WORDS)
    header_count = len(headers)
    return [body_len, special_chars, sql_count, xss_count, header_count]


class ModelWrapper:
    def __init__(self):
        self.model = None
        self.type = None

    def train(self, X: List[List[float]]):
        X = np.array(X)
        if SKLEARN_AVAILABLE:
            clf = IsolationForest(contamination=0.05, random_state=42)
            clf.fit(X)
            self.model = clf
            self.type = 'sklearn'
        else:
            # fallback: compute mean/std per feature
            mean = X.mean(axis=0).tolist()
            std = X.std(axis=0).tolist()
            self.model = {'mean': mean, 'std': std}
            self.type = 'fallback'

    def is_anomaly(self, x: List[float]) -> bool:
        if self.model is None:
            return False
        if self.type == 'sklearn':
            pred = self.model.predict([x])[0]
            # IsolationForest: -1 anomaly, 1 normal
            return int(pred) == -1
        else:
            mean = np.array(self.model['mean'])
            std = np.array(self.model['std'])
            z = np.abs((np.array(x) - mean) / (std + 1e-9))
            score = z.mean()
            return score > 3.0

    def save(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if self.type == 'sklearn' and joblib is not None:
            joblib.dump({'type': self.type, 'model': self.model}, path)
        else:
            with open(path, 'wb') as f:
                pickle.dump({'type': self.type, 'model': self.model}, f)

    def load(self, path: str):
        if not os.path.exists(path):
            return False
        try:
            if joblib is not None:
                data = joblib.load(path)
                if isinstance(data, dict) and 'type' in data and 'model' in data:
                    self.type = data['type']
                    self.model = data['model']
                    return True
            with open(path, 'rb') as f:
                data = pickle.load(f)
                self.type = data.get('type')
                self.model = data.get('model')
                return True
        except Exception:
            return False


# Convenience functions
_global_model = ModelWrapper()


def train_from_file(csv_path: str, save_path: str = None) -> Dict[str, Any]:
    X = []
    count = 0
    if not os.path.exists(csv_path):
        return {'ok': False, 'reason': 'file-not-found'}
    with open(csv_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            path = row.get('path','')
            body = row.get('body','')
            headers = row.get('headers','')
            # label = row.get('label','0')
            vec = vectorize_record(path, body, headers)
            X.append(vec)
            count += 1
    if count == 0:
        return {'ok': False, 'reason': 'no-rows'}
    _global_model.train(X)
    if save_path:
        _global_model.save(save_path)
    return {'ok': True, 'trained': True, 'rows': count}


def load_model(path: str) -> bool:
    return _global_model.load(path)


def is_anomaly_for_request(path: str, body: str, headers: Dict[str, str]) -> bool:
    headers_json = json.dumps(headers)
    vec = vectorize_record(path, body, headers_json)
    return _global_model.is_anomaly(vec)

if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--train', help='CSV train file')
    p.add_argument('--save', help='Save model path', default='models/model.pkl')
    args = p.parse_args()
    if args.train:
        res = train_from_file(args.train, save_path=args.save)
        print(res)
