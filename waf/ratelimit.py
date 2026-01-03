from collections import deque
import time
import threading
import os
from typing import Tuple

class RateLimiter:
    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = int(os.environ.get('BEEWAF_RATE_LIMIT_MAX', max_requests))
        self.window_seconds = int(os.environ.get('BEEWAF_RATE_LIMIT_WINDOW', window_seconds))
        self._stores = {}  # client_id -> deque[timestamps]
        self._lock = threading.Lock()

    def _now(self) -> float:
        return time.time()

    def allow_request(self, client_id: str) -> Tuple[bool, int]:
        """Return (allowed, remaining_requests)"""
        now = self._now()
        window_start = now - self.window_seconds
        with self._lock:
            dq = self._stores.get(client_id)
            if dq is None:
                dq = deque()
                self._stores[client_id] = dq
            # evict old timestamps
            while dq and dq[0] < window_start:
                dq.popleft()
            if len(dq) >= self.max_requests:
                return False, 0
            dq.append(now)
            return True, self.max_requests - len(dq)

    def reset(self, client_id: str):
        with self._lock:
            if client_id in self._stores:
                del self._stores[client_id]

