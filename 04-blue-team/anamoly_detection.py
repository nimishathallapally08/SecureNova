# anomaly_detection.py - volume spike, scope change, token reuse after expiry
import time, json, datetime
from collections import deque

class AnomalyDetector:
    def __init__(self):
        self.call_times = deque()
        self.last_scope = {}
        self.seen_expired = set()

    def log_call(self, identity, scope, token_exp_ts):
        now = time.time()
        self.call_times.append(now)
        while self.call_times and now - self.call_times[0] > 60:
            self.call_times.popleft()
        if len(self.call_times) > 20:
            self._alert("volume_spike", identity, f"{len(self.call_times)} calls in 60s")

        prev = self.last_scope.get(identity)
        if prev and prev != scope:
            self._alert("scope_change", identity, f"{prev} -> {scope}")
        self.last_scope[identity] = scope

        if token_exp_ts < now:
            key = (identity, token_exp_ts)
            if key in self.seen_expired:
                self._alert("token_reuse_after_expiry", identity, f"token expired at {token_exp_ts}")
            self.seen_expired.add(key)

    def _alert(self, event_type, identity, detail):
        print(f"[ALERT] {datetime.datetime.now().isoformat()} type={event_type} identity={identity} detail={detail}")

d = AnomalyDetector()
for i in range(22):
    d.log_call("agent-001", "read:ai-data", time.time() + 300)
d.log_call("agent-001", "write:admin", time.time() + 300)
expired_ts = time.time() - 10
d.log_call("agent-001", "read:ai-data", expired_ts)
d.log_call("agent-001", "read:ai-data", expired_ts)