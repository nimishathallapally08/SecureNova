"""Project 4 timestamped anomaly detection and deterministic event replay."""

from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import TypedDict


class RequestEvent(TypedDict):
    timestamp: float
    identity: str
    scope: str
    token_id: str
    expires_at: float
    case_id: str
    event_type: str


class Alert(TypedDict):
    timestamp: str
    identity: str
    event_type: str
    case_id: str
    detail: str


class AnomalyDetector:
    def __init__(self):
        self.calls: dict[str, deque[float]] = defaultdict(deque)
        self.scopes: dict[str, str] = {}
        self.expired_seen: set[tuple[str, str]] = set()
        self.last_time: dict[str, float] = {}

    def observe(self, event: RequestEvent) -> list[Alert]:
        now = event["timestamp"]
        identity = event["identity"]
        if now < self.last_time.get(identity, float("-inf")):
            raise ValueError(f"out-of-order event for {identity}")
        self.last_time[identity] = now
        alerts: list[Alert] = []

        def emit(kind: str, detail: str) -> None:
            alerts.append(Alert(
                timestamp=datetime.fromtimestamp(now, timezone.utc).isoformat(),
                identity=identity, event_type=kind, case_id=event["case_id"],
                detail=detail,
            ))

        if event["event_type"] not in ("agent_request", "llm_call"):
            raise ValueError(f"Unknown request event type: {event['event_type']}")
        if event["event_type"] == "llm_call":
            times = self.calls[identity]
            # Keep only calls from the rolling minute before enforcing the
            # 20-call threshold.
            while times and now - times[0] >= 60:
                times.popleft()
            times.append(now)
            if len(times) > 20:
                emit("volume_spike", f"{len(times)} LLM calls in the rolling 60s window")
        previous = self.scopes.get(identity)
        if previous is not None and previous != event["scope"]:
            emit("scope_change", f"{previous} -> {event['scope']}")
        self.scopes[identity] = event["scope"]
        if event["expires_at"] <= now:
            key = (identity, event["token_id"])
            if key in self.expired_seen:
                emit("token_reuse_after_expiry", "same expired token used again")
            self.expired_seen.add(key)
        return alerts


def replay(events: list[RequestEvent]) -> list[Alert]:
    detector = AnomalyDetector()
    return [alert for event in events for alert in detector.observe(event)]


def attack_scenario(events: list[RequestEvent]) -> list[RequestEvent]:
    """Replay real lab case IDs with explicit synthetic timing/auth perturbations."""
    if not events:
        raise ValueError("Cannot replay an empty attack run")
    origin = events[0]["timestamp"]
    scenario: list[RequestEvent] = []
    for i in range(23):
        event = events[i % len(events)].copy()
        event.update(
            timestamp=origin + i, identity="replay-agent",
            scope="write:admin" if i >= 21 else "read:demo",
            token_id="synthetic-expired-token" if i >= 21 else "synthetic-token",
            expires_at=origin + 20 if i >= 21 else origin + 300,
            event_type="llm_call",
        )
        scenario.append(event)
    return scenario
