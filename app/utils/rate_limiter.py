import asyncio
import time


class AdaptiveRateLimiter:
    """Small async token limiter with conservative slowdown on instability."""

    def __init__(self, requests_per_second: float):
        self.base_rate = max(0.2, min(float(requests_per_second), 20.0))
        self.current_rate = self.base_rate
        self._lock = asyncio.Lock()
        self._next_allowed = 0.0
        self._recent_anomalies = 0

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait_for = max(0.0, self._next_allowed - now)
            if wait_for:
                await asyncio.sleep(wait_for)
            interval = 1.0 / max(self.current_rate, 0.2)
            self._next_allowed = time.monotonic() + interval

    def record_anomaly(self) -> None:
        self._recent_anomalies += 1
        if self._recent_anomalies >= 3:
            self.current_rate = max(0.2, self.current_rate * 0.65)
            self._recent_anomalies = 0

    def record_stable(self) -> None:
        if self.current_rate < self.base_rate:
            self.current_rate = min(self.base_rate, self.current_rate * 1.05)

