"""One process-global rate governor. Never per-tool.

A token bucket (rate = requests_per_second) plus a concurrency semaphore (max_concurrency),
acquired by EVERY outbound unit of work — a built-in source fetch or an external tool spawn —
so N concurrent tools can never aggregate past the config caps. A human grant may only lower it.
"""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from typing import Callable, Iterator


class RateGovernor:
    def __init__(
        self,
        requests_per_second: float,
        max_concurrency: int,
        *,
        sleep_fn: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if requests_per_second <= 0:
            raise ValueError("requests_per_second must be > 0")
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be >= 1")
        self.rps = float(requests_per_second)
        self.max_concurrency = int(max_concurrency)
        self._sleep = sleep_fn
        self._clock = clock
        self._lock = threading.Lock()
        self._sem = threading.BoundedSemaphore(self.max_concurrency)
        self._next_free = self._clock()
        self.total_acquires = 0

    def _pace(self) -> None:
        interval = 1.0 / self.rps
        with self._lock:
            now = self._clock()
            wait = max(0.0, self._next_free - now)
            self._next_free = max(now, self._next_free) + interval
            self.total_acquires += 1
        if wait > 0:
            self._sleep(wait)

    @contextmanager
    def lease(self) -> Iterator[None]:
        """Acquire one concurrency slot and pace to the global rps, then release."""
        self._sem.acquire()
        try:
            self._pace()
            yield
        finally:
            self._sem.release()

    def narrowed(self, requests_per_second: float, max_concurrency: int) -> "RateGovernor":
        """Return a governor that only LOWERS the caps (a human may narrow, never broaden)."""
        return RateGovernor(
            min(self.rps, requests_per_second),
            min(self.max_concurrency, max_concurrency),
            sleep_fn=self._sleep,
            clock=self._clock,
        )
