"""High-precision timing utilities."""
import time
from contextlib import contextmanager


class Timer:
    """Simple timer for measuring operation duration."""

    def __init__(self, name: str = ""):
        self.name = name
        self.start_time: float = 0.0
        self.end_time: float = 0.0
        self.elapsed_ns: int = 0

    def __enter__(self):
        self.start_time = time.perf_counter_ns()
        return self

    def __exit__(self, *args):
        self.end_time = time.perf_counter_ns()
        self.elapsed_ns = self.end_time - self.start_time

    @property
    def elapsed_ms(self) -> float:
        return self.elapsed_ns / 1_000_000

    @property
    def elapsed_sec(self) -> float:
        return self.elapsed_ns / 1_000_000_000


def measure_time(func, *args, **kwargs) -> tuple:
    """Measure execution time of a function in nanoseconds. Returns (result, duration_ns)."""
    t0 = time.perf_counter_ns()
    result = func(*args, **kwargs)
    t1 = time.perf_counter_ns()
    return result, t1 - t0
