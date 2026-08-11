"""Scheduler -- cron-like scheduled scanning for the Sentinel.

Supports cron expressions (5-field: minute hour day month weekday)
and per-protocol scan schedules.

Usage:
    from defihunter.sentinel.scheduler import CronSchedule
    cron = CronSchedule("0 */6 * * *")  # every 6 hours
    cron.matches()  # True/False based on current time
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta
from typing import Optional


class CronSchedule:
    """Simple cron expression parser (5-field).

    Supports: *, N, N-M, N/S, N,M,O
    """

    def __init__(self, expr: str):
        parts = expr.strip().split()
        if len(parts) != 5:
            raise ValueError(f"Invalid cron (need 5 fields, got {len(parts)}): {expr}")
        self.minutes = self._parse_field(parts[0], 0, 59)
        self.hours = self._parse_field(parts[1], 0, 23)
        self.days = self._parse_field(parts[2], 1, 31)
        self.months = self._parse_field(parts[3], 1, 12)
        self.weekdays = self._parse_field(parts[4], 0, 6)
        self.expr = expr

    @staticmethod
    def _parse_field(field: str, min_val: int, max_val: int) -> set:
        values = set()
        for part in field.split(","):
            if "/" in part:
                base, step = part.split("/", 1)
                step = int(step)
                start = min_val if base == "*" else int(base)
                for v in range(start, max_val + 1, step):
                    values.add(v)
            elif "-" in part:
                lo, hi = part.split("-", 1)
                for v in range(int(lo), int(hi) + 1):
                    values.add(v)
            elif part == "*":
                values.update(range(min_val, max_val + 1))
            else:
                values.add(int(part))
        return values

    def matches(self, dt: Optional[datetime] = None) -> bool:
        if dt is None:
            dt = datetime.now()
        # Convert Python weekday (0=Monday) to cron weekday (0=Sunday)
        cron_weekday = (dt.weekday() + 1) % 7
        return (
            dt.minute in self.minutes
            and dt.hour in self.hours
            and dt.day in self.days
            and dt.month in self.months
            and cron_weekday in self.weekdays
        )

    def next_run(self, after: Optional[datetime] = None) -> datetime:
        if after is None:
            after = datetime.now()
        candidate = after.replace(second=0, microsecond=0) + timedelta(minutes=1)
        for _ in range(366 * 24 * 60):
            if self.matches(candidate):
                return candidate
            candidate += timedelta(minutes=1)
        raise RuntimeError("Could not find next cron run within 366 days")

    def __repr__(self) -> str:
        return f"CronSchedule('{self.expr}')"


class IntervalSchedule:
    """Interval-based schedule (every N seconds)."""

    def __init__(self, interval_seconds: int):
        self.interval = interval_seconds
        self._last_run: float = 0

    def should_run(self) -> bool:
        now = time.time()
        if now - self._last_run >= self.interval:
            self._last_run = now
            return True
        return False

    def matches(self, dt: Optional[datetime] = None) -> bool:
        return self.should_run()

    def __repr__(self) -> str:
        return f"IntervalSchedule({self.interval}s)"


class CombinedSchedule:
    """Combine multiple schedules -- run if ANY triggers."""

    def __init__(self):
        self.schedules = []

    def add(self, schedule) -> None:
        self.schedules.append(schedule)

    def should_run(self) -> bool:
        return any(
            s.should_run() for s in self.schedules
            if hasattr(s, 'should_run')
        )

    def matches(self, dt: Optional[datetime] = None) -> bool:
        return any(s.matches(dt) for s in self.schedules)


def parse_schedule(expr: str):
    """Parse a schedule expression.

    "*/30 * * * *"  -> CronSchedule (every 30 min)
    "0 */6 * * *"   -> CronSchedule (every 6 hours)
    "every 3600s"   -> IntervalSchedule
    "every 1h"      -> IntervalSchedule
    "every 30m"     -> IntervalSchedule
    """
    expr = expr.strip()
    if expr.startswith("every "):
        unit = expr[6:].strip()
        if unit.endswith("s"):
            return IntervalSchedule(int(unit[:-1]))
        elif unit.endswith("m"):
            return IntervalSchedule(int(unit[:-1]) * 60)
        elif unit.endswith("h"):
            return IntervalSchedule(int(unit[:-1]) * 3600)
        elif unit.endswith("d"):
            return IntervalSchedule(int(unit[:-1]) * 86400)
        else:
            return IntervalSchedule(int(unit))
    return CronSchedule(expr)
