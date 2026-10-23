"""Offline research controller. No sockets, secrets, crypto, or VPN implementation.

Only reviewed route IDs are selectable. Partial/cancelled feedback is not failure.
Round is a simulated clock; an integration needs a monotonic clock and real probes.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
import math
import random


@dataclass(frozen=True)
class Route:
    id: str
    provider: str
    family: str
    estimated_ms: float = 400.0


@dataclass
class Evidence:
    good: float = 0.0
    bad: float = 0.0
    latency_ms: float = 400.0
    updated: int = 0
    failures: int = 0
    cooldown_until: int = 0
    latest_origin: int = -1

    def decayed(self, now: int, decay: float) -> tuple[float, float]:
        weight = decay ** max(0, now - self.updated)
        return self.good * weight, self.bad * weight


@dataclass
class Context:
    routes: dict[str, Evidence] = field(default_factory=dict)
    last_good: str | None = None
    visits: int = 0
    last_good_origin: int = -1


@dataclass(frozen=True)
class Ticket:
    number: int
    context: str
    route: str
    started: int
    generation: int


class Controller:
    """A memory-bounded local selector with final-outcome feedback tickets.

    mode: lkg, bandit, adaptive. These are research implementations, not replicas
    of Psiphon/Lantern. 'adaptive' is a heuristic, with no regret guarantee.
    Per-session attempt/time budgets are enforced by benchmark.play(), not here.
    A production adapter must enforce attempts, bytes, time, concurrency, and
    probe rate independently; it must not expose this bare interface to models.
    """

    def __init__(self, routes: list[Route], mode: str = "adaptive", seed: int = 0,
                 max_contexts: int = 16, max_pending: int = 128):
        if not routes or len({r.id for r in routes}) != len(routes):
            raise ValueError("Reviewed routes must be nonempty with unique IDs")
        if mode not in {"lkg", "bandit", "adaptive"}:
            raise ValueError("Unknown mode")
        if max_contexts < 1 or max_pending < 1:
            raise ValueError("State limits must be positive")
        self.routes = {r.id: r for r in routes}
        self.mode = mode
        self.rng = random.Random(seed)
        self.max_contexts = max_contexts
        self.max_pending = max_pending
        self.contexts: OrderedDict[str, tuple[int, Context]] = OrderedDict()
        self.pending: OrderedDict[int, Ticket] = OrderedDict()
        self._generation = 0
        self._ticket = 0

    def _context(self, key: str) -> tuple[int, Context]:
        if key not in self.contexts:
            self._generation += 1
            self.contexts[key] = (self._generation, Context(routes={
                rid: Evidence(latency_ms=r.estimated_ms) for rid, r in self.routes.items()
            }))
            while len(self.contexts) > self.max_contexts:
                self.contexts.popitem(last=False)
        self.contexts.move_to_end(key)
        return self.contexts[key]

    def begin(self, context: str) -> None:
        self._context(context)[1].visits += 1

    def choose(self, context: str, now: int, attempted: list[str],
               failed: list[str], eligible: set[str] | None = None,
               inflight: list[str] | None = None) -> str | None:
        _, ctx = self._context(context)
        allowed = set(self.routes) if eligible is None else set(eligible) & self.routes.keys()
        candidates = [rid for rid in self.routes if rid in allowed and rid not in attempted]
        if not candidates:
            return None
        ready = [rid for rid in candidates if ctx.routes[rid].cooldown_until <= now]
        # Cooldown is temporary evidence, never an irreversible blocklist.
        candidates = ready or candidates
        # In-flight diversity is a scheduling hint, not negative evidence.
        avoid_routes = [self.routes[rid] for rid in failed + (inflight or []) if rid in self.routes]

        def diversity_penalty(rid: str) -> float:
            route = self.routes[rid]
            same_provider = any(r.provider == route.provider for r in avoid_routes)
            same_family = any(r.family == route.family for r in avoid_routes)
            return 0.24 * same_provider + 0.13 * same_family

        if self.mode == "lkg":
            if ctx.last_good in candidates and not failed:
                return ctx.last_good
            def baseline_score(rid: str) -> float:
                ev = ctx.routes[rid]
                rate = (1.0 + ev.good) / (2.0 + ev.good + ev.bad)
                return rate - ev.latency_ms / 6000.0 - diversity_penalty(rid)
            return max(candidates, key=baseline_score)

        decay = 0.985
        if self.mode == "bandit":
            def bandit_score(rid: str) -> float:
                ev = ctx.routes[rid]
                good, bad = ev.decayed(now, decay)
                return self.rng.betavariate(1.0 + good, 1.0 + bad) - ev.latency_ms / 6000.0
            return max(candidates, key=bandit_score)

        def adaptive_score(rid: str) -> float:
            route, ev = self.routes[rid], ctx.routes[rid]
            good, bad = ev.decayed(now, decay)
            n = good + bad
            rate = (1.0 + good) / (2.0 + n)
            uncertainty = min(0.13, 0.08 * math.sqrt(math.log1p(ctx.visits) / (n + 1)))
            # Capped sibling heuristic; excludes this route's own observations.
            # It is a ranking hint, not independent Bayesian evidence or a label
            # for any untried route. Group aggregation is deliberately shallow.
            sibling_rates = []
            for other_id, other in self.routes.items():
                if other_id == rid:
                    continue
                if other.provider != route.provider and other.family != route.family:
                    continue
                pg, pb = ctx.routes[other_id].decayed(now, decay)
                if pg + pb >= 2:
                    sibling_rates.append((1 + pg) / (2 + pg + pb))
            hint = 0.04 * (sum(sibling_rates) / len(sibling_rates) - 0.5) if sibling_rates else 0
            loyalty = 0.025 if rid == ctx.last_good and not failed else 0.0
            return rate + uncertainty + hint + loyalty - ev.latency_ms / 6000 - diversity_penalty(rid)
        return max(candidates, key=adaptive_score)

    def start(self, context: str, rid: str, now: int) -> Ticket:
        if rid not in self.routes:
            raise ValueError("Unreviewed route")
        generation, _ = self._context(context)
        self._ticket += 1
        ticket = Ticket(self._ticket, context, rid, now, generation)
        self.pending[ticket.number] = ticket
        while len(self.pending) > self.max_pending:
            self.pending.popitem(last=False)
        return ticket

    def stage(self, ticket: Ticket, stage: str) -> bool:
        if stage not in {"transport", "authenticated", "verified_bytes"}:
            raise ValueError("Unknown intermediate stage")
        # Stage notification is not evidence of sustained success in this v0.
        return self.pending.get(ticket.number) == ticket

    def finish(self, ticket: Ticket, verdict: str, elapsed_ms: float, now: int) -> bool:
        if verdict not in {"usable", "unusable", "unknown"}:
            raise ValueError("Unknown terminal verdict")
        if not math.isfinite(elapsed_ms) or elapsed_ms < 0:
            raise ValueError("Duration must be finite and nonnegative")
        if not isinstance(now, int) or now < ticket.started:
            raise ValueError("Feedback clock must not precede attempt")
        if self.pending.get(ticket.number) != ticket:
            return False  # duplicate, missing, or evicted ticket
        current = self.contexts.get(ticket.context)
        if current is None or current[0] != ticket.generation:
            del self.pending[ticket.number]
            return False  # Do not resurrect an evicted network's evidence.
        ev = current[1].routes[ticket.route]
        if now < ev.updated:
            return False  # Invalid delivery clock; leave ticket retryable.
        del self.pending[ticket.number]
        if verdict == "unknown":
            return True  # cancellation/right-censoring does not imply failure
        weight = 1.0
        if self.mode != "lkg":
            ev.good, ev.bad = ev.decayed(now, 0.985)
            # Delayed evidence loses value from its origin, not its arrival.
            weight = 0.985 ** (now - ticket.started)
        fresh_origin = ticket.started >= ev.latest_origin
        if verdict == "usable":
            ev.good += weight
            if fresh_origin:
                ev.failures = 0
                ev.cooldown_until = 0
            if fresh_origin and ticket.started >= current[1].last_good_origin:
                current[1].last_good = ticket.route
                current[1].last_good_origin = ticket.started
        else:
            ev.bad += weight
            if fresh_origin:
                ev.failures += 1
                ev.cooldown_until = max(ev.cooldown_until,
                                        ticket.started + min(16, 2 ** min(ev.failures, 4)))
        # Bounded memory even for the non-discounted baseline.
        total = ev.good + ev.bad
        if total > 100:
            ev.good *= 100 / total
            ev.bad *= 100 / total
        rate = 0.2 * weight
        ev.latency_ms = (1 - rate) * ev.latency_ms + rate * elapsed_ms
        ev.updated = now
        ev.latest_origin = max(ev.latest_origin, ticket.started)
        return True
