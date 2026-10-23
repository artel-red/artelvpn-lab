"""Synthetic paired benchmark. Uses only Python standard library, no network.

Every selector sees the same latent (seed, session, route) potential outcomes.
Selectors cannot see scenario, probabilities, change times, or unused outcomes.
The world is exogenous: no adaptive censor, probe interference, real TCP stack,
bootstrap traffic, battery model, or real transport implementation is modeled.
"""
from __future__ import annotations

from dataclasses import dataclass
from collections import defaultdict
import argparse
import hashlib
import json
from pathlib import Path
import random
import statistics

from controller import Controller, Route

ROUTES = [
    Route("udp_a", "A", "udp", 220),
    Route("tls_a", "A", "tcp", 320),
    Route("http_b", "B", "tcp", 430),
    Route("udp_b", "B", "udp", 240),
    Route("http_c", "C", "tcp", 490),
    Route("tls_c", "C", "tcp", 380),
]
SCENARIOS = ["stationary", "transport_shift", "provider_shift", "deceptive_handshake",
             "strict_allowlist_no_ingress", "restricted_with_ingress", "outage_recovery",
             "new_network_every_session", "new_opportunity"]
POLICIES = ["lkg", "lkg_racing", "bandit", "adaptive"]
DEADLINE_MS = 4500.0
MAX_ATTEMPTS = 3
# Capture at module load so a later edit cannot change the claimed tested source.
SOURCE_SHA256 = hashlib.sha256(Path(__file__).with_name("controller.py").read_bytes()
                               + Path(__file__).read_bytes()).hexdigest()


@dataclass(frozen=True)
class Potential:
    usable: bool
    duration_ms: float
    handshake: bool


def world(scenario: str, seed: int, session: int, sessions: int) -> tuple[str, dict[str, Potential]]:
    # Independent of which selector is run, order, or its attempt number.
    rng = random.Random(seed * 10000019 + session * 1009 + 23)
    phase = min(3, session * 4 // sessions)
    context = f"network_{session % 3}" if scenario != "new_network_every_session" else f"fresh_{session}"
    # Context-specific probabilities are hidden, but local context identity is observable.
    preferences = [0.97, 0.90, 0.88, 0.94, 0.89, 0.91]
    if session % 3 == 1:
        preferences = [0.15, 0.89, 0.96, 0.20, 0.94, 0.92]
    elif session % 3 == 2:
        preferences = [0.90, 0.89, 0.91, 0.94, 0.96, 0.90]
    if scenario == "stationary":
        preferences = [0.995, 0.92, 0.88, 0.93, 0.90, 0.92]
    if scenario == "deceptive_handshake":
        preferences = [0.08, 0.10, 0.94, 0.12, 0.93, 0.91]
    if scenario == "strict_allowlist_no_ingress":
        preferences = [0.0] * len(ROUTES)
    if scenario == "restricted_with_ingress":
        reachable = (seed + phase) % len(ROUTES)
        preferences = [0.97 if i == reachable else 0.0 for i in range(len(ROUTES))]
    if scenario == "new_network_every_session":
        local_rng = random.Random(seed * 97 + session * 101)
        best = local_rng.randrange(len(ROUTES))
        preferences = [0.97 if i == best else 0.12 for i in range(len(ROUTES))]
    if scenario == "new_opportunity":
        preferences = [0.82, 0.0, 0.999 if session >= sessions // 2 else 0.0, 0.0, 0.0, 0.0]
    global_outage = scenario == "outage_recovery" and sessions // 3 <= session < sessions // 2
    potentials = {}
    for i, route in enumerate(ROUTES):
        p = preferences[i]
        if scenario == "transport_shift" and route.family == ("udp" if phase % 2 else "tcp"):
            p = 0.0
        if scenario == "provider_shift" and route.provider == "ABC"[(phase + seed) % 3]:
            p = 0.0
        if global_outage:
            p = 0.0
        usable = rng.random() < p
        handshake = usable or (scenario == "deceptive_handshake")
        if usable:
            duration = max(50.0, route.estimated_ms * rng.uniform(0.65, 1.45))
        else:
            duration = rng.uniform(700, 1700) if handshake else rng.uniform(600, 1500)
        potentials[route.id] = Potential(usable, duration, handshake)
    return context, potentials


def play(controller: Controller, policy: str, context: str, now: int,
         potentials: dict[str, Potential]) -> dict:
    controller.begin(context)
    attempted: list[str] = []
    failed: list[str] = []
    elapsed = 0.0
    work_ms = 0.0
    censored = 0
    handshake_without_useful = 0
    while len(attempted) < MAX_ATTEMPTS and elapsed < DEADLINE_MS:
        # Racing starts at most two attempts together, once, then one fallback.
        width = 2 if policy == "lkg_racing" and not attempted else 1
        batch = []
        for _ in range(min(width, MAX_ATTEMPTS - len(attempted))):
            rid = controller.choose(context, now, attempted, failed,
                                    inflight=[rid for rid, _, _ in batch])
            if rid is None:
                break
            attempted.append(rid)
            ticket = controller.start(context, rid, now)
            if potentials[rid].handshake:
                controller.stage(ticket, "authenticated")
            batch.append((rid, ticket, potentials[rid]))
        if not batch:
            break
        remaining = DEADLINE_MS - elapsed
        winners = [(p.duration_ms, rid) for rid, _, p in batch if p.usable and p.duration_ms <= remaining]
        winner = min(winners)[1] if winners else None
        interval = min(potentials[winner].duration_ms if winner else max(p.duration_ms for _, _, p in batch), remaining)
        for rid, ticket, p in batch:
            work_ms += min(p.duration_ms, interval)
            if p.duration_ms > interval:
                controller.finish(ticket, "unknown", interval, now)
                censored += 1
            else:
                verdict = "usable" if p.usable else "unusable"
                controller.finish(ticket, verdict, p.duration_ms, now)
                if not p.usable:
                    failed.append(rid)
                    handshake_without_useful += p.handshake
        elapsed += interval
        if winner:
            return {"success": 1, "attempts": len(attempted), "latency_ms": elapsed,
                    "capped_ms": elapsed, "work_ms": work_ms, "censored": censored,
                    "misleading_handshakes": handshake_without_useful}
    return {"success": 0, "attempts": len(attempted), "latency_ms": None,
            "capped_ms": DEADLINE_MS, "work_ms": work_ms, "censored": censored,
            "misleading_handshakes": handshake_without_useful}


def mean_ci(values: list[float]) -> dict:
    average = statistics.mean(values)
    error = 1.96 * statistics.stdev(values) / len(values) ** 0.5 if len(values) > 1 else 0.0
    return {"mean": average, "mc_95_low": average - error, "mc_95_high": average + error}


def percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    values = sorted(values)
    return values[min(len(values) - 1, int((len(values) - 1) * q))]


def run(seeds: list[int], sessions: int) -> dict:
    output = {"evidence": "synthetic_simulation_only", "seed_start": seeds[0],
              "seeds": len(seeds), "sessions_per_seed": sessions,
              "deadline_ms": DEADLINE_MS, "max_attempts": MAX_ATTEMPTS,
              "assumptions": ["exogenous potential outcomes", "no adaptive censor or probe interference",
                              "perfect controlled final usable verdict", "round-based cooldown",
                              "no real transports, bootstrap, byte or battery model"], "scenarios": {}}
    for scenario in SCENARIOS:
        by_policy = {name: [] for name in POLICIES}
        recovery_by_policy = defaultdict(list)
        for seed in seeds:
            environment = [world(scenario, seed, t, sessions) for t in range(sessions)]
            for policy in POLICIES:
                ctrl = Controller(ROUTES, mode="lkg" if policy == "lkg_racing" else policy, seed=seed)
                rows = [play(ctrl, policy, ctx, t, latent) for t, (ctx, latent) in enumerate(environment)]
                hindsight = statistics.mean(any(p.usable and p.duration_ms <= DEADLINE_MS for p in latent.values())
                                            for _, latent in environment)
                successful = [r["latency_ms"] for r in rows if r["success"]]
                by_policy[policy].append({
                    "success_pct": statistics.mean(r["success"] for r in rows) * 100,
                    "mean_attempts": statistics.mean(r["attempts"] for r in rows),
                    "capped_ms": statistics.mean(r["capped_ms"] for r in rows),
                    "mean_work_ms": statistics.mean(r["work_ms"] for r in rows),
                    "success_only_p95_ms": percentile(successful, 0.95),
                    "hindsight_possible_pct": hindsight * 100,
                })
                if scenario == "outage_recovery":
                    restored = sessions // 2
                    first = next((i for i in range(restored, sessions) if rows[i]["success"]), None)
                    recovery_by_policy[policy].append(first - restored if first is not None else sessions - restored)
        summary = {}
        for policy, seed_rows in by_policy.items():
            summary[policy] = {metric: mean_ci([r[metric] for r in seed_rows])
                               for metric in ["success_pct", "mean_attempts", "capped_ms", "mean_work_ms", "hindsight_possible_pct"]}
            p95s = [r["success_only_p95_ms"] for r in seed_rows if r["success_only_p95_ms"] is not None]
            summary[policy]["success_only_p95_ms"] = mean_ci(p95s) if p95s else None
            if recovery_by_policy[policy]:
                summary[policy]["recovery_rounds"] = mean_ci(recovery_by_policy[policy])
        # Paired seed differences; not independent packet/session confidence intervals.
        paired = {}
        for baseline in POLICIES:
            if baseline == "adaptive":
                continue
            paired[baseline] = {
                "success_pp": mean_ci([a["success_pct"] - b["success_pct"]
                                       for a, b in zip(by_policy["adaptive"], by_policy[baseline])]),
                "capped_ms": mean_ci([a["capped_ms"] - b["capped_ms"]
                                      for a, b in zip(by_policy["adaptive"], by_policy[baseline])])}
        output["scenarios"][scenario] = {"policies": summary, "adaptive_minus_baseline": paired}
    output["source_sha256"] = SOURCE_SHA256
    return output


def markdown(results: dict) -> str:
    lines = ["# ArtelVPN controller v0 — synthetic benchmark", "",
             "Evidence: synthetic simulation only. No claim of bypassing TSPU or scientific novelty.", "",
             f"Seeds: {results['seeds']} from {results['seed_start']}; sessions per seed/scenario: {results['sessions_per_seed']}.",
             "The same latent route outcomes are shared across policies. No model tuning on reported evaluation is included.",
             "Intervals in results.json describe Monte Carlo variation across synthetic seeds, not uncertainty over Russia.", "",
             "| Scenario | Policy | Useful success, % | Attempts/session | Failure-inclusive time score, ms | Attempt occupancy, ms |",
             "|---|---|---:|---:|---:|---:|"]
    for scenario, block in results["scenarios"].items():
        for policy, row in block["policies"].items():
            lines.append(f"| {scenario} | {policy} | {row['success_pct']['mean']:.2f} | "
                         f"{row['mean_attempts']['mean']:.2f} | {row['capped_ms']['mean']:.0f} | "
                         f"{row['mean_work_ms']['mean']:.0f} |")
    lines += ["", "Failure-inclusive score assigns the full 4500 ms budget to every failed session, "
              "even if attempts stopped earlier. Attempt occupancy is a synthetic concurrency-cost proxy, not bytes or energy.",
              "Racing launches up to two attempts concurrently; it has the same maximum of three attempts but consumes more concurrent capacity.",
              "hindsight_possible_pct is a clairvoyant realized-outcome bound, not an implementable policy or a regret comparator.",
              "Success-only latency is secondary and must not be interpreted without failure rates.", "",
              "Limitations: exogenous network; no adaptive adversary; no real stack; perfect final-useful-data labels; "
              "no bootstrap or shaping evaluation; no off-policy real-data replay. Results are algorithm diagnostics only.", "",
              f"Source SHA-256: `{results['source_sha256']}`", ""]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", type=int, default=64)
    parser.add_argument("--sessions", type=int, default=600)
    parser.add_argument("--seed-start", type=int, default=10000)
    parser.add_argument("--output", type=Path, default=Path(__file__).parent / "results")
    args = parser.parse_args()
    if args.seeds < 1 or args.sessions < 12:
        parser.error("Need positive seeds and at least 12 sessions")
    result = run(list(range(args.seed_start, args.seed_start + args.seeds)), args.sessions)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "results.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (args.output / "benchmark.md").write_text(markdown(result), encoding="utf-8")
    print(json.dumps({"evidence": result["evidence"], "scenarios": len(SCENARIOS),
                      "seeds": args.seeds, "sessions_per_seed": args.sessions,
                      "source_sha256": result["source_sha256"]}))


if __name__ == "__main__":
    main()
