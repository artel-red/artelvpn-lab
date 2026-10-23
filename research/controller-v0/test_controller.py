"""Invariants and counterexamples, not real censorship tests."""
import unittest

from controller import Controller, Route
from benchmark import ROUTES, DEADLINE_MS, MAX_ATTEMPTS, Potential, play, world


class ControllerTests(unittest.TestCase):
    def test_unreviewed_routes_cannot_be_selected(self):
        ctrl = Controller(ROUTES)
        self.assertIsNone(ctrl.choose("net", 0, [], [], {"unknown"}))
        with self.assertRaises(ValueError):
            ctrl.start("net", "unknown", 0)

    def test_handshake_is_not_success_and_cancel_is_not_failure(self):
        ctrl = Controller(ROUTES)
        ticket = ctrl.start("net", "udp_a", 0)
        ctrl.stage(ticket, "authenticated")
        self.assertIsNone(ctrl.contexts["net"][1].last_good)
        self.assertTrue(ctrl.finish(ticket, "unknown", 200, 1))
        ev = ctrl.contexts["net"][1].routes["udp_a"]
        self.assertEqual((ev.good, ev.bad), (0, 0))

    def test_terminal_feedback_is_idempotent(self):
        ctrl = Controller(ROUTES)
        ticket = ctrl.start("net", "udp_a", 0)
        self.assertTrue(ctrl.finish(ticket, "usable", 200, 1))
        self.assertFalse(ctrl.finish(ticket, "unusable", 900, 2))
        self.assertEqual(ctrl.contexts["net"][1].routes["udp_a"].bad, 0)

    def test_evicted_network_cannot_be_resurrected_by_delayed_feedback(self):
        ctrl = Controller(ROUTES, max_contexts=1)
        ticket = ctrl.start("old", "udp_a", 0)
        ctrl.begin("new")
        self.assertFalse(ctrl.finish(ticket, "usable", 200, 1))
        self.assertNotIn("old", ctrl.contexts)

    def test_unknown_feedback_does_not_update_other_context(self):
        ctrl = Controller(ROUTES)
        ticket = ctrl.start("one", "udp_a", 0)
        ctrl.begin("two")
        ctrl.finish(ticket, "usable", 200, 1)
        self.assertIsNone(ctrl.contexts["two"][1].last_good)

    def test_route_not_repeated_within_session(self):
        ctrl = Controller(ROUTES)
        chosen = ctrl.choose("net", 0, [], [])
        self.assertNotEqual(chosen, ctrl.choose("net", 0, [chosen], []))

    def test_common_failure_steers_to_different_provider(self):
        ctrl = Controller(ROUTES)
        selected = ctrl.choose("net", 0, ["udp_a"], ["udp_a"])
        self.assertNotEqual(ctrl.routes[selected].provider, "A")

    def test_cooldown_does_not_permanently_blacklist(self):
        route = Route("only", "A", "tcp")
        ctrl = Controller([route])
        ticket = ctrl.start("net", "only", 0)
        ctrl.finish(ticket, "unusable", 1000, 1)
        self.assertEqual(ctrl.choose("net", 2, [], []), "only")

    def test_budget_censored_attempt_does_not_poison_evidence(self):
        ctrl = Controller(ROUTES)
        potentials = {r.id: Potential(False, 10000, True) for r in ROUTES}
        row = play(ctrl, "adaptive", "net", 0, potentials)
        self.assertEqual(row["success"], 0)
        self.assertEqual(row["censored"], 1)
        self.assertEqual(sum(ev.bad for ev in ctrl.contexts["net"][1].routes.values()), 0)
        self.assertEqual(row["capped_ms"], DEADLINE_MS)

    def test_no_route_means_no_invented_success(self):
        for mode in ["lkg", "bandit", "adaptive"]:
            ctrl = Controller(ROUTES, mode)
            for t in range(30):
                context, potential = world("strict_allowlist_no_ingress", 1, t, 60)
                row = play(ctrl, mode, context, t, potential)
                self.assertEqual(row["success"], 0)
                self.assertLessEqual(row["attempts"], MAX_ATTEMPTS)

    def test_racing_cancellation_is_unknown(self):
        ctrl = Controller(ROUTES, "lkg")
        potential = {r.id: Potential(True, 1000 if r.id != "udp_a" else 100, True) for r in ROUTES}
        row = play(ctrl, "lkg_racing", "net", 0, potential)
        self.assertEqual(row["success"], 1)
        self.assertEqual(row["censored"], 1)
        self.assertEqual(sum(ev.bad for ev in ctrl.contexts["net"][1].routes.values()), 0)

    def test_pending_state_is_bounded(self):
        ctrl = Controller(ROUTES, max_pending=2)
        tickets = [ctrl.start("net", "udp_a", i) for i in range(3)]
        self.assertEqual(len(ctrl.pending), 2)
        self.assertFalse(ctrl.finish(tickets[0], "usable", 1, 3))

    def test_invalid_feedback_keeps_ticket_retryable(self):
        ctrl = Controller(ROUTES)
        ticket = ctrl.start("net", "udp_a", 5)
        for invalid_duration in [float("nan"), float("inf"), -1]:
            with self.assertRaises(ValueError):
                ctrl.finish(ticket, "usable", invalid_duration, 6)
        with self.assertRaises(ValueError):
            ctrl.finish(ticket, "usable", 200, 4)
        self.assertTrue(ctrl.finish(ticket, "usable", 200, 6))

    def test_delayed_success_does_not_replace_fresher_last_good(self):
        ctrl = Controller(ROUTES)
        old = ctrl.start("net", "udp_a", 0)
        new = ctrl.start("net", "http_b", 10)
        ctrl.finish(new, "usable", 400, 10)
        ctrl.finish(old, "usable", 200, 20)
        ctx = ctrl.contexts["net"][1]
        self.assertEqual(ctx.last_good, "http_b")
        self.assertAlmostEqual(ctx.routes["udp_a"].good, 0.985 ** 20)

    def test_old_failure_does_not_cool_fresher_success(self):
        ctrl = Controller(ROUTES)
        old = ctrl.start("net", "udp_a", 0)
        new = ctrl.start("net", "udp_a", 5)
        ctrl.finish(new, "usable", 200, 5)
        ctrl.finish(old, "unusable", 1000, 10)
        self.assertEqual(ctrl.contexts["net"][1].routes["udp_a"].cooldown_until, 0)

    def test_old_success_cannot_nominate_route_after_newer_route_failure(self):
        ctrl = Controller(ROUTES)
        good_b = ctrl.start("net", "http_b", 0)
        ctrl.finish(good_b, "usable", 400, 0)
        old_a = ctrl.start("net", "udp_a", 1)
        newer_a = ctrl.start("net", "udp_a", 2)
        ctrl.finish(newer_a, "unusable", 1000, 2)
        ctrl.finish(old_a, "usable", 200, 10)
        self.assertEqual(ctrl.contexts["net"][1].last_good, "http_b")

    def test_racing_prefers_independent_family_and_provider(self):
        ctrl = Controller(ROUTES, "lkg")
        rid = ctrl.choose("net", 0, ["udp_a"], [], inflight=["udp_a"])
        self.assertNotEqual(ctrl.routes[rid].provider, "A")
        self.assertNotEqual(ctrl.routes[rid].family, "udp")


if __name__ == "__main__":
    unittest.main()
