# ArtelVPN controller v0 — synthetic benchmark

Evidence: synthetic simulation only. No claim of bypassing TSPU or scientific novelty.

Seeds: 64 from 10000; sessions per seed/scenario: 600.
The same latent route outcomes are shared across policies. No model tuning on reported evaluation is included.
Intervals in results.json describe Monte Carlo variation across synthetic seeds, not uncertainty over Russia.

| Scenario | Policy | Useful success, % | Attempts/session | Failure-inclusive time score, ms | Attempt occupancy, ms |
|---|---|---:|---:|---:|---:|
| stationary | lkg | 100.00 | 1.01 | 252 | 252 |
| stationary | lkg_racing | 100.00 | 2.00 | 231 | 462 |
| stationary | bandit | 100.00 | 1.04 | 310 | 310 |
| stationary | adaptive | 100.00 | 1.01 | 241 | 241 |
| transport_shift | lkg | 84.85 | 1.40 | 1091 | 888 |
| transport_shift | lkg_racing | 84.88 | 2.19 | 1009 | 1109 |
| transport_shift | bandit | 85.32 | 1.48 | 1151 | 954 |
| transport_shift | adaptive | 85.38 | 1.41 | 1089 | 891 |
| provider_shift | lkg | 99.04 | 1.12 | 493 | 480 |
| provider_shift | lkg_racing | 98.82 | 2.04 | 397 | 705 |
| provider_shift | bandit | 99.03 | 1.19 | 580 | 567 |
| provider_shift | adaptive | 98.87 | 1.13 | 506 | 491 |
| deceptive_handshake | lkg | 99.00 | 1.09 | 560 | 551 |
| deceptive_handshake | lkg_racing | 98.90 | 2.02 | 442 | 817 |
| deceptive_handshake | bandit | 99.43 | 1.15 | 639 | 634 |
| deceptive_handshake | adaptive | 98.74 | 1.10 | 578 | 567 |
| strict_allowlist_no_ingress | lkg | 0.00 | 3.00 | 4500 | 3149 |
| strict_allowlist_no_ingress | lkg_racing | 0.00 | 3.00 | 4500 | 3149 |
| strict_allowlist_no_ingress | bandit | 0.00 | 3.00 | 4500 | 3147 |
| strict_allowlist_no_ingress | adaptive | 0.00 | 3.00 | 4500 | 3151 |
| restricted_with_ingress | lkg | 94.46 | 1.13 | 612 | 537 |
| restricted_with_ingress | lkg_racing | 94.53 | 2.06 | 597 | 870 |
| restricted_with_ingress | bandit | 94.71 | 1.24 | 719 | 648 |
| restricted_with_ingress | adaptive | 94.49 | 1.14 | 627 | 552 |
| outage_recovery | lkg | 83.21 | 1.40 | 1102 | 875 |
| outage_recovery | lkg_racing | 83.08 | 2.18 | 1003 | 1010 |
| outage_recovery | bandit | 83.23 | 1.41 | 1144 | 918 |
| outage_recovery | adaptive | 83.17 | 1.41 | 1105 | 878 |
| new_network_every_session | lkg | 64.98 | 2.26 | 2349 | 1875 |
| new_network_every_session | lkg_racing | 64.98 | 2.52 | 1971 | 1796 |
| new_network_every_session | bandit | 64.66 | 2.27 | 2408 | 1929 |
| new_network_every_session | adaptive | 64.98 | 2.26 | 2349 | 1875 |
| new_opportunity | lkg | 90.57 | 1.21 | 753 | 626 |
| new_opportunity | lkg_racing | 90.52 | 2.10 | 659 | 763 |
| new_opportunity | bandit | 90.11 | 1.28 | 822 | 688 |
| new_opportunity | adaptive | 90.58 | 1.22 | 753 | 626 |

Failure-inclusive score assigns the full 4500 ms budget to every failed session, even if attempts stopped earlier. Attempt occupancy is a synthetic concurrency-cost proxy, not bytes or energy.
Racing launches up to two attempts concurrently; it has the same maximum of three attempts but consumes more concurrent capacity.
hindsight_possible_pct is a clairvoyant realized-outcome bound, not an implementable policy or a regret comparator.
Success-only latency is secondary and must not be interpreted without failure rates.

Limitations: exogenous network; no adaptive adversary; no real stack; perfect final-useful-data labels; no bootstrap or shaping evaluation; no off-policy real-data replay. Results are algorithm diagnostics only.

Source SHA-256: `9adeae9d02bec7f3e4307144c58048f8afc009a241d7cf5d55df8bbf3ea2ffd0`
