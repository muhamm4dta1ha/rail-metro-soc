# Rules of Engagement (RoE) - attack generation

Applies to every scenario, runner and script in `src/attacks/`. **Sign-off:** all four members approve this file in its PR (task M2-01). These rules implement hard constraints HC-02, HC-03 and HC-18 of [PLAN.md](../../plan/PLAN.md); the code in `railsoc_attacks/safety.py` enforces the technical ones.

1. **Allowed targets.** Only containers of the simulation compose project, addressed by *literal IP inside `10.60.0.0/16`*. Hostnames, public IPs, the host machine, home/campus networks and cloud services are never targets. (Enforced: `LabScope.assert_target_allowed`, called by `RunContext.guard`.)
2. **No operational systems.** Never connect to real railway, metro or utility networks, operational signaling or any safety system (HC-02).
3. **Synthetic only.** Accounts, data and traffic are synthetic or authorised laboratory traffic (HC-03). No real credentials, no personal data.
4. **Isolation.** Lab networks stay `internal: true`. Do not add `network_mode: host`, bridged NICs, extra network attachments for the attacker container, or published ports other than `127.0.0.1:...` (a contract test checks the compose file).
5. **Safety-related functions are out of scope.** Simulated station controllers are monitoring-class only (temperature, power feeder, lift status). Points, signals, interlocking and train protection are neither simulated nor attacked.
6. **Caps.** Rate <= `max_rate_per_s` and duration <= `max_duration_s` in `config/lab_scope.toml`; both are clamped in code. The scope can be narrowed, never widened beyond the lab address space.
7. **Kill switch.** `touch .kill_attacks` aborts a running scenario (checked by `ctx.guard()` - call it inside every loop). Test the kill switch before the first live run of each scenario.
8. **Scenario C (service disruption).** Time-boxed, rate-capped, only against the simulated PIS / broker; a watchdog restores the service; never run it unattended the first time.
9. **Reproducibility.** Tools and versions are pinned and listed in the scenario doc; every run produces a manifest and a ground-truth row through `recorder.run_scenario`.
10. **Purpose and disclosure.** Scenarios exist to be *detected and mitigated* (defensive purpose). Do not publish runners outside the team/course.
11. **When in doubt, ask in the PR before running.**
