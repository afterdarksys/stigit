# StigIt Enterprise Overhaul — Design

**Date:** 2026-07-06
**Goal:** Make StigIt useful to enterprises: a CLI built for automation (MDM scripts, CI, cron) and a GUI that works as a management console for ops teams, not just a single-machine scanner.

## Problem

Today the CLI is a flat flag parser with no exit-code contract, human-only output, and an AppleScript auth prompt that blocks headless use. The GUI is a per-profile tab view of the local machine with no concept of exceptions, history, or other endpoints. Enterprises need:

1. **Automation** — deterministic exit codes, machine-readable output, non-interactive remediation, scheduled scans.
2. **Exception management** — auditors expect documented waivers (who approved, why, until when), not silently ignored findings.
3. **Drift visibility** — "what changed since the last scan" matters more than a point-in-time score.
4. **Fleet awareness** — ops teams manage many Macs; results must aggregate.

## Approach (phased, no server)

Chosen over (a) local-app-only polish and (b) a full client/server fleet product. A server is out of scope; instead endpoints write self-describing JSON reports to a shared drop directory (MDM/scp/NFS/S3-sync — transport is the customer's), and both CLI and GUI aggregate that directory. This delivers fleet visibility without new infrastructure, and a real server can be layered on later.

## Phase 1 — Core services (StigItCore)

- **EndpointInfo** — hostname, serial number, hardware model, OS version/build, collected once per run. Stamped into every report.
- **Waiver + WaiverStore** — JSON file (default `~/.stigit/waivers.json`, overridable) of `{ruleID, reason, approvedBy, ticket?, expires?}`. Applied post-scan: a non-compliant rule with an unexpired waiver is reported `waived` and never fails the exit-code gate. Expired waivers are flagged.
- **ScanRecord + ScanHistoryService** — compact per-scan snapshot (`~/.stigit/history/<profile>-<timestamp>.json`) with per-rule status; `drift(from:to:)` computes regressions (pass→fail) and fixes (fail→pass).
- **ScanReport** — the single canonical report model (endpoint + profile + counts + rule results + waivers + drift), replacing ad-hoc JSON in ReportExporter. Stable schema for automation.
- **FleetService** — write endpoint report into a fleet directory as `<hostname>.json` (atomic); aggregate a directory into a FleetSummary (per-endpoint score, high-severity failures, stale endpoints > N days).
- **LaunchdScheduler** — generate/install/uninstall a LaunchDaemon plist running `stigit-cli scan …` on an interval.
- **RemediationService** — add `executeDirect(rules:)` running `/bin/sh` directly when euid == 0, so `sudo stigit-cli remediate --non-interactive` works headlessly; AppleScript prompt remains for desktop use.
- **ReportExporter** — add JUnit XML (CI ingestion) and NDJSON (log shippers/SIEM) alongside JSON/CSV/summary; all formats now built from ScanReport.

## Phase 2 — CLI rewrite (stigit-cli)

Subcommand interface (hand-rolled, no new deps):

```
stigit-cli scan       [--profile P] [--severity S] [--rules-dir DIR] [--waivers FILE]
                      [--format text|json|ndjson|junit] [--quiet]
                      [--export FMT --output DIR] [--fleet-dir DIR]
                      [--history] [--compare] [--fail-on high|medium|low|any|none]
stigit-cli remediate  [scan opts] [--backup] [--non-interactive] [--dry-run]
stigit-cli waiver     list|add|remove …
stigit-cli fleet      summarize <dir> [--format …] [--stale-days N]
stigit-cli schedule   install|uninstall|status [--interval daily|hourly|weekly] [scan opts]
stigit-cli mobileconfig [--org-name N] [--profile-identifier ID]
stigit-cli rules      list [--profile P] [--format …]
```

Exit codes: **0** = compliant or below threshold; **1** = unwaived findings at/above `--fail-on` (default `high`); **2** = usage/runtime error. Legacy flat flags (`stigit-cli --profile stig --remediate`) keep working via a shim.

## Phase 3 — GUI management console

- **Sidebar navigation replaces the 15-profile tab row**: sections *This Mac* (per-profile workflow), *Fleet*, *Waivers*, *Backups*.
- **FleetView** — pick the fleet drop directory; table of endpoints (score, high fails, OS, last report, stale highlighting); drill into an endpoint's failing rules.
- **WaiversView** — CRUD on the waiver store with reason/approver/expiry; expired shown in red.
- **Dashboard** — adds score-over-time from ScanHistoryService and drift since last scan.

## Testing / verification

`swift build` for both targets; CLI smoke runs (`rules list`, `waiver add/list/remove`, `fleet summarize` on fixture JSON, `scan --format junit` schema sanity). GUI verified by compilation (no UI test harness in repo).

## Out of scope (deliberate)

Central server/API, agents pushing over the network, RBAC, non-macOS endpoints, notarized packaging.
