# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Product

StigIt is a macOS security compliance scanner and remediation tool for enterprises, government agencies, and high-security environments. It audits a macOS endpoint against industry security frameworks (DISA STIG, NIST 800-53/800-171, CMMC, CIS, CNSSI-1253, SOC 2, ISO 27001, GDPR, and more), generates audit-ready compliance reports, and applies remediations — either interactively via a native macOS app or headlessly via a CLI suitable for MDM/pipeline deployment. It ships with 60+ built-in rules and can additionally load 280+ YAML rules at runtime from the [Apple/NIST macos_security project](https://github.com/usnistgov/macos_security), vendored as a git submodule under `reference/macos_security/`.

## Commands

This is a Swift 6.0 SwiftPM package targeting macOS 14+ (requires Xcode 16+ or the Swift 6.0 toolchain). There are no test targets defined in `Package.swift` — no `swift test`.

```bash
# Build both executables (StigIt.app-style GUI binary + stigit-cli)
swift build

# Release build
swift build -c release

# Run the CLI directly (subcommands: scan, remediate, waiver, fleet, schedule, mobileconfig, rules)
swift run stigit-cli scan --profile stig
swift run stigit-cli scan --profile stig --rules-dir ./reference/macos_security/rules
swift run stigit-cli help

# Run the SwiftUI management console
swift run StigIt
```

## Architecture

Three SwiftPM targets share one core library:

- **`StigItCore`** (`Sources/Shared/`) — the shared library, depends on Yams. Contains all models and services; both the GUI and CLI executables depend only on this and platform frameworks.
- **`StigIt`** (`Sources/StigIt/`) — SwiftUI macOS app, a sidebar console (Dashboard, per-profile workflow, Fleet, Waivers, Backups).
- **`StigItCLI`** (`Sources/StigItCLI/`) — automation-grade CLI with subcommand dispatch (`StigItCLI.swift`), shared arg parsing/exit codes (`CLISupport.swift`), and per-domain command groups (`ScanCommands.swift`, `ManagementCommands.swift`). A legacy flat-flag invocation style (`stigit-cli --profile stig --remediate`) is preserved via a shim in `StigItCLI.swift` for existing MDM scripts.

### Core data flow

1. **Rule library**: `RuleStore` (`Sources/Shared/Models/RuleStore.swift`) assembles the default rule set from per-category files under `Sources/Shared/Models/Rules/` (access control, authentication, network security, auditing, data protection, password policy, media controls, financial/healthcare, misc). Each `Rule` (`Rule.swift`) carries a check command, expected result, severity, category, applicable `ComplianceProfile`s, and STIG/CCE/CCI/NIST 800-53 metadata. `ComplianceProfile` maps human names to CLI profile keys (e.g. `stig`, `nist`, `cmmc2`) and to macos_security YAML tags.
2. **Extending the library at runtime**: `YAMLRuleLoader` ingests directories of YAML rules following the macos_security schema (e.g. `reference/macos_security/rules/`), handling `$ODV` substitution, AsciiDoc stripping from `fix:` fields, tag-to-profile mapping, and dedup against existing rule IDs. Rules without a `result:` block are skipped.
3. **Scanning**: `ScannerService` runs each rule's shell check command concurrently via `TaskGroup` and updates `RuleStatus` in place on the caller's rule array — this is the shared engine used by both the GUI (`RuleStore`-driven scans with progress) and the CLI scan pipeline in `CLISupport.swift`.
4. **Remediation**: `RemediationService` applies fixes for non-compliant, unwaived rules, either through an AppleScript elevation prompt (GUI/interactive CLI) or direct root execution (`--non-interactive`, for MDM/SSH). `BackupRestoreService` can snapshot key system config paths (SSH, PAM, audit config, preferences) to `~/.stigit/backups/<name>/` before remediation runs.
5. **Waivers**: `Waiver` records documented, time-boxed exceptions (approver, reason, ticket, expiry) in `~/.stigit/waivers.json`, shared between the CLI (`--waivers`) and the app's Waivers view. Waived findings are excluded from `--fail-on` gating but remain visible in reports; expired waivers automatically revert to findings.
6. **Reporting**: All output formats (JSON, CSV, NDJSON, JUnit XML, plain-text summary) render from one schema-versioned `ScanReport` (`Sources/Shared/Models/ScanReport.swift`) via `ReportExporter`, stamped with endpoint identity from `EndpointInfo` (hostname/serial/OS via IOKit/sysctl). `ScanHistoryService` persists scan snapshots to `~/.stigit/history/` for drift detection (`--compare`).
7. **Fleet aggregation**: `scan --fleet-dir <dir>` publishes one JSON report per host via `FleetService`; `fleet summarize <dir>` (and the app's Fleet view) roll these up into per-endpoint scores, high-severity counts, and stale-endpoint detection — no central server required.
8. **Scheduling & MDM**: `LaunchdScheduler` installs/removes a recurring LaunchDaemon/Agent scan (`schedule install|uninstall|status`). `MobileConfigGenerator` emits an Apple `.mobileconfig` XML profile for rules tagged `mobileconfig: true`, for deployment via Jamf/Intune/Mosyle/Kandji.

The GUI and CLI are two front ends over the same `StigItCore` engine: the app drives `RuleStore` reactively (`@Observable`) for live UI state, while the CLI drives the same services statelessly per invocation, with machine-readable output on stdout and diagnostics on stderr (exit codes: `0` compliant/below gate, `1` unwaived findings at/above `--fail-on`, `2` usage/runtime error).
