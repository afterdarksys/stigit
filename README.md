# StigIt

A macOS security compliance scanner and remediation tool for enterprises, government agencies, and high-security environments. StigIt audits a macOS endpoint against industry security frameworks, generates audit-ready compliance reports, and applies remediations — either interactively via a native macOS app or headlessly via a CLI suitable for deployment pipelines and MDM workflows.

## Why StigIt Exists

StigIt grew out of a government-contract environment where the standard endpoint
security workflow was designed around managed Windows machines, while a macOS
endpoint was required as an accessibility accommodation. The Mac still needed a
repeatable way to apply equivalent controls, expose failures, document exceptions,
and produce evidence that security and compliance teams could review.

StigIt is intended to close that operational gap. It combines macOS-focused checks,
framework metadata, deterministic automation, controlled remediation, waivers,
backups, and fleet reporting without requiring an organization to replace its MDM
or existing evidence pipeline.

### Compliance trust boundary

StigIt supports compliance assessment and evidence collection; it does not itself
certify an endpoint or organization as compliant. Strict environments should pair
it with version-matched, independently validated baselines, controlled rule
provenance, signed and notarized releases, MDM acceptance testing, change approval,
and the organization's normal authorization and risk-management process.

---

## Supported Compliance Frameworks

| Framework | Profile Key |
|---|---|
| DISA STIG for macOS | `stig` |
| NIST SP 800-53 Rev 5 | `nist` |
| NIST SP 800-171 Rev 3 | `nist171` |
| CMMC Level 1 | `cmmc1` |
| CMMC Level 2 | `cmmc2` |
| CIS Benchmark Level 1 | `cis1` |
| CIS Benchmark Level 2 | `cis2` |
| CNSSI-1253 | `cnssi` |
| SOC 2 | `soc2` |
| ISO/IEC 27001 | `iso27001` |
| GDPR | `gdpr` |
| OS Tweaks / Misc | `other` |

---

## Rule Coverage

StigIt ships with 60+ hardcoded rules drawn from the [Apple/NIST macos_security project](https://github.com/usnistgov/macos_security), organized into these categories:

**Access Control**
- Screensaver password enforcement and ≤15 minute idle timeout
- Guest account disabled
- Automatic login disabled
- Automatic session logout after 30 minutes
- Login window shows name and password fields (no username enumeration)

**Authentication**
- SSH password authentication disabled (key/cert only)
- SSH root login disabled
- SSHD `ClientAliveInterval` set to 900 seconds
- SSHD `ClientAliveCountMax` set to 0
- SSHD login grace time set to 30 seconds
- U.S. Government policy banner at SSH login (`/etc/banner`)
- SmartCard / PIV / CAC authentication enforced
- SmartCard required for `sudo` via PAM

**Network Security**
- Bluetooth disabled
- AirDrop disabled
- Application Firewall enabled
- Firewall stealth mode enabled
- Bonjour multicast advertising disabled
- Screen sharing / Apple Remote Desktop disabled
- Internet sharing disabled
- Printer sharing disabled
- Content caching disabled
- AirPlay receiver disabled
- Bluetooth file sharing disabled

**Auditing & Logging**
- `auditd` enabled and running
- Audit flags: `lo` (login/logout), `aa` (auth), `ad` (admin), `fd` (file deletion), `fm` (file attribute modification), `ex` (execution)
- Audit log retention configured to ≥7 days
- Audit storage capacity warning at 25%
- `audit_control` file permissions set to 0440

**Data Protection**
- FileVault full-disk encryption enforced with MDM lock (prevents user disable)
- System Integrity Protection (SIP) enabled
- Authenticated Root Volume enabled
- Gatekeeper enabled
- Gatekeeper user override disabled

**Password Policy**
- Minimum password length ≥15 characters
- Requires numeric character
- Requires special character
- Password history ≥5 previous passwords
- Maximum password age ≤60 days
- Account lockout after 3 consecutive failed attempts
- Account lockout duration ≥15 minutes

**Media Controls**
- Built-in camera disabled
- Blank Blu-Ray / CD / DVD media burning disabled
- Diagnostic and crash report submission to Apple disabled

**System Configuration**
- macOS software update current
- MDM enrollment verified

Each rule carries its full compliance metadata: DISA STIG ID (e.g. `APPL-26-001003`), CCE ID, CCI IDs, and NIST 800-53r5 control references.

---

## Architecture

```
StigIt/
├── Sources/
│   ├── Shared/                  # StigItCore library
│   │   ├── Models/
│   │   │   ├── Rule.swift          # Rule model, enums (severity, profiles, categories)
│   │   │   ├── RuleStore.swift     # Observable store, 60+ default rules
│   │   │   ├── ScanReport.swift    # Canonical schema-versioned scan result
│   │   │   ├── Waiver.swift        # Documented exceptions (approver, reason, expiry)
│   │   │   └── EndpointInfo.swift  # Host identity (hostname, serial, OS) via IOKit/sysctl
│   │   └── Services/
│   │       ├── ScannerService.swift         # Parallel scan via TaskGroup
│   │       ├── RemediationService.swift     # AppleScript prompt or direct root execution
│   │       ├── ReportExporter.swift         # JSON / CSV / summary / NDJSON / JUnit
│   │       ├── ScanHistoryService.swift     # Scan snapshots + drift detection
│   │       ├── FleetService.swift           # Endpoint report publish + fleet roll-up
│   │       ├── LaunchdScheduler.swift       # Recurring scans via LaunchDaemon/Agent
│   │       ├── MobileConfigGenerator.swift  # Apple .mobileconfig XML for MDM
│   │       ├── YAMLRuleLoader.swift         # Runtime YAML rule ingestion (Yams)
│   │       └── BackupRestoreService.swift   # Pre-remediation snapshots + restore
│   ├── StigIt/                  # SwiftUI macOS management console
│   │   └── Views/               # Sidebar shell, dashboard with trends, per-profile
│   │                            # workflow, FleetView, WaiversView, BackupsView
│   └── StigItCLI/               # Automation-grade CLI
│       ├── StigItCLI.swift          # Subcommand dispatch + legacy flag shim
│       ├── CLISupport.swift         # Arg parsing, exit codes, scan pipeline
│       ├── ScanCommands.swift       # scan / remediate
│       └── ManagementCommands.swift # waiver / fleet / schedule / mobileconfig / rules
└── reference/
    └── macos_security/          # Apple/NIST rule reference (git submodule)
        └── rules/               # 280+ YAML rule definitions
```

**Dependencies:** [Yams](https://github.com/jpsim/Yams) 5.x (YAML parsing for the runtime rule loader)

---

## Building

Requires Xcode 16+ or Swift 6.0 toolchain. Targets macOS 14+.

```bash
# Build both targets
swift build

# Build release binaries
swift build -c release

# Run the CLI directly
swift run stigit-cli scan --profile stig

# Run the regression suite
swift test
```

---

## macOS Management Console

The SwiftUI app is a sidebar-based console for ops teams:

- **Dashboard** — compliance score, severity breakdown, one-click full scan, and a compliance-over-time chart fed by the scan history shared with the CLI
- **Per-profile workflow** (This Mac) — category browser with failure badges, severity filter chips, per-rule STIG/CCE/NIST metadata, staged remediation review, and AppleScript-prompted Apply Now
- **Fleet** — point it at the directory endpoints publish reports into (`stigit-cli scan --fleet-dir …`) and get per-endpoint scores, high-severity failure counts, stale-endpoint flagging, and drill-down into any machine's open findings
- **Waivers** — create, review, and revoke documented exceptions (approver, reason, ticket, expiry); expired waivers are highlighted and automatically become findings again
- **Backups** — create named pre-remediation snapshots to `~/.stigit/backups/`, list and restore existing backups
- **Export menu** — JSON, CSV, or summary reports and `.mobileconfig` generation from the toolbar

---

## CLI

The CLI is built for automation: subcommands, deterministic exit codes, machine-readable
output on stdout, diagnostics on stderr.

```
USAGE: stigit-cli <command> [options]

COMMANDS:
  scan          Scan this machine against a compliance profile
  remediate     Scan, then apply fixes for unwaived failing rules
  waiver        Manage documented exceptions (list | add | remove)
  fleet         Aggregate endpoint reports (summarize <dir>)
  schedule      Manage the recurring launchd scan (install | uninstall | status)
  mobileconfig  Generate an MDM .mobileconfig profile
  rules         List the rule library (rules list)

SCAN / REMEDIATE OPTIONS:
  --profile <key>       stig | nist | nist171 | cmmc1 | cmmc2 | cis1 | cis2 |
                        cnssi | soc2 | iso27001 | gdpr | sox | hipaa | glba | other
  --severity <level>    high | medium | low
  --rules-dir <path>    Load YAML rules (macos_security schema); matching IDs replace
                        bundled rules
  --waivers <file>      Waiver file (default: ~/.stigit/waivers.json)
  --format <fmt>        text | json | ndjson | junit    (stdout format)
  --quiet, -q           Suppress per-rule output and progress
  --export <fmt>        Also write a report file: json | csv | summary | ndjson | junit
  --output <dir>        Report directory (default: ~/.stigit/reports/)
  --fleet-dir <dir>     Publish this endpoint's report into a fleet drop directory
  --history             Save this scan to ~/.stigit/history/
  --compare             Include drift vs. the previous saved scan
  --fail-on <level>     Exit 1 on unwaived findings at/above:
                        high (default) | medium | low | any | none

REMEDIATE-ONLY OPTIONS:
  --dry-run             Print the staged remediation script without executing
  --backup              Snapshot system config first
  --non-interactive     No GUI prompt; requires root (sudo / MDM)

EXIT CODES:
  0  compliant (or findings below --fail-on)
  1  unwaived findings at/above --fail-on
  2  usage or runtime error
```

Legacy flat-flag invocations (`stigit-cli --profile stig --remediate`) still work.

### Examples

```bash
# CI gate: fail the job on any unwaived high-severity finding
stigit-cli scan --profile stig --format junit --fail-on high > results.xml

# Nightly MDM script: scan, record history, publish to the fleet share
sudo stigit-cli scan --profile cis1 --quiet --history \
  --fleet-dir /Volumes/Compliance/fleet

# Auto-remediate headlessly (MDM / SSH), with a backup first
sudo stigit-cli remediate --profile stig --backup --non-interactive

# Record an approved exception with an expiry
stigit-cli waiver add os_ssh_root_login \
  --reason "break-glass account required by DR runbook" \
  --approved-by "J. Doe" --ticket SEC-142 --expires 2026-12-31

# What changed since the last recorded scan?
stigit-cli scan --profile stig --history --compare

# Ops roll-up across every Mac publishing into the share
stigit-cli fleet summarize /Volumes/Compliance/fleet --format csv

# Install a daily scheduled scan (LaunchDaemon when run as root)
sudo stigit-cli schedule install --interval daily --profile stig \
  --fleet-dir /Volumes/Compliance/fleet

# Load rules from a macos_security checkout matching this Mac's major OS version
stigit-cli scan --profile stig --rules-dir ./reference/macos_security/rules
```

YAML ingestion is intentionally fail-closed: an invalid directory, malformed rule,
empty compatible rule set, or rule whose `macOS` applicability excludes the current
major version stops the command instead of silently falling back. For STIG scans,
`odv.stig` values take precedence; other profiles use `odv.recommended` when present.

### Root and MDM execution

System rules execute as root during non-interactive remediation. Rules that inspect
or change per-user preferences are marked `console_user`; when StigIt itself runs as
root, those commands are executed through the currently logged-in console user. If
there is no safe console user, the rule fails closed instead of reading or writing
root's preferences. Multi-rule remediation scripts also stop at the first failure.

Backups use a structured manifest with exact source paths, validate backup names,
and only report success after every copy succeeds. Restores are restricted to known
system paths under the configured backup root.

### Waivers

A waiver is a documented, time-boxed exception: rule ID, reason, approver, optional
ticket, optional expiry. Waived rules stay visible in every report (marked `waived`)
but do not count against `--fail-on` gating or remediation. Expired waivers turn back
into findings and are flagged on scan. The waiver file (`~/.stigit/waivers.json`) is
shared between the CLI and the app's Waivers view, and can be checked into config
management and distributed with `--waivers`.

### Fleet reporting without a server

`scan --fleet-dir <dir>` writes the endpoint's full report as `<hostname>.json`
(atomic overwrite, one file per host) into a directory you sync however you already
move files — MDM script, scp, NFS/SMB share, S3 sync. `fleet summarize <dir>` and the
app's Fleet view aggregate it: per-endpoint score, high-severity failures, waived
counts, and stale endpoints that have stopped reporting (`--stale-days`, default 7).

---

## YAML Rule Loader

StigIt can ingest any directory of YAML rules following the [macos_security](https://github.com/usnistgov/macos_security) schema at runtime — no recompilation required.

```swift
let dir = URL(fileURLWithPath: "/path/to/macos_security/rules")
let extra = try YAMLRuleLoader.loadRules(from: dir)
store.rules += extra
```

The loader handles:
- `result.string`, `result.integer`, and `result.boolean` check types
- `$ODV` substitution using the rule's `recommended` or `stig` ODV value
- AsciiDoc source block stripping from `fix:` fields
- Tag-to-profile mapping (e.g. `stig` → `.stig`, `cmmc_lvl2` → `.cmmc2`)
- Category inference from directory name and rule ID prefix
- Deduplication against existing rule IDs

Rules that lack a `result:` block (informational/manual findings) are skipped automatically.

---

## MDM Deployment

For rules marked `mobileconfig: true`, StigIt can generate an Apple Configuration Profile containing the corresponding managed preference payloads. The profile can be deployed via any MDM solution.

Tested with:
- Jamf Pro
- Microsoft Intune
- Mosyle
- Kandji

```bash
stigit-cli mobileconfig --profile stig \
  --org-name "Department of Example" \
  --profile-identifier "gov.example.stig-macos"
```

Rules currently deliverable via MDM profile include: Application Firewall, Firewall Stealth Mode, Gatekeeper enforcement, Gatekeeper override disallow, FileVault MDM lock, Bonjour disable, Content Caching disable, AirPlay Receiver disable, SmartCard enforcement, Camera disable, optical media burning restrictions, and diagnostic report suppression.

---

## Backup & Restore

StigIt snapshots key system configuration paths before any remediation:

```
/Library/Preferences
/etc/ssh/sshd_config
/etc/ssh/sshd_config.d/
/etc/pam.d/
/etc/security/audit_control
/etc/security/audit_user
/private/etc/pam.d/sudo
/private/etc/pam.d/su
```

Backups are stored in `~/.stigit/backups/<name>/` with a `manifest.json` recording the timestamp. Restore is available both from the app (Backups tab) and programmatically via `BackupRestoreService.restore(from:)`.

---

## Compliance Report Output

All formats are rendered from the same schema-versioned `ScanReport`, stamped with the
endpoint's hostname, serial number, and OS version.

### JSON
Full machine-readable report: summary counts, per-rule outcome (including `waived`),
STIG/CCE/NIST metadata, applied waivers, and drift when `--compare` is used. Stable
`schemaVersion` field for downstream consumers.

### JUnit XML
One test case per rule — failures are unwaived findings, waived/unevaluated rules are
skips. Drop it into Jenkins, GitLab CI, GitHub Actions, or any test-report ingester.

### NDJSON
One JSON object per rule result with endpoint identity inlined, ready for log shippers
and SIEM pipelines (Splunk, Elastic, Datadog).

### CSV
Tabular format (now with outcome and waiver columns) for Excel, Numbers, or compliance
tracking spreadsheets.

### Summary
Plain-text executive summary: score, drift, findings by severity, waived findings with
approver and expiry, passing controls. Designed for email or ticketing attachments.

Reports are written to `~/.stigit/reports/` with ISO 8601 timestamps in the filename.

---

## Security Notes

- Remediation commands require administrator privileges. StigIt requests elevation via a macOS authentication dialog — it never stores credentials.
- Rules that modify SSH configuration write to `/etc/ssh/sshd_config.d/01-mscp-sshd.conf` following Apple's recommended drop-in pattern, preserving the base `sshd_config` file.
- SIP and Authenticated Root rules cannot be remediated from a running OS. StigIt surfaces these as informational findings with instructions to boot into Recovery Mode.
- Always create a backup before running `--remediate` in production.

---

## License

See [LICENSE](LICENSE).
