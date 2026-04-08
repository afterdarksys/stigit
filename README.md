# StigIt

A macOS security compliance scanner and remediation tool for enterprises, government agencies, and high-security environments. StigIt audits a macOS endpoint against industry security frameworks, generates audit-ready compliance reports, and applies remediations — either interactively via a native macOS app or headlessly via a CLI suitable for deployment pipelines and MDM workflows.

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
│   │   │   ├── Rule.swift       # Rule model, enums (severity, profiles, categories, result types)
│   │   │   └── RuleStore.swift  # Observable store, 60+ default rules
│   │   └── Services/
│   │       ├── ScannerService.swift         # Parallel scan via TaskGroup
│   │       ├── RemediationService.swift     # Executes fixes via AppleScript (admin priv)
│   │       ├── ReportExporter.swift         # JSON / CSV / summary report generation
│   │       ├── MobileConfigGenerator.swift  # Apple .mobileconfig XML for MDM
│   │       ├── YAMLRuleLoader.swift         # Runtime YAML rule ingestion (Yams)
│   │       └── BackupRestoreService.swift   # Pre-remediation snapshots + restore
│   ├── StigIt/                  # SwiftUI macOS app
│   │   └── Views/
│   │       ├── ContentView.swift
│   │       ├── DashboardView.swift
│   │       ├── StandardWorkflowView.swift
│   │       ├── StagingView.swift
│   │       ├── StagingModalView.swift
│   │       ├── RulesView.swift
│   │       └── BackupsView.swift
│   └── StigItCLI/               # Headless CLI
│       └── StigItCLI.swift
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
swift run stigit-cli --profile stig
```

---

## macOS App

The SwiftUI app provides a tab-per-profile workspace with:

- **Dashboard** — compliance score gauge, severity breakdown chart (high/medium/low pass rates), profile picker, one-click full scan with live progress bar, last scan timestamp
- **Category sidebar** — rules grouped by category with red badge counts for non-compliant rules
- **Rule list** — each rule shows its compliance status, color-coded severity badge (HIGH / MEDIUM / LOW), STIG ID, CCE ID, NIST control references, and MDM-deployable indicator
- **Severity filter chips** — filter the rule list to High / Medium / Low within any category
- **Staging** — review the shell commands that will be executed before committing to remediation
- **Apply Now** — submits remediation commands via AppleScript administrator privileges prompt
- **Export menu** — export JSON, CSV, or plain-text summary reports; generate a `.mobileconfig` profile directly from the toolbar
- **Backups** — create named pre-remediation snapshots to `~/.stigit/backups/`, list and restore existing backups

---

## CLI

```
USAGE: stigit-cli [OPTIONS]

SCAN OPTIONS:
  --profile <name>      Compliance profile (default: stig)
                        stig | nist | soc2 | iso27001 | gdpr |
                        cmmc1 | cmmc2 | cis1 | cis2 | cnssi | nist171 | other
  --severity <level>    Filter to rules of a single severity: high | medium | low
  --rules-dir <path>    Load additional rules from a YAML rules directory
                        (e.g. /path/to/macos_security/rules)

REMEDIATION OPTIONS:
  --remediate           Apply fixes for all failing rules (triggers macOS auth prompt)
  --backup              Snapshot system config to ~/.stigit/backups/ before remediating

EXPORT OPTIONS:
  --export <format>     Write a report: json | csv | summary
  --output <path>       Output directory (default: ~/.stigit/reports/)

MDM OPTIONS:
  --generate-mobileconfig          Generate a .mobileconfig profile
  --org-name <name>                Organisation name in the profile metadata
  --profile-identifier <id>        Reverse-DNS identifier (default: com.stigit.baseline)
```

### Examples

```bash
# Scan against DISA STIG and print results
stigit-cli --profile stig

# Scan only high-severity CMMC Level 2 rules
stigit-cli --profile cmmc2 --severity high

# Export a JSON report
stigit-cli --profile nist --export json

# Scan, backup, then auto-remediate
stigit-cli --profile stig --backup --remediate

# Generate an MDM configuration profile
stigit-cli --profile stig --generate-mobileconfig \
  --org-name "Acme Corp" \
  --profile-identifier "com.acme.stig-baseline"

# Load all 280+ rules from the macos_security reference
stigit-cli --profile stig \
  --rules-dir ./reference/macos_security/rules
```

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
stigit-cli --profile stig \
  --generate-mobileconfig \
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

### JSON
Full machine-readable report with per-rule status, STIG IDs, CCE IDs, CCI IDs, NIST controls, severity, and MDM flag. Suitable for ingestion into SIEM systems or compliance dashboards.

### CSV
Tabular format for import into Excel, Numbers, or compliance tracking spreadsheets.

### Summary
Plain-text executive summary showing overall score, findings grouped by severity, and passing controls. Designed for email or ticketing system attachments.

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
