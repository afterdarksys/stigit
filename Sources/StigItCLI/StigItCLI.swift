import Foundation
import StigItCore

// MARK: - Argument parsing helpers

private func arg(after flag: String) -> String? {
    guard let idx = CommandLine.arguments.firstIndex(of: flag),
          idx + 1 < CommandLine.arguments.count else { return nil }
    return CommandLine.arguments[idx + 1]
}

private func hasFlag(_ flag: String) -> Bool {
    CommandLine.arguments.contains(flag)
}

// MARK: - Usage

private func printUsage() {
    print("""
    StigIt CLI – macOS Security Compliance Scanner
    ================================================
    USAGE: stigit-cli [OPTIONS]

    SCAN OPTIONS:
      --profile <name>      Compliance profile to scan  (default: stig)
                            Values: stig | nist | soc2 | iso27001 | gdpr |
                                    cmmc1 | cmmc2 | cis1 | cis2 | cnssi | nist171 | other
      --severity <level>    Filter rules by severity: high | medium | low
      --rules-dir <path>    Load additional rules from a YAML rules directory
                            (e.g., /path/to/macos_security/rules)

    REMEDIATION OPTIONS:
      --remediate           Auto-apply remediations for all failing rules (requires sudo)
      --backup              Create a backup before remediating (recommended)

    EXPORT OPTIONS:
      --export <format>     Export scan results: json | csv | summary
      --output <path>       Directory to write the report (default: ~/.stigit/reports)

    MDM OPTIONS:
      --generate-mobileconfig          Generate an MDM .mobileconfig profile
      --org-name <name>                Organisation name embedded in the profile
      --profile-identifier <id>        Reverse-DNS profile ID (default: com.stigit.baseline)

    OTHER:
      --help                Show this help message
    """)
}

// MARK: - Main

@main
struct StigItCLIRunner {
    static func main() async {
        if hasFlag("--help") || hasFlag("-h") {
            printUsage()
            return
        }

        print("StigIt CLI  –  macOS Security Compliance Scanner")
        print("==================================================\n")

        // --- Resolve compliance profile ---
        let profileStr = arg(after: "--profile")?.lowercased() ?? "stig"
        let targetProfile: ComplianceProfile
        switch profileStr {
        case "nist", "nist800-53":     targetProfile = .nist
        case "soc2":                   targetProfile = .soc2
        case "iso27001":               targetProfile = .iso27001
        case "gdpr":                   targetProfile = .gdpr
        case "cmmc1", "cmmc_lvl1":     targetProfile = .cmmc1
        case "cmmc2", "cmmc_lvl2":     targetProfile = .cmmc2
        case "cis1",  "cis_lvl1":      targetProfile = .cisL1
        case "cis2",  "cis_lvl2":      targetProfile = .cisL2
        case "cnssi", "cnssi-1253":    targetProfile = .cnssi
        case "nist171", "800-171":     targetProfile = .nist171
        case "other":                  targetProfile = .other
        default:                       targetProfile = .stig
        }

        // --- Severity filter ---
        let severityFilter: RuleSeverity? = {
            switch arg(after: "--severity")?.lowercased() {
            case "high":   return .high
            case "medium": return .medium
            case "low":    return .low
            default:       return nil
            }
        }()

        // --- Build rule store ---
        let store = RuleStore()

        // Optionally load additional rules from a YAML directory
        if let rulesPath = arg(after: "--rules-dir") {
            let dir = URL(fileURLWithPath: rulesPath)
            print("Loading rules from: \(rulesPath)")
            if let extra = try? YAMLRuleLoader.loadRules(from: dir) {
                let before = store.rules.count
                // Merge – skip rules whose IDs already exist
                let existingIDs = Set(store.rules.map(\.id))
                let newRules = extra.filter { !existingIDs.contains($0.id) }
                store.rules += newRules
                print("Loaded \(newRules.count) additional rules (skipped \(extra.count - newRules.count) duplicates)\n")
                _ = before
            } else {
                print("Warning: could not load YAML rules from \(rulesPath)\n")
            }
        }

        store.activeProfile = targetProfile
        var profileRules = store.activeRules
        if let sv = severityFilter {
            profileRules = profileRules.filter { $0.severity == sv }
        }

        print("Profile  : \(targetProfile.rawValue)")
        if let sv = severityFilter { print("Severity : \(sv.rawValue) only") }
        print("Rules    : \(profileRules.count)\n")

        // --- Backup ---
        if hasFlag("--backup") || hasFlag("--remediate") {
            print("Creating backup before scan/remediation...")
            let result = await BackupRestoreService.createBackup()
            switch result {
            case .success(let url):
                print("Backup saved to: \(url.path)\n")
            case .failure(let err):
                print("Warning: backup failed – \(err.localizedDescription)\n")
            }
        }

        // --- Scan ---
        print("Scanning \(profileRules.count) rules concurrently...\n")
        let start = Date()
        let total = profileRules.count

        // Scan using the full store.rules array but filter to profile
        await ScannerService.scan(rules: &store.rules, profile: targetProfile) { done, of in
            let pct = Int(Double(done) / Double(of) * 100)
            print("\r  Progress: \(pct)% (\(done)/\(of))", terminator: "")
            fflush(stdout)
        }
        print("\r  Complete: 100% (\(total)/\(total))          ")

        let elapsed = String(format: "%.1f", Date().timeIntervalSince(start))
        print("\nScan completed in \(elapsed)s")

        // Re-derive filtered rules after scan
        let scannedRules = store.rules.filter { rule in
            rule.profiles.contains(targetProfile) &&
            (severityFilter == nil || rule.severity == severityFilter)
        }

        let compliant    = scannedRules.filter { $0.status == .compliant }
        let score        = scannedRules.isEmpty ? 0.0 :
            Double(compliant.count) / Double(scannedRules.count) * 100

        print(String(format: "\nScore: %.1f%%  (%d/%d compliant)\n", score, compliant.count, scannedRules.count))

        // --- Print results table ---
        printResultsTable(rules: scannedRules)

        // --- Export report ---
        if let fmt = arg(after: "--export") {
            let format: ReportExporter.Format
            switch fmt.lowercased() {
            case "json":    format = .json
            case "csv":     format = .csv
            default:        format = .summary
            }
            let outputDir = arg(after: "--output")
                .map { URL(fileURLWithPath: $0) }
                ?? ReportExporter.defaultOutputDirectory()
            do {
                let url = try ReportExporter.write(
                    rules: store.rules, profile: targetProfile, format: format, to: outputDir
                )
                print("\nReport written to: \(url.path)")
            } catch {
                print("\nError writing report: \(error)")
            }
        }

        // --- Generate .mobileconfig ---
        if hasFlag("--generate-mobileconfig") {
            let orgName  = arg(after: "--org-name") ?? "Your Organization"
            let profId   = arg(after: "--profile-identifier") ?? "com.stigit.baseline"
            let outputDir = arg(after: "--output")
                .map { URL(fileURLWithPath: $0) }
                ?? MobileConfigGenerator.defaultOutputDirectory()
            do {
                let url = try MobileConfigGenerator.write(
                    rules: store.rules,
                    profile: targetProfile,
                    orgName: orgName,
                    profileIdentifier: profId,
                    to: outputDir
                )
                print("\nMobileConfig profile written to: \(url.path)")
            } catch {
                print("\nError writing mobileconfig: \(error)")
            }
        }

        // --- Remediate ---
        if hasFlag("--remediate") {
            let failing = scannedRules.filter { $0.status == .nonCompliant }
            if failing.isEmpty {
                print("\nNo remediations needed – all scanned rules are compliant.")
            } else {
                print("\nApplying \(failing.count) remediations...")
                let ok = await RemediationService.submit(rules: store.rules.filter {
                    $0.profiles.contains(targetProfile) && $0.status == .nonCompliant
                })
                if ok {
                    print("Remediations applied successfully.")
                    print("Re-running scan to verify...\n")
                    await ScannerService.scan(rules: &store.rules, profile: targetProfile)
                    let after = store.activeRules.filter { $0.status == .compliant }.count
                    print(String(format: "Post-remediation score: %.1f%% (%d/%d compliant)",
                                 Double(after) / Double(store.activeRules.count) * 100,
                                 after, store.activeRules.count))
                } else {
                    print("Remediation failed or was cancelled.")
                }
            }
        }
    }

    // MARK: - Helpers

    private static func printResultsTable(rules: [Rule]) {
        let colWidth = 52
        let high    = rules.filter { $0.severity == .high }
        let medium  = rules.filter { $0.severity == .medium }
        let low     = rules.filter { $0.severity == .low }

        for (group, label) in [(high, "HIGH"), (medium, "MEDIUM"), (low, "LOW")] {
            guard !group.isEmpty else { continue }
            print("── \(label) SEVERITY ──────────────────────────────────────────────")
            for rule in group {
                let marker = rule.status == .compliant ? "[PASS]" : "[FAIL]"
                let stig   = rule.stigId.map { " [\($0)]" } ?? ""
                let title  = rule.title + stig
                let truncated = title.count > colWidth ? String(title.prefix(colWidth - 1)) + "…" : title
                print("  \(marker)  \(truncated)")
            }
            print()
        }
    }
}
