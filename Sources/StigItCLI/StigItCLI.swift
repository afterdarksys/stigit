import Foundation
import StigItCore

@MainActor
@main
struct StigItCLI {

    static func main() async {
        if hasFlag("--help") || hasFlag("-h") { printUsage(); return }

        print("StigIt CLI  –  macOS Security Compliance Scanner")
        print("==================================================\n")

        let profile       = resolveProfile()
        let severity      = resolveSeverity()
        let store         = RuleStore()

        loadExtraRules(into: store)

        store.activeProfile = profile
        let target = store.rules.filter { $0.profiles.contains(profile) && (severity == nil || $0.severity == severity) }

        print("Profile  : \(profile.rawValue)")
        if let sv = severity { print("Severity : \(sv.rawValue) only") }
        print("Rules    : \(target.count)\n")

        if hasFlag("--backup") || hasFlag("--remediate") { await runBackup() }

        await runScan(store: store, profile: profile)

        let scanned = store.rules.filter {
            $0.profiles.contains(profile) && (severity == nil || $0.severity == severity)
        }
        printResults(scanned)

        if let fmt = arg(after: "--export")  { await runExport(store: store, profile: profile, fmt: fmt) }
        if hasFlag("--generate-mobileconfig") { runMobileConfig(store: store, profile: profile) }
        if hasFlag("--remediate")             { await runRemediation(store: store, profile: profile) }
    }

    // MARK: - Steps

    private static func runScan(store: RuleStore, profile: ComplianceProfile) async {
        let total = store.rules.filter { $0.profiles.contains(profile) }.count
        print("Scanning \(total) rules concurrently…\n")
        let start = Date()
        var snapshot = store.rules
        await ScannerService.scan(rules: &snapshot, profile: profile) { done, of in
            let pct = Int(Double(done) / Double(of) * 100)
            print("\r  Progress: \(pct)% (\(done)/\(of))", terminator: "")
            fflush(stdout)
        }
        store.rules = snapshot
        print("\r  Complete: 100% (\(total)/\(total))          ")
        print(String(format: "Scan finished in %.1fs", Date().timeIntervalSince(start)))

        let compliant = store.activeRules.filter { $0.status == .compliant }.count
        print(String(format: "\nScore: %.1f%%  (%d/%d compliant)\n",
                     Double(compliant) / Double(max(store.activeRules.count, 1)) * 100,
                     compliant, store.activeRules.count))
    }

    private static func runBackup() async {
        print("Creating backup…")
        switch await BackupRestoreService.createBackup() {
        case .success(let url): print("Backup saved to: \(url.path)\n")
        case .failure(let err): print("Warning: backup failed – \(err.localizedDescription)\n")
        }
    }

    private static func runExport(store: RuleStore, profile: ComplianceProfile, fmt: String) async {
        let format: ReportExporter.Format = switch fmt.lowercased() {
        case "json":    .json
        case "csv":     .csv
        default:        .summary
        }
        let dir = arg(after: "--output").map { URL(fileURLWithPath: $0) }
            ?? ReportExporter.defaultOutputDirectory()
        do {
            let url = try ReportExporter.write(rules: store.rules, profile: profile, format: format, to: dir)
            print("Report written to: \(url.path)")
        } catch {
            print("Export failed: \(error)")
        }
    }

    private static func runMobileConfig(store: RuleStore, profile: ComplianceProfile) {
        let orgName = arg(after: "--org-name")            ?? "Your Organization"
        let profId  = arg(after: "--profile-identifier") ?? "com.stigit.baseline"
        let dir     = arg(after: "--output").map { URL(fileURLWithPath: $0) }
            ?? MobileConfigGenerator.defaultOutputDirectory()
        do {
            let url = try MobileConfigGenerator.write(
                rules: store.rules, profile: profile,
                orgName: orgName, profileIdentifier: profId, to: dir
            )
            print("MobileConfig written to: \(url.path)")
        } catch {
            print("MobileConfig generation failed: \(error)")
        }
    }

    private static func runRemediation(store: RuleStore, profile: ComplianceProfile) async {
        let failing = store.rules.filter { $0.profiles.contains(profile) && $0.status == .nonCompliant }
        guard !failing.isEmpty else { print("\nAll rules compliant – nothing to remediate."); return }

        print("\nApplying \(failing.count) remediations…")
        let ok = await RemediationService.submit(rules: failing)
        guard ok else { print("Remediation failed or was cancelled."); return }

        print("Applied. Re-scanning to verify…\n")
        var snapshot = store.rules
        await ScannerService.scan(rules: &snapshot, profile: profile)
        store.rules = snapshot
        let after = store.activeRules.filter { $0.status == .compliant }.count
        print(String(format: "Post-remediation score: %.1f%% (%d/%d)",
                     Double(after) / Double(max(store.activeRules.count, 1)) * 100,
                     after, store.activeRules.count))
    }

    private static func loadExtraRules(into store: RuleStore) {
        guard let path = arg(after: "--rules-dir") else { return }
        print("Loading rules from: \(path)")
        let dir = URL(fileURLWithPath: path)
        guard let extra = try? YAMLRuleLoader.loadRules(from: dir) else {
            print("Warning: could not load rules from \(path)\n"); return
        }
        let existingIDs = Set(store.rules.map(\.id))
        let fresh = extra.filter { !existingIDs.contains($0.id) }
        store.rules += fresh
        print("Loaded \(fresh.count) additional rules (skipped \(extra.count - fresh.count) duplicates)\n")
    }

    // MARK: - Output

    private static func printResults(_ rules: [Rule]) {
        for severity in [RuleSeverity.high, .medium, .low] {
            let group = rules.filter { $0.severity == severity }
            guard !group.isEmpty else { continue }
            print("── \(severity.rawValue.uppercased()) ──────────────────────────────────────────────────")
            for rule in group {
                let marker = rule.status == .compliant ? "[PASS]" : "[FAIL]"
                let stig   = rule.stigId.map { " [\($0)]" } ?? ""
                let line   = "\(rule.title)\(stig)"
                print("  \(marker)  \(line.count > 55 ? String(line.prefix(54)) + "…" : line)")
            }
            print()
        }
    }

    // MARK: - Arg parsing

    private static func resolveProfile() -> ComplianceProfile {
        switch arg(after: "--profile")?.lowercased() {
        case "nist", "nist800-53":   return .nist
        case "soc2":                 return .soc2
        case "iso27001":             return .iso27001
        case "gdpr":                 return .gdpr
        case "cmmc1", "cmmc_lvl1":  return .cmmc1
        case "cmmc2", "cmmc_lvl2":  return .cmmc2
        case "cis1",  "cis_lvl1":   return .cisL1
        case "cis2",  "cis_lvl2":   return .cisL2
        case "cnssi":                return .cnssi
        case "nist171", "800-171":  return .nist171
        case "other":                return .other
        default:                     return .stig
        }
    }

    private static func resolveSeverity() -> RuleSeverity? {
        switch arg(after: "--severity")?.lowercased() {
        case "high":   return .high
        case "medium": return .medium
        case "low":    return .low
        default:       return nil
        }
    }

    private static func arg(after flag: String) -> String? {
        guard let idx = CommandLine.arguments.firstIndex(of: flag),
              idx + 1 < CommandLine.arguments.count else { return nil }
        return CommandLine.arguments[idx + 1]
    }

    private static func hasFlag(_ flag: String) -> Bool {
        CommandLine.arguments.contains(flag)
    }

    // MARK: - Usage

    private static func printUsage() {
        print("""
        StigIt CLI – macOS Security Compliance Scanner
        ================================================
        USAGE: stigit-cli [OPTIONS]

        SCAN:
          --profile <name>      stig|nist|cmmc1|cmmc2|cis1|cis2|cnssi|nist171|other (default: stig)
          --severity <level>    high | medium | low
          --rules-dir <path>    Load extra YAML rules from a directory

        REMEDIATION:
          --remediate           Apply fixes for failing rules
          --backup              Snapshot config to ~/.stigit/backups/ first

        EXPORT:
          --export <format>     json | csv | summary
          --output <path>       Output directory (default: ~/.stigit/reports/)

        MDM:
          --generate-mobileconfig
          --org-name <name>
          --profile-identifier <id>
        """)
    }
}
