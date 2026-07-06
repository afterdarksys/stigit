import Foundation
import StigItCore

// MARK: - Exit codes

/// The CLI's contract with automation: green, findings, or broken.
enum ExitCode {
    static let success: Int32 = 0     // compliant, or findings below the --fail-on gate
    static let findings: Int32 = 1    // unwaived findings at/above the --fail-on gate
    static let error: Int32 = 2       // usage or runtime error
}

// MARK: - Console

enum Console {
    /// Diagnostics and progress go to stderr so stdout stays clean for documents
    /// (JSON, JUnit, …) that pipelines consume.
    static func error(_ message: String) {
        FileHandle.standardError.write(Data((message + "\n").utf8))
    }
}

// MARK: - Argument scanning

struct ArgScanner {
    let tokens: [String]

    init(_ tokens: [String]) {
        self.tokens = tokens
    }

    func value(for flag: String) -> String? {
        guard let idx = tokens.firstIndex(of: flag), idx + 1 < tokens.count else { return nil }
        return tokens[idx + 1]
    }

    func has(_ flag: String) -> Bool {
        tokens.contains(flag)
    }

    /// Leading tokens that are not flags or flag values (e.g. the rule ID in `waiver add <id>`).
    var positionals: [String] {
        var result: [String] = []
        var skipNext = false
        for token in tokens {
            if skipNext { skipNext = false; continue }
            if token.hasPrefix("--") { skipNext = true; continue }
            result.append(token)
        }
        return result
    }
}

// MARK: - Shared option resolution

enum FailThreshold: String {
    case high, medium, low, any, none

    func gatedFailures(in report: ScanReport) -> [ScanReport.RuleResult] {
        switch self {
        case .none:   return []
        case .any:    return report.failures(atOrAbove: .na)
        case .low:    return report.failures(atOrAbove: .low)
        case .medium: return report.failures(atOrAbove: .medium)
        case .high:   return report.failures(atOrAbove: .high)
        }
    }
}

enum OutputFormat: String {
    case text, json, ndjson, junit

    var reportFormat: ReportExporter.Format? {
        switch self {
        case .text:   return nil
        case .json:   return .json
        case .ndjson: return .ndjson
        case .junit:  return .junit
        }
    }
}

struct ScanOptions {
    var profile: ComplianceProfile = .stig
    var severity: RuleSeverity?
    var rulesDir: String?
    var waiversPath: String?
    var format: OutputFormat = .text
    var quiet = false
    var export: ReportExporter.Format?
    var outputDir: String?
    var fleetDir: String?
    var saveHistory = false
    var compare = false
    var failOn: FailThreshold = .high

    /// Parses scan options shared by `scan` and `remediate`. Returns nil (after
    /// printing the problem) on an invalid value — the caller exits with a usage error.
    static func parse(_ args: ArgScanner) -> ScanOptions? {
        var options = ScanOptions()

        if let raw = args.value(for: "--profile") {
            guard let profile = resolveProfile(raw) else {
                Console.error("Unknown profile '\(raw)'. Valid: \(ComplianceProfile.allCases.map(\.key).joined(separator: " | "))")
                return nil
            }
            options.profile = profile
        }
        if let raw = args.value(for: "--severity") {
            guard let severity = RuleSeverity(rawValue: raw.capitalized), severity != .na else {
                Console.error("Unknown severity '\(raw)'. Valid: high | medium | low")
                return nil
            }
            options.severity = severity
        }
        if let raw = args.value(for: "--format") {
            guard let format = OutputFormat(rawValue: raw.lowercased()) else {
                Console.error("Unknown format '\(raw)'. Valid: text | json | ndjson | junit")
                return nil
            }
            options.format = format
        }
        if let raw = args.value(for: "--export") {
            guard let format = ReportExporter.Format(rawValue: raw.lowercased()) else {
                Console.error("Unknown export format '\(raw)'. Valid: json | csv | summary | ndjson | junit")
                return nil
            }
            options.export = format
        }
        if let raw = args.value(for: "--fail-on") {
            guard let threshold = FailThreshold(rawValue: raw.lowercased()) else {
                Console.error("Unknown --fail-on value '\(raw)'. Valid: high | medium | low | any | none")
                return nil
            }
            options.failOn = threshold
        }
        options.rulesDir = args.value(for: "--rules-dir")
        options.waiversPath = args.value(for: "--waivers")
        options.outputDir = args.value(for: "--output")
        options.fleetDir = args.value(for: "--fleet-dir")
        options.quiet = args.has("--quiet") || args.has("-q")
        options.saveHistory = args.has("--history")
        options.compare = args.has("--compare")
        return options
    }

    static func resolveProfile(_ raw: String) -> ComplianceProfile? {
        // Accept the canonical key plus historical aliases.
        switch raw.lowercased() {
        case "nist800-53":          return .nist
        case "cmmc_lvl1":           return .cmmc1
        case "cmmc_lvl2":           return .cmmc2
        case "cis_lvl1":            return .cisL1
        case "cis_lvl2":            return .cisL2
        case "800-171":             return .nist171
        default:                    return ComplianceProfile.from(key: raw)
        }
    }
}

// MARK: - Shared pipeline pieces

@MainActor
enum CLIPipeline {

    /// Default rule library plus any YAML rules dir, ready for scanning.
    static func loadRules(rulesDir: String?, quiet: Bool) -> [Rule] {
        var rules = RuleStore.defaultRules()
        guard let rulesDir else { return rules }

        let dir = URL(fileURLWithPath: rulesDir)
        guard let extra = try? YAMLRuleLoader.loadRules(from: dir) else {
            Console.error("Warning: could not load rules from \(rulesDir)")
            return rules
        }
        let existing = Set(rules.map(\.id))
        let fresh = extra.filter { !existing.contains($0.id) }
        rules += fresh
        if !quiet {
            Console.error("Loaded \(fresh.count) additional rules from \(rulesDir)")
        }
        return rules
    }

    /// Loads the waiver store, failing hard on a malformed file: silently dropping
    /// waivers would flip every waived finding back to a failure in CI.
    static func loadWaivers(path: String?) throws -> WaiverStore {
        if let path {
            return try WaiverStore.load(from: URL(fileURLWithPath: path))
        }
        return try WaiverStore.load()
    }

    /// Scans the rules matching profile/severity and returns the filtered, scanned set.
    static func scan(rules: inout [Rule], options: ScanOptions) async -> [Rule] {
        let profile = options.profile
        let severity = options.severity
        let matches: @Sendable (Rule) -> Bool = { rule in
            rule.profiles.contains(profile)
                && (severity == nil || rule.severity == severity)
        }
        let showProgress = options.format == .text && !options.quiet
        let total = rules.filter(matches).count
        if showProgress {
            Console.error("Scanning \(total) rules (\(options.profile.rawValue))…")
        }
        await ScannerService.scan(rules: &rules, where: matches) { done, of in
            if showProgress {
                FileHandle.standardError.write(Data("\r  \(done)/\(of)".utf8))
            }
        }
        if showProgress {
            FileHandle.standardError.write(Data("\r".utf8))
        }
        return rules.filter(matches)
    }

    /// Builds the report, then applies drift/history/fleet side-effects per options.
    static func buildReport(
        scannedRules: [Rule],
        options: ScanOptions,
        waivers: WaiverStore
    ) -> ScanReport {
        var report = ScanReport(rules: scannedRules, profile: options.profile, waivers: waivers)

        if options.compare,
           let baseline = ScanHistoryService.latest(profileKey: options.profile.key) {
            report.drift = ScanHistoryService.drift(from: baseline, to: report)
        }
        if options.saveHistory {
            do { try ScanHistoryService.save(report) }
            catch { Console.error("Warning: could not save scan history: \(error.localizedDescription)") }
        }
        if let fleetDir = options.fleetDir {
            do {
                let url = try FleetService.publish(report, to: URL(fileURLWithPath: fleetDir))
                if options.format == .text && !options.quiet {
                    Console.error("Fleet report published: \(url.path)")
                }
            } catch {
                Console.error("Warning: could not publish fleet report: \(error.localizedDescription)")
            }
        }
        return report
    }

    /// Emits the report per --format/--export and returns the gated exit code.
    static func emit(report: ScanReport, options: ScanOptions) -> Int32 {
        if let format = options.format.reportFormat {
            if let document = try? ReportExporter.export(report: report, format: format) {
                print(document)
            }
        } else {
            printText(report: report, quiet: options.quiet)
        }

        if let exportFormat = options.export {
            let dir = options.outputDir.map { URL(fileURLWithPath: $0) }
                ?? ReportExporter.defaultOutputDirectory()
            do {
                let url = try ReportExporter.write(report: report, format: exportFormat, to: dir)
                Console.error("Report written to: \(url.path)")
            } catch {
                Console.error("Export failed: \(error.localizedDescription)")
                return ExitCode.error
            }
        }

        let gated = options.failOn.gatedFailures(in: report)
        return gated.isEmpty ? ExitCode.success : ExitCode.findings
    }

    // MARK: - Text rendering

    private static func printText(report: ScanReport, quiet: Bool) {
        let summary = report.summary
        if !quiet {
            for severity in [RuleSeverity.high, .medium, .low] {
                let group = report.results.filter { $0.severity == severity && $0.outcome != .unknown }
                guard !group.isEmpty else { continue }
                print("── \(severity.rawValue.uppercased()) ──────────────────────────────────────────────")
                for result in group {
                    let marker: String
                    switch result.outcome {
                    case .compliant:    marker = "[PASS]"
                    case .nonCompliant: marker = "[FAIL]"
                    case .waived:       marker = "[WAIV]"
                    case .unknown:      marker = "[----]"
                    case .error:        marker = "[ERR ]"
                    }
                    let stig = result.stigId.map { " [\($0)]" } ?? ""
                    let line = "\(result.title)\(stig)"
                    print("  \(marker)  \(line.count > 60 ? String(line.prefix(59)) + "…" : line)")
                }
                print()
            }
        }

        print(String(
            format: "Score: %.1f%%  (%d pass / %d fail / %d waived / %d not evaluated)",
            summary.score * 100, summary.compliant, summary.nonCompliant,
            summary.waived, summary.unknown + summary.errors
        ))

        if let drift = report.drift {
            if drift.regressions.isEmpty && drift.fixes.isEmpty {
                print("Drift: none since last scan")
            } else {
                print("Drift since last scan: \(drift.regressions.count) regression(s), \(drift.fixes.count) fixed")
                for change in drift.regressions {
                    print("  [REGRESSED] \(change.title) (\(change.severity.rawValue))")
                }
            }
        }
    }
}
