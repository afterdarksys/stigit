import Foundation

/// Generates compliance scan reports in multiple formats for audit trail and regulatory submission.
public enum ReportExporter {

    public enum Format {
        case json
        case csv
        case summary   // plain-text executive summary
    }

    // MARK: - Public

    public static func export(rules: [Rule], profile: ComplianceProfile, format: Format) throws -> String {
        let scanned = rules.filter { $0.profiles.contains(profile) }
        switch format {
        case .json:    return try exportJSON(rules: scanned, profile: profile)
        case .csv:     return exportCSV(rules: scanned, profile: profile)
        case .summary: return exportSummary(rules: scanned, profile: profile)
        }
    }

    /// Write a report to disk.  Returns the URL of the written file.
    @discardableResult
    public static func write(
        rules: [Rule],
        profile: ComplianceProfile,
        format: Format,
        to directory: URL = ReportExporter.defaultOutputDirectory()
    ) throws -> URL {
        let content = try export(rules: rules, profile: profile, format: format)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let ext: String
        switch format {
        case .json:    ext = "json"
        case .csv:     ext = "csv"
        case .summary: ext = "txt"
        }

        let timestamp = ISO8601DateFormatter().string(from: Date())
            .replacingOccurrences(of: ":", with: "-")
        let name = "stigit_\(profile.id.lowercased().replacingOccurrences(of: " ", with: "_"))_\(timestamp).\(ext)"
        let url = directory.appendingPathComponent(name)
        try content.write(to: url, atomically: true, encoding: .utf8)
        return url
    }

    // MARK: - JSON

    private static func exportJSON(rules: [Rule], profile: ComplianceProfile) throws -> String {
        let report = JSONReport(
            generatedAt: ISO8601DateFormatter().string(from: Date()),
            profile: profile.rawValue,
            totalRules: rules.count,
            compliantCount: rules.filter { $0.status == .compliant }.count,
            nonCompliantCount: rules.filter { $0.status == .nonCompliant }.count,
            unknownCount: rules.filter { $0.status == .unknown }.count,
            complianceScore: rules.isEmpty ? 0 :
                Double(rules.filter { $0.status == .compliant }.count) / Double(rules.count),
            rules: rules.map { JSONRuleRecord(from: $0) }
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(report)
        return String(data: data, encoding: .utf8) ?? ""
    }

    // MARK: - CSV

    private static func exportCSV(rules: [Rule], profile: ComplianceProfile) -> String {
        var lines: [String] = []
        let header = [
            "Rule ID", "Title", "Category", "Severity",
            "Status", "STIG ID", "CCE ID", "CCI IDs", "NIST Controls",
            "Profile", "MobileConfig"
        ].joined(separator: ",")
        lines.append(header)

        for rule in rules {
            let row: [String] = [
                csvEscape(rule.id),
                csvEscape(rule.title),
                csvEscape(rule.category.rawValue),
                csvEscape(rule.severity.rawValue),
                csvEscape(rule.status.rawValue),
                csvEscape(rule.stigId ?? ""),
                csvEscape(rule.cceId ?? ""),
                csvEscape(rule.cciIds.joined(separator: "; ")),
                csvEscape(rule.nistControls.joined(separator: "; ")),
                csvEscape(profile.rawValue),
                csvEscape(rule.mobileconfig ? "Yes" : "No")
            ]
            lines.append(row.joined(separator: ","))
        }
        return lines.joined(separator: "\n")
    }

    private static func csvEscape(_ value: String) -> String {
        if value.contains(",") || value.contains("\"") || value.contains("\n") {
            return "\"" + value.replacingOccurrences(of: "\"", with: "\"\"") + "\""
        }
        return value
    }

    // MARK: - Summary

    private static func exportSummary(rules: [Rule], profile: ComplianceProfile) -> String {
        let compliant    = rules.filter { $0.status == .compliant }
        let nonCompliant = rules.filter { $0.status == .nonCompliant }
        let unknown      = rules.filter { $0.status == .unknown }
        let score = rules.isEmpty ? 0.0 :
            Double(compliant.count) / Double(rules.count) * 100

        var lines: [String] = []
        lines.append("=================================================")
        lines.append(" StigIt Compliance Report")
        lines.append(" Profile : \(profile.rawValue)")
        lines.append(" Date    : \(Date())")
        lines.append("=================================================")
        lines.append("")
        lines.append(String(format: " Score          : %.1f%%", score))
        lines.append(" Total Rules    : \(rules.count)")
        lines.append(" Compliant      : \(compliant.count)")
        lines.append(" Non-Compliant  : \(nonCompliant.count)")
        lines.append(" Unknown        : \(unknown.count)")
        lines.append("")

        // High-severity failures
        let highFailures = nonCompliant.filter { $0.severity == .high }
        if !highFailures.isEmpty {
            lines.append("----- HIGH SEVERITY FINDINGS (\(highFailures.count)) ------")
            for r in highFailures {
                let stig = r.stigId.map { " [\($0)]" } ?? ""
                lines.append("  [FAIL] \(r.title)\(stig)")
                if !r.nistControls.isEmpty {
                    lines.append("         NIST: \(r.nistControls.joined(separator: ", "))")
                }
            }
            lines.append("")
        }

        let medFailures = nonCompliant.filter { $0.severity == .medium }
        if !medFailures.isEmpty {
            lines.append("----- MEDIUM SEVERITY FINDINGS (\(medFailures.count)) -----")
            for r in medFailures {
                let stig = r.stigId.map { " [\($0)]" } ?? ""
                lines.append("  [FAIL] \(r.title)\(stig)")
            }
            lines.append("")
        }

        if !compliant.isEmpty {
            lines.append("----- PASSING CONTROLS (\(compliant.count)) ----------------")
            for r in compliant {
                lines.append("  [PASS] \(r.title)")
            }
        }
        lines.append("")
        lines.append("=================================================")
        return lines.joined(separator: "\n")
    }

    // MARK: - Helpers

    public static func defaultOutputDirectory() -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".stigit/reports")
    }

    // MARK: - Codable models for JSON

    private struct JSONReport: Encodable {
        let generatedAt: String
        let profile: String
        let totalRules: Int
        let compliantCount: Int
        let nonCompliantCount: Int
        let unknownCount: Int
        let complianceScore: Double
        let rules: [JSONRuleRecord]
    }

    private struct JSONRuleRecord: Encodable {
        let id: String
        let title: String
        let category: String
        let severity: String
        let status: String
        let stigId: String?
        let cceId: String?
        let cciIds: [String]
        let nistControls: [String]
        let mobileconfig: Bool

        init(from rule: Rule) {
            id           = rule.id
            title        = rule.title
            category     = rule.category.rawValue
            severity     = rule.severity.rawValue
            status       = rule.status.rawValue
            stigId       = rule.stigId
            cceId        = rule.cceId
            cciIds       = rule.cciIds
            nistControls = rule.nistControls
            mobileconfig = rule.mobileconfig
        }
    }
}
