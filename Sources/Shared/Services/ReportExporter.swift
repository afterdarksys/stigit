import Foundation

/// Renders a `ScanReport` in formats for auditors (summary, CSV), automation (JSON,
/// JUnit for CI gates), and log pipelines (NDJSON for SIEM ingestion).
public enum ReportExporter {

    public enum Format: String, CaseIterable, Sendable {
        case json
        case csv
        case summary   // plain-text executive summary
        case ndjson    // one JSON object per rule result, for log shippers
        case junit     // JUnit XML, for CI systems

        public var fileExtension: String {
            switch self {
            case .json:    return "json"
            case .csv:     return "csv"
            case .summary: return "txt"
            case .ndjson:  return "ndjson"
            case .junit:   return "xml"
            }
        }
    }

    // MARK: - Public

    public static func export(report: ScanReport, format: Format) throws -> String {
        switch format {
        case .json:    return String(data: try report.jsonData(), encoding: .utf8) ?? ""
        case .csv:     return exportCSV(report)
        case .summary: return exportSummary(report)
        case .ndjson:  return try exportNDJSON(report)
        case .junit:   return exportJUnit(report)
        }
    }

    /// Write a report to disk. Returns the URL of the written file.
    @discardableResult
    public static func write(
        report: ScanReport,
        format: Format,
        to directory: URL = ReportExporter.defaultOutputDirectory()
    ) throws -> URL {
        let content = try export(report: report, format: format)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let timestamp = ISO8601DateFormatter().string(from: report.generatedAt)
            .replacingOccurrences(of: ":", with: "-")
        let name = "stigit_\(report.profileKey)_\(timestamp).\(format.fileExtension)"
        let url = directory.appendingPathComponent(name)
        try content.write(to: url, atomically: true, encoding: .utf8)
        return url
    }

    // MARK: - Legacy rule-array API (used by the GUI's export menu)

    public static func export(rules: [Rule], profile: ComplianceProfile, format: Format) throws -> String {
        try export(report: makeReport(rules: rules, profile: profile), format: format)
    }

    @discardableResult
    public static func write(
        rules: [Rule],
        profile: ComplianceProfile,
        format: Format,
        to directory: URL = ReportExporter.defaultOutputDirectory()
    ) throws -> URL {
        try write(report: makeReport(rules: rules, profile: profile), format: format, to: directory)
    }

    private static func makeReport(rules: [Rule], profile: ComplianceProfile) -> ScanReport {
        ScanReport(
            rules: rules,
            profile: profile,
            waivers: try? WaiverStore.load()
        )
    }

    // MARK: - CSV

    private static func exportCSV(_ report: ScanReport) -> String {
        var lines: [String] = []
        lines.append([
            "Rule ID", "Title", "Category", "Severity", "Outcome",
            "STIG ID", "CCE ID", "NIST Controls",
            "Waiver Reason", "Waiver Approved By", "Waiver Expires",
            "Profile", "Hostname",
        ].joined(separator: ","))

        let dateFormatter = ISO8601DateFormatter()
        for r in report.results {
            lines.append([
                csvEscape(r.id),
                csvEscape(r.title),
                csvEscape(r.category),
                csvEscape(r.severity.rawValue),
                csvEscape(r.outcome.rawValue),
                csvEscape(r.stigId ?? ""),
                csvEscape(r.cceId ?? ""),
                csvEscape(r.nistControls.joined(separator: "; ")),
                csvEscape(r.waiver?.reason ?? ""),
                csvEscape(r.waiver?.approvedBy ?? ""),
                csvEscape(r.waiver?.expiresAt.map { dateFormatter.string(from: $0) } ?? ""),
                csvEscape(report.profileName),
                csvEscape(report.endpoint.hostname),
            ].joined(separator: ","))
        }
        return lines.joined(separator: "\n")
    }

    private static func csvEscape(_ value: String) -> String {
        if value.contains(",") || value.contains("\"") || value.contains("\n") {
            return "\"" + value.replacingOccurrences(of: "\"", with: "\"\"") + "\""
        }
        return value
    }

    // MARK: - NDJSON

    private static func exportNDJSON(_ report: ScanReport) throws -> String {
        struct Line: Encodable {
            let generatedAt: Date
            let hostname: String
            let serialNumber: String?
            let profile: String
            let ruleID: String
            let title: String
            let category: String
            let severity: String
            let outcome: String
            let stigId: String?
            let nistControls: [String]
            let waivedBy: String?
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601

        return try report.results.map { r in
            let line = Line(
                generatedAt: report.generatedAt,
                hostname: report.endpoint.hostname,
                serialNumber: report.endpoint.serialNumber,
                profile: report.profileKey,
                ruleID: r.id,
                title: r.title,
                category: r.category,
                severity: r.severity.rawValue,
                outcome: r.outcome.rawValue,
                stigId: r.stigId,
                nistControls: r.nistControls,
                waivedBy: r.waiver?.approvedBy
            )
            return String(data: try encoder.encode(line), encoding: .utf8) ?? ""
        }.joined(separator: "\n")
    }

    // MARK: - JUnit XML

    private static func exportJUnit(_ report: ScanReport) -> String {
        let summary = report.summary
        var lines: [String] = []
        lines.append(#"<?xml version="1.0" encoding="UTF-8"?>"#)
        lines.append(
            #"<testsuite name="stigit.\#(xmlEscape(report.profileKey))" "#
            + #"hostname="\#(xmlEscape(report.endpoint.hostname))" "#
            + #"tests="\#(summary.total)" failures="\#(summary.nonCompliant)" "#
            + #"errors="\#(summary.errors)" skipped="\#(summary.waived + summary.unknown)" "#
            + #"timestamp="\#(ISO8601DateFormatter().string(from: report.generatedAt))">"#
        )
        for r in report.results {
            let name = xmlEscape("\(r.id): \(r.title)")
            let classname = xmlEscape("stigit.\(report.profileKey).\(r.category)")
            let open = #"  <testcase classname="\#(classname)" name="\#(name)">"#
            switch r.outcome {
            case .compliant:
                lines.append(#"  <testcase classname="\#(classname)" name="\#(name)"/>"#)
            case .nonCompliant:
                lines.append(open)
                let detail = xmlEscape(
                    "severity=\(r.severity.rawValue)"
                    + (r.stigId.map { " stig=\($0)" } ?? "")
                )
                lines.append(#"    <failure message="Non-compliant" type="\#(xmlEscape(r.severity.rawValue))">\#(detail)</failure>"#)
                lines.append("  </testcase>")
            case .waived:
                lines.append(open)
                let reason = xmlEscape(r.waiver.map { "Waived by \($0.approvedBy): \($0.reason)" } ?? "Waived")
                lines.append(#"    <skipped message="\#(reason)"/>"#)
                lines.append("  </testcase>")
            case .unknown:
                lines.append(open)
                lines.append(#"    <skipped message="Not evaluated"/>"#)
                lines.append("  </testcase>")
            case .error:
                lines.append(open)
                lines.append(#"    <error message="Check command failed"/>"#)
                lines.append("  </testcase>")
            }
        }
        lines.append("</testsuite>")
        return lines.joined(separator: "\n")
    }

    private static func xmlEscape(_ value: String) -> String {
        value
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
    }

    // MARK: - Summary

    private static func exportSummary(_ report: ScanReport) -> String {
        let summary = report.summary
        let failing = report.results.filter { $0.outcome == .nonCompliant }

        var lines: [String] = []
        lines.append("=================================================")
        lines.append(" StigIt Compliance Report")
        lines.append(" Profile  : \(report.profileName)")
        lines.append(" Host     : \(report.endpoint.hostname) (\(report.endpoint.osVersion))")
        if let serial = report.endpoint.serialNumber {
            lines.append(" Serial   : \(serial)")
        }
        lines.append(" Date     : \(report.generatedAt)")
        lines.append("=================================================")
        lines.append("")
        lines.append(String(format: " Score          : %.1f%%", summary.score * 100))
        lines.append(" Total Rules    : \(summary.total)")
        lines.append(" Compliant      : \(summary.compliant)")
        lines.append(" Non-Compliant  : \(summary.nonCompliant)")
        lines.append(" Waived         : \(summary.waived)")
        lines.append(" Unknown        : \(summary.unknown + summary.errors)")
        lines.append("")

        if let drift = report.drift {
            lines.append(" Drift since \(drift.baselineDate):")
            lines.append("   Regressions : \(drift.regressions.count)")
            lines.append("   Fixed       : \(drift.fixes.count)")
            for change in drift.regressions {
                lines.append("   [REGRESSED] \(change.title) (\(change.severity.rawValue))")
            }
            lines.append("")
        }

        for severity in [RuleSeverity.high, .medium, .low] {
            let group = failing.filter { $0.severity == severity }
            guard !group.isEmpty else { continue }
            lines.append("----- \(severity.rawValue.uppercased()) SEVERITY FINDINGS (\(group.count)) -----")
            for r in group {
                let stig = r.stigId.map { " [\($0)]" } ?? ""
                lines.append("  [FAIL] \(r.title)\(stig)")
                if !r.nistControls.isEmpty {
                    lines.append("         NIST: \(r.nistControls.joined(separator: ", "))")
                }
            }
            lines.append("")
        }

        let waived = report.results.filter { $0.outcome == .waived }
        if !waived.isEmpty {
            lines.append("----- WAIVED FINDINGS (\(waived.count)) ----------------")
            for r in waived {
                let w = r.waiver
                lines.append("  [WAIVED] \(r.title)")
                if let w {
                    let expiry = w.expiresAt.map { " until \($0)" } ?? ""
                    lines.append("           by \(w.approvedBy)\(expiry): \(w.reason)")
                }
            }
            lines.append("")
        }

        let passing = report.results.filter { $0.outcome == .compliant }
        if !passing.isEmpty {
            lines.append("----- PASSING CONTROLS (\(passing.count)) ----------------")
            for r in passing {
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
}
