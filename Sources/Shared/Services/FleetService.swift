import Foundation

/// Fleet aggregation without a server: each endpoint drops its `ScanReport` JSON into a
/// shared directory (synced however the org likes — MDM script, scp, NFS, S3 sync), and
/// this service rolls the directory up into one ops-facing summary.
public enum FleetService {

    public struct EndpointSummary: Codable, Sendable, Identifiable {
        public let hostname: String
        public let serialNumber: String?
        public let osVersion: String
        public let profileName: String
        public let reportDate: Date
        public let score: Double
        public let highSeverityFailures: Int
        public let totalFailures: Int
        public let waived: Int
        public let isStale: Bool

        public var id: String { hostname }
    }

    public struct FleetSummary: Codable, Sendable {
        public let generatedAt: Date
        public let endpointCount: Int
        public let staleCount: Int
        /// Mean of endpoint scores (unweighted — each machine counts equally).
        public let averageScore: Double
        public let endpoints: [EndpointSummary]
    }

    /// Filename an endpoint's report is published under (one file per host, latest wins).
    public static func reportFilename(for endpoint: EndpointInfo) -> String {
        let safe = endpoint.hostname
            .replacingOccurrences(of: "/", with: "-")
            .replacingOccurrences(of: ":", with: "-")
        return "\(safe).json"
    }

    /// Publishes this endpoint's report into the fleet drop directory (atomic overwrite).
    @discardableResult
    public static func publish(_ report: ScanReport, to directory: URL) throws -> URL {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent(reportFilename(for: report.endpoint))
        try report.jsonData().write(to: url, options: .atomic)
        return url
    }

    /// All parseable endpoint reports in a fleet directory.
    public static func loadReports(from directory: URL) throws -> [ScanReport] {
        let files = try FileManager.default.contentsOfDirectory(
            at: directory, includingPropertiesForKeys: nil
        )
        return files
            .filter { $0.pathExtension == "json" }
            .compactMap { url in
                guard let data = try? Data(contentsOf: url) else { return nil }
                return try? ScanReport.from(jsonData: data)
            }
            .sorted { $0.endpoint.hostname < $1.endpoint.hostname }
    }

    /// Rolls endpoint reports up into a fleet summary. An endpoint whose report is older
    /// than `staleAfterDays` is flagged stale — it may be offline or its agent broken.
    public static func summarize(
        reports: [ScanReport],
        staleAfterDays: Int = 7,
        now: Date = Date()
    ) -> FleetSummary {
        let staleCutoff = now.addingTimeInterval(-Double(staleAfterDays) * 86_400)
        let endpoints = reports.map { report -> EndpointSummary in
            let summary = report.summary
            return EndpointSummary(
                hostname: report.endpoint.hostname,
                serialNumber: report.endpoint.serialNumber,
                osVersion: report.endpoint.osVersion,
                profileName: report.profileName,
                reportDate: report.generatedAt,
                score: summary.score,
                highSeverityFailures: report.failures(atOrAbove: .high).count,
                totalFailures: summary.nonCompliant,
                waived: summary.waived,
                isStale: report.generatedAt < staleCutoff
            )
        }
        return FleetSummary(
            generatedAt: now,
            endpointCount: endpoints.count,
            staleCount: endpoints.filter(\.isStale).count,
            averageScore: endpoints.isEmpty
                ? 0 : endpoints.map(\.score).reduce(0, +) / Double(endpoints.count),
            endpoints: endpoints
        )
    }

    // MARK: - Rendering

    public static func renderJSON(_ summary: FleetSummary) throws -> String {
        let data = try ScanReport.jsonEncoder().encode(summary)
        return String(data: data, encoding: .utf8) ?? ""
    }

    public static func renderCSV(_ summary: FleetSummary) -> String {
        var lines = ["Hostname,Serial,OS,Profile,Score,High Failures,Total Failures,Waived,Last Report,Stale"]
        let dateFormatter = ISO8601DateFormatter()
        for e in summary.endpoints {
            lines.append([
                e.hostname,
                e.serialNumber ?? "",
                e.osVersion,
                e.profileName,
                String(format: "%.1f%%", e.score * 100),
                String(e.highSeverityFailures),
                String(e.totalFailures),
                String(e.waived),
                dateFormatter.string(from: e.reportDate),
                e.isStale ? "yes" : "no",
            ].map(csvEscape).joined(separator: ","))
        }
        return lines.joined(separator: "\n")
    }

    private static func csvEscape(_ rawValue: String) -> String {
        var value = rawValue
        if let first = value.first, "=+-@\t\r".contains(first) {
            value = "'" + value
        }
        if value.contains(",") || value.contains("\"") || value.contains("\n") {
            return "\"" + value.replacingOccurrences(of: "\"", with: "\"\"") + "\""
        }
        return value
    }

    public static func renderText(_ summary: FleetSummary) -> String {
        var lines: [String] = []
        lines.append("Fleet Compliance Summary")
        lines.append(String(format: "Endpoints: %d   Stale: %d   Average score: %.1f%%",
                            summary.endpointCount, summary.staleCount, summary.averageScore * 100))
        lines.append("")
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd HH:mm"
        for e in summary.endpoints {
            let stale = e.isStale ? "  [STALE]" : ""
            lines.append(String(
                format: "  %-28s %6.1f%%  high:%-3d fail:%-3d waived:%-3d %@%@",
                (e.hostname as NSString).utf8String ?? "",
                e.score * 100, e.highSeverityFailures, e.totalFailures, e.waived,
                dateFormatter.string(from: e.reportDate), stale
            ))
        }
        return lines.joined(separator: "\n")
    }
}
