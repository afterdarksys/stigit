import Foundation

/// Persists every scan as a `ScanReport` snapshot and computes drift between runs.
/// Layout: `<root>/<profileKey>/scan_<ISO8601>.json`, newest sorts last by name.
public enum ScanHistoryService {

    public static func defaultRootDirectory() -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".stigit/history")
    }

    @discardableResult
    public static func save(
        _ report: ScanReport,
        root: URL = defaultRootDirectory()
    ) throws -> URL {
        let dir = root.appendingPathComponent(report.profileKey)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let stamp = ISO8601DateFormatter().string(from: report.generatedAt)
            .replacingOccurrences(of: ":", with: "-")
        let url = dir.appendingPathComponent("scan_\(stamp).json")
        try report.jsonData().write(to: url, options: .atomic)
        return url
    }

    /// Most recent snapshot for a profile, or nil when no history exists.
    /// Corrupt snapshots are skipped rather than failing the scan that reads them.
    public static func latest(
        profileKey: String,
        root: URL = defaultRootDirectory()
    ) -> ScanReport? {
        allSnapshots(profileKey: profileKey, root: root).last
    }

    /// All parseable snapshots for a profile, oldest first.
    public static func allSnapshots(
        profileKey: String,
        root: URL = defaultRootDirectory()
    ) -> [ScanReport] {
        let dir = root.appendingPathComponent(profileKey)
        guard let files = try? FileManager.default.contentsOfDirectory(
            at: dir, includingPropertiesForKeys: nil
        ) else { return [] }
        return files
            .filter { $0.pathExtension == "json" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
            .compactMap { url in
                guard let data = try? Data(contentsOf: url) else { return nil }
                return try? ScanReport.from(jsonData: data)
            }
    }

    /// Regressions (pass→fail) and fixes (fail→pass) between two reports.
    /// Waived and undecided outcomes are excluded — drift is about real state changes.
    public static func drift(from baseline: ScanReport, to current: ScanReport) -> ScanReport.Drift {
        let before = Dictionary(uniqueKeysWithValues: baseline.results.map { ($0.id, $0.outcome) })

        var regressions: [ScanReport.Drift.Change] = []
        var fixes: [ScanReport.Drift.Change] = []
        for result in current.results {
            guard let previous = before[result.id] else { continue }
            let change = ScanReport.Drift.Change(
                ruleID: result.id, title: result.title, severity: result.severity
            )
            if previous == .compliant && result.outcome == .nonCompliant {
                regressions.append(change)
            } else if previous == .nonCompliant && result.outcome == .compliant {
                fixes.append(change)
            }
        }
        return ScanReport.Drift(
            baselineDate: baseline.generatedAt,
            regressions: regressions,
            fixes: fixes
        )
    }
}
