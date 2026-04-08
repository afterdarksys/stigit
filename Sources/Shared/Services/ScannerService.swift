import Foundation

public class ScannerService {

    // MARK: - Public API

    /// Scan a single rule and return its compliance status.
    public static func check(rule: Rule) async -> RuleStatus {
        let output = await runShellCommand(rule.checkCommand)
        let clean = output.trimmingCharacters(in: .whitespacesAndNewlines)

        switch rule.expectedResult {
        case .string(let expected):
            return clean.contains(expected) ? .compliant : .nonCompliant
        case .integer(let expected):
            if let actual = Int(clean) {
                return actual == expected ? .compliant : .nonCompliant
            }
            // Some commands return multi-line; try trimming each line
            let lines = clean.split(separator: "\n")
            for line in lines {
                if let actual = Int(line.trimmingCharacters(in: .whitespaces)) {
                    return actual == expected ? .compliant : .nonCompliant
                }
            }
            return .error
        }
    }

    /// Scan all rules concurrently using a TaskGroup, reporting progress via a callback.
    /// - Parameters:
    ///   - rules: The rule array to update in-place.
    ///   - progress: Called with (completedCount, totalCount) after each rule finishes.
    public static func scanAll(
        rules: inout [Rule],
        progress: (@Sendable (Int, Int) -> Void)? = nil
    ) async {
        let total = rules.count

        // Capture the snapshots needed for concurrent checking (Rule is a value type)
        let snapshots = rules

        // Collect results concurrently
        var results: [(index: Int, status: RuleStatus)] = []
        results.reserveCapacity(total)

        await withTaskGroup(of: (Int, RuleStatus).self) { group in
            for (i, rule) in snapshots.enumerated() {
                group.addTask {
                    let status = await ScannerService.check(rule: rule)
                    return (i, status)
                }
            }
            var completed = 0
            for await (index, status) in group {
                results.append((index, status))
                completed += 1
                progress?(completed, total)
            }
        }

        // Apply results back to the caller's array
        for (index, status) in results {
            rules[index].status = status
        }
    }

    /// Scan only the rules belonging to a specific profile, concurrently.
    public static func scan(
        rules: inout [Rule],
        profile: ComplianceProfile,
        progress: (@Sendable (Int, Int) -> Void)? = nil
    ) async {
        let indices = rules.indices.filter { rules[$0].profiles.contains(profile) }
        let snapshots = indices.map { rules[$0] }
        let total = snapshots.count

        var results: [(index: Int, status: RuleStatus)] = []
        results.reserveCapacity(total)

        await withTaskGroup(of: (Int, RuleStatus).self) { group in
            for (pos, rule) in snapshots.enumerated() {
                group.addTask {
                    let status = await ScannerService.check(rule: rule)
                    return (pos, status)
                }
            }
            var completed = 0
            for await (pos, status) in group {
                results.append((pos, status))
                completed += 1
                progress?(completed, total)
            }
        }

        for (pos, status) in results {
            rules[indices[pos]].status = status
        }
    }

    // MARK: - Private

    private static func runShellCommand(_ command: String) async -> String {
        return await withCheckedContinuation { continuation in
            let task = Process()
            let pipe = Pipe()

            task.standardOutput = pipe
            task.standardError  = pipe
            task.launchPath = "/bin/sh"
            task.arguments  = ["-c", command]

            do {
                try task.run()
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                task.waitUntilExit()
                continuation.resume(returning: String(data: data, encoding: .utf8) ?? "")
            } catch {
                continuation.resume(returning: "")
            }
        }
    }
}
