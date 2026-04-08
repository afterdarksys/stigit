import Foundation

public enum ScannerService {

    // MARK: - Single rule

    public static func check(rule: Rule) async -> RuleStatus {
        let raw = await runShellCommand(rule.checkCommand)
        let output = raw.trimmingCharacters(in: .whitespacesAndNewlines)

        switch rule.expectedResult {
        case .string(let expected):
            return output.contains(expected) ? .compliant : .nonCompliant
        case .integer(let expected):
            return intResult(from: output, expected: expected)
        }
    }

    // MARK: - Batch scan

    /// Concurrently scan every rule whose id satisfies `predicate`, updating them in-place.
    /// - Parameters:
    ///   - rules: Array to update. Pass-by-inout so the caller's copy reflects results.
    ///   - predicate: Only rules where this returns `true` are scanned; others are untouched.
    ///   - progress: Called on an arbitrary thread with (completed, total) after each result.
    public static func scan(
        rules: inout [Rule],
        where predicate: (Rule) -> Bool = { _ in true },
        progress: (@Sendable (Int, Int) -> Void)? = nil
    ) async {
        let indices = rules.indices.filter { predicate(rules[$0]) }
        guard !indices.isEmpty else { return }

        let snapshots = indices.map { rules[$0] }
        var results = [(pos: Int, status: RuleStatus)]()
        results.reserveCapacity(indices.count)

        await withTaskGroup(of: (Int, RuleStatus).self) { group in
            for (pos, rule) in snapshots.enumerated() {
                group.addTask { (pos, await ScannerService.check(rule: rule)) }
            }
            var completed = 0
            for await result in group {
                results.append(result)
                completed += 1
                progress?(completed, indices.count)
            }
        }

        for (pos, status) in results {
            rules[indices[pos]].status = status
        }
    }

    /// Convenience overload — scan all rules belonging to a specific profile.
    public static func scan(
        rules: inout [Rule],
        profile: ComplianceProfile,
        progress: (@Sendable (Int, Int) -> Void)? = nil
    ) async {
        await scan(rules: &rules, where: { $0.profiles.contains(profile) }, progress: progress)
    }

    // MARK: - Private

    private static func runShellCommand(_ command: String) async -> String {
        await withCheckedContinuation { continuation in
            let process = Process()
            let pipe    = Pipe()
            process.standardOutput = pipe
            process.standardError  = pipe
            process.launchPath     = "/bin/sh"
            process.arguments      = ["-c", command]
            process.terminationHandler = { _ in
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                continuation.resume(returning: String(data: data, encoding: .utf8) ?? "")
            }
            do    { try process.run() }
            catch { continuation.resume(returning: "") }
        }
    }

    private static func intResult(from output: String, expected: Int) -> RuleStatus {
        // Try the whole trimmed output first, then fall back line-by-line
        let candidates = [output] + output.split(separator: "\n").map {
            $0.trimmingCharacters(in: .whitespaces)
        }
        for candidate in candidates {
            if let actual = Int(candidate) {
                return actual == expected ? .compliant : .nonCompliant
            }
        }
        return .error
    }
}
