import Foundation

public enum ScannerService {

    // MARK: - Single rule

    public static func check(rule: Rule) async -> RuleStatus {
        guard let command = ExecutionContextService.command(
            for: rule,
            command: rule.checkCommand,
            runningAsRoot: geteuid() == 0,
            consoleUsername: ExecutionContextService.currentConsoleUsername()
        ) else { return .error }
        let result = await runShellCommand(command)
        // Exit 1 is commonly produced by grep when a tested setting is absent; in
        // that case its numeric/string output is still the rule result. Shell and
        // process failures use exit codes greater than 1 and must fail closed.
        guard result.status == 0 || result.status == 1 else { return .error }
        let output = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)

        switch rule.expectedResult {
        case .string(let expected):
            return output == expected.trimmingCharacters(in: .whitespacesAndNewlines)
                ? .compliant : .nonCompliant
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

    private struct ShellResult: Sendable {
        let stdout: String
        let stderr: String
        let status: Int32
    }

    private static func runShellCommand(_ command: String) async -> ShellResult {
        await withCheckedContinuation { continuation in
            let process = Process()
            let stdout = Pipe()
            let stderr = Pipe()
            process.standardOutput = stdout
            process.standardError  = stderr
            process.executableURL  = URL(fileURLWithPath: "/bin/sh")
            process.arguments      = ["-c", command]
            process.terminationHandler = { process in
                let outputData = stdout.fileHandleForReading.readDataToEndOfFile()
                let errorData = stderr.fileHandleForReading.readDataToEndOfFile()
                continuation.resume(returning: ShellResult(
                    stdout: String(data: outputData, encoding: .utf8) ?? "",
                    stderr: String(data: errorData, encoding: .utf8) ?? "",
                    status: process.terminationStatus
                ))
            }
            do    { try process.run() }
            catch {
                continuation.resume(returning: ShellResult(
                    stdout: "", stderr: error.localizedDescription, status: 127
                ))
            }
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
