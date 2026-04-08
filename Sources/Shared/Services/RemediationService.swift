import Foundation

public enum RemediationService {

    /// Generates a shell script that applies every selected non-compliant rule.
    public static func stagingScript(for rules: [Rule]) -> String {
        rules
            .filter { $0.isSelectedForRemediation && $0.status != .compliant }
            .map(\.remediateCommand)
            .joined(separator: "\n")
    }

    /// Runs the staged remediations via an AppleScript administrator-privilege prompt.
    /// Returns `true` when the script exits 0, `false` if cancelled or failed.
    public static func submit(rules: [Rule]) async -> Bool {
        let script = stagingScript(for: rules)
        guard !script.isEmpty else { return true }

        let escaped = script
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"",  with: "\\\"")

        return await runAppleScript(#"do shell script "\#(escaped)" with administrator privileges"#)
    }

    // MARK: - Private

    private static func runAppleScript(_ script: String) async -> Bool {
        await withCheckedContinuation { continuation in
            let process = Process()
            process.launchPath = "/usr/bin/osascript"
            process.arguments  = ["-e", script]
            process.standardOutput = Pipe()
            process.standardError  = Pipe()
            process.terminationHandler = { p in
                continuation.resume(returning: p.terminationStatus == 0)
            }
            do    { try process.run() }
            catch { continuation.resume(returning: false) }
        }
    }
}
