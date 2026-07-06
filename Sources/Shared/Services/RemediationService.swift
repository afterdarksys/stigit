import Foundation

public enum RemediationService {

    /// Generates a shell script that applies every selected non-compliant rule.
    public static func stagingScript(for rules: [Rule]) -> String {
        rules
            .filter { $0.isSelectedForRemediation && $0.status != .compliant }
            .map(\.remediateCommand)
            .joined(separator: "\n")
    }

    /// Whether the process already has root and can remediate without a GUI prompt.
    public static var canRunNonInteractively: Bool { geteuid() == 0 }

    /// Headless remediation for automation (MDM scripts, launchd, CI). Requires the
    /// process to already be root — it never prompts, and fails closed otherwise.
    /// Returns `true` when the combined script exits 0.
    public static func executeDirect(rules: [Rule]) async -> Bool {
        guard canRunNonInteractively else { return false }
        let script = stagingScript(for: rules)
        guard !script.isEmpty else { return true }

        return await withCheckedContinuation { continuation in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/bin/sh")
            process.arguments = ["-c", script]
            process.standardOutput = Pipe()
            process.standardError = Pipe()
            process.terminationHandler = { p in
                continuation.resume(returning: p.terminationStatus == 0)
            }
            do    { try process.run() }
            catch { continuation.resume(returning: false) }
        }
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
