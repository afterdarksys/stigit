import Foundation

public enum RemediationService {

    /// Rules safe to remediate: explicitly selected, confirmed non-compliant, and
    /// not covered by an active waiver.
    public static func eligibleRules(
        from rules: [Rule],
        waivers: WaiverStore? = nil,
        at date: Date = Date()
    ) -> [Rule] {
        rules.filter { rule in
            rule.isSelectedForRemediation
                && rule.status == .nonCompliant
                && waivers?.activeWaiver(for: rule.id, at: date) == nil
        }
    }

    /// Generates a shell script that applies every selected non-compliant rule.
    public static func stagingScript(for rules: [Rule]) -> String {
        let consoleUsername = ExecutionContextService.currentConsoleUsername()
        let commands = eligibleRules(from: rules)
            .map { rule in
                ExecutionContextService.command(
                    for: rule,
                    runningAsRoot: true,
                    consoleUsername: consoleUsername
                ) ?? "echo 'No logged-in console user for \(rule.id)' >&2; exit 70"
            }
            .joined(separator: "\n")
        return commands.isEmpty ? "" : "set -e\n\(commands)"
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
