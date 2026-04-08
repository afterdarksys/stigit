import Foundation

/// Creates and restores system configuration backups before applying remediations.
///
/// Backups are stored in ~/.stigit/backups/<name>/ and include key preference files,
/// SSH configuration, PAM modules, and audit control files.
public class BackupRestoreService {

    private static let backupRoot: URL = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".stigit/backups")

    /// Key system paths to snapshot before remediation.
    private static let backupTargets: [String] = [
        "/Library/Preferences",
        "/Library/Preferences/com.apple.Bluetooth.plist",
        "/Library/Preferences/com.apple.loginwindow.plist",
        "/etc/ssh/sshd_config",
        "/etc/ssh/sshd_config.d",
        "/etc/pam.d",
        "/etc/security/audit_control",
        "/etc/security/audit_user",
        "/private/etc/pam.d/sudo",
        "/private/etc/pam.d/su",
    ]

    // MARK: - Create Backup

    /// Create a timestamped snapshot of key system configuration files.
    /// Returns the path to the backup directory on success.
    @discardableResult
    public static func createBackup(name: String? = nil) async -> Result<URL, Error> {
        let timestamp = ISO8601DateFormatter().string(from: Date())
            .replacingOccurrences(of: ":", with: "-")
        let backupName = name ?? "backup_\(timestamp)"
        let backupDir  = backupRoot.appendingPathComponent(backupName)

        let mkdirCmd = "mkdir -p '\(backupDir.path)'"
        var copyCommands: [String] = []
        for target in backupTargets {
            let dest = backupDir.path + "/" + target.replacingOccurrences(of: "/", with: "_")
            copyCommands.append("cp -R '\(target)' '\(dest)' 2>/dev/null || true")
        }

        // Write a manifest so we know what was captured
        let manifestCmd = """
            echo '{ "timestamp": "\(timestamp)", "name": "\(backupName)" }' \
              > '\(backupDir.path)/manifest.json'
            """

        let fullCommand = ([mkdirCmd] + copyCommands + [manifestCmd]).joined(separator: " && ")
        let appleScript = "do shell script \"\(shellEscape(fullCommand))\" with administrator privileges"

        let ok = await runAppleScript(appleScript)
        if ok {
            return .success(backupDir)
        } else {
            return .failure(BackupError.scriptFailed)
        }
    }

    // MARK: - List Backups

    public static func listBackups() -> [URL] {
        let fm = FileManager.default
        guard let contents = try? fm.contentsOfDirectory(
            at: backupRoot, includingPropertiesForKeys: [.creationDateKey], options: [.skipsHiddenFiles]
        ) else { return [] }
        return contents
            .filter { $0.hasDirectoryPath }
            .sorted { ($0.path) < ($1.path) }
    }

    // MARK: - Restore

    /// Restore from a previously-created backup directory.
    public static func restore(from backupDir: URL) async -> Bool {
        var restoreCommands: [String] = []
        let fm = FileManager.default
        guard let items = try? fm.contentsOfDirectory(
            at: backupDir, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]
        ) else { return false }

        for item in items where item.lastPathComponent != "manifest.json" {
            // Reverse the path encoding: replace leading _ with /
            let originalPath = "/" + item.lastPathComponent
                .trimmingCharacters(in: CharacterSet(charactersIn: "_"))
                .replacingOccurrences(of: "_", with: "/")
            restoreCommands.append("cp -R '\(item.path)' '\(originalPath)' 2>/dev/null || true")
        }

        guard !restoreCommands.isEmpty else { return false }
        let script = restoreCommands.joined(separator: " && ")
        let appleScript = "do shell script \"\(shellEscape(script))\" with administrator privileges"
        return await runAppleScript(appleScript)
    }

    // MARK: - Private

    private static func shellEscape(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\")
         .replacingOccurrences(of: "\"", with: "\\\"")
    }

    private static func runAppleScript(_ script: String) async -> Bool {
        return await withCheckedContinuation { continuation in
            let task = Process()
            task.launchPath = "/usr/bin/osascript"
            task.arguments  = ["-e", script]
            task.standardOutput = Pipe()
            task.standardError  = Pipe()
            do {
                try task.run()
                task.waitUntilExit()
                continuation.resume(returning: task.terminationStatus == 0)
            } catch {
                continuation.resume(returning: false)
            }
        }
    }

    public enum BackupError: Error, LocalizedError {
        case scriptFailed
        public var errorDescription: String? { "Backup script failed. Check administrator privileges." }
    }
}
