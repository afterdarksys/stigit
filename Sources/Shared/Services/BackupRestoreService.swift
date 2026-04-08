import Foundation

public enum BackupRestoreService {

    public enum BackupError: Error, LocalizedError {
        case scriptFailed
        public var errorDescription: String? {
            "Backup script failed. Verify administrator privileges."
        }
    }

    private static let backupRoot = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".stigit/backups")

    private static let snapshotPaths: [String] = [
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

    // MARK: - Create

    /// Snapshot key system config files into `~/.stigit/backups/<name>/`.
    @discardableResult
    public static func createBackup(name: String? = nil) async -> Result<URL, Error> {
        let timestamp  = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
        let backupName = name ?? "backup_\(timestamp)"
        let dest       = backupRoot.appendingPathComponent(backupName)

        let copies = snapshotPaths.map { path -> String in
            let flat = dest.path + "/" + path.replacingOccurrences(of: "/", with: "_")
            return "cp -R '\(path)' '\(flat)' 2>/dev/null || true"
        }

        let manifest = #"echo '{"timestamp":"\#(timestamp)","name":"\#(backupName)"}' > '\#(dest.path)/manifest.json'"#
        let script   = (["mkdir -p '\(dest.path)'"] + copies + [manifest]).joined(separator: " && ")

        let ok = await runElevated(script)
        return ok ? .success(dest) : .failure(BackupError.scriptFailed)
    }

    // MARK: - List

    public static func listBackups() -> [URL] {
        (try? FileManager.default.contentsOfDirectory(
            at: backupRoot,
            includingPropertiesForKeys: [.creationDateKey],
            options: .skipsHiddenFiles
        ))?.filter(\.hasDirectoryPath).sorted { $0.path < $1.path } ?? []
    }

    // MARK: - Restore

    public static func restore(from backupDir: URL) async -> Bool {
        guard let items = try? FileManager.default.contentsOfDirectory(
            at: backupDir,
            includingPropertiesForKeys: nil,
            options: .skipsHiddenFiles
        ) else { return false }

        let restores = items
            .filter { $0.lastPathComponent != "manifest.json" }
            .map { item -> String in
                let original = "/" + item.lastPathComponent
                    .trimmingCharacters(in: CharacterSet(charactersIn: "_"))
                    .replacingOccurrences(of: "_", with: "/")
                return "cp -R '\(item.path)' '\(original)' 2>/dev/null || true"
            }

        guard !restores.isEmpty else { return false }
        return await runElevated(restores.joined(separator: " && "))
    }

    // MARK: - Private

    private static func runElevated(_ script: String) async -> Bool {
        let escaped = script
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"",  with: "\\\"")
        return await withCheckedContinuation { continuation in
            let process = Process()
            process.launchPath = "/usr/bin/osascript"
            process.arguments  = ["-e", #"do shell script "\#(escaped)" with administrator privileges"#]
            process.standardOutput = Pipe()
            process.standardError  = Pipe()
            process.terminationHandler = { p in continuation.resume(returning: p.terminationStatus == 0) }
            do    { try process.run() }
            catch { continuation.resume(returning: false) }
        }
    }
}
