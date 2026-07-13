import Foundation

public enum BackupRestoreService {

    public enum BackupError: Error, LocalizedError {
        case invalidName
        case noFilesAvailable
        case invalidManifest
        case scriptFailed

        public var errorDescription: String? {
            switch self {
            case .invalidName:
                return "Backup names may contain only letters, numbers, '.', '_', and '-'."
            case .noFilesAvailable:
                return "None of the configured system paths were available to back up."
            case .invalidManifest:
                return "The backup manifest is missing, malformed, or contains an unsafe path."
            case .scriptFailed:
                return "Backup or restore failed. Verify administrator privileges and available disk space."
            }
        }
    }

    struct Manifest: Codable, Sendable {
        struct Entry: Codable, Sendable {
            let sourcePath: String
            let storedName: String
        }

        let timestamp: String
        let name: String
        let entries: [Entry]
    }

    private static let backupRoot = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".stigit/backups")

    private static let snapshotPaths: [String] = [
        "/Library/Preferences",
        "/etc/ssh/sshd_config",
        "/etc/ssh/sshd_config.d",
        "/etc/pam.d",
        "/etc/security/audit_control",
        "/etc/security/audit_user",
    ]

    // MARK: - Create

    /// Snapshot key system config files into `~/.stigit/backups/<name>/`.
    @discardableResult
    public static func createBackup(name: String? = nil) async -> Result<URL, Error> {
        let timestamp = ISO8601DateFormatter().string(from: Date())
            .replacingOccurrences(of: ":", with: "-")
        let requestedName = name ?? "backup_\(timestamp)"
        guard let backupName = validatedBackupName(requestedName) else {
            return .failure(BackupError.invalidName)
        }

        let availablePaths = snapshotPaths.filter {
            FileManager.default.fileExists(atPath: $0)
        }
        guard !availablePaths.isEmpty else {
            return .failure(BackupError.noFilesAvailable)
        }

        let destination = backupRoot.appendingPathComponent(backupName, isDirectory: true)
        let entries = availablePaths.enumerated().map { index, source in
            Manifest.Entry(
                sourcePath: source,
                storedName: String(format: "%03d-item", index)
            )
        }
        let manifest = Manifest(timestamp: timestamp, name: backupName, entries: entries)

        do {
            guard !FileManager.default.fileExists(atPath: destination.path) else {
                return .failure(BackupError.invalidName)
            }
            try FileManager.default.createDirectory(
                at: destination, withIntermediateDirectories: true
            )
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            try encoder.encode(manifest).write(
                to: destination.appendingPathComponent("manifest.json"),
                options: .atomic
            )
        } catch {
            return .failure(error)
        }

        let copies = entries.map { entry in
            let source = shellQuote(entry.sourcePath)
            let stored = shellQuote(destination.appendingPathComponent(entry.storedName).path)
            return "if [ -d \(source) ]; then /usr/bin/ditto \(source) \(stored); else /bin/cp -p \(source) \(stored); fi"
        }
        let ok = await runElevated((["set -e"] + copies).joined(separator: "\n"))
        if !ok {
            try? FileManager.default.removeItem(at: destination)
            return .failure(BackupError.scriptFailed)
        }
        return .success(destination)
    }

    // MARK: - List

    public static func listBackups() -> [URL] {
        (try? FileManager.default.contentsOfDirectory(
            at: backupRoot,
            includingPropertiesForKeys: [.creationDateKey],
            options: .skipsHiddenFiles
        ))?.filter {
            $0.hasDirectoryPath
                && FileManager.default.fileExists(
                    atPath: $0.appendingPathComponent("manifest.json").path
                )
        }.sorted { $0.path < $1.path } ?? []
    }

    // MARK: - Restore

    public static func restore(from backupDirectory: URL) async -> Bool {
        let resolvedRoot = backupRoot.resolvingSymlinksInPath().standardizedFileURL.path + "/"
        let resolvedBackup = backupDirectory.resolvingSymlinksInPath().standardizedFileURL
        guard resolvedBackup.path.hasPrefix(resolvedRoot),
              let data = try? Data(contentsOf: resolvedBackup.appendingPathComponent("manifest.json")),
              let manifest = try? JSONDecoder().decode(Manifest.self, from: data),
              let script = try? restoreScript(
                manifest: manifest,
                backupDirectory: resolvedBackup,
                allowedSourcePaths: Set(snapshotPaths)
              ) else {
            return false
        }

        for entry in manifest.entries {
            let stored = resolvedBackup.appendingPathComponent(entry.storedName)
            guard FileManager.default.fileExists(atPath: stored.path) else { return false }
        }
        return await runElevated(script)
    }

    static func restoreScript(
        manifest: Manifest,
        backupDirectory: URL,
        allowedSourcePaths: Set<String>
    ) throws -> String {
        guard !manifest.entries.isEmpty else { throw BackupError.invalidManifest }
        var commands = ["set -e"]
        for entry in manifest.entries {
            guard allowedSourcePaths.contains(entry.sourcePath),
                  !entry.storedName.isEmpty,
                  entry.storedName != ".",
                  entry.storedName != "..",
                  URL(fileURLWithPath: entry.storedName).lastPathComponent == entry.storedName else {
                throw BackupError.invalidManifest
            }
            let stored = shellQuote(
                backupDirectory.appendingPathComponent(entry.storedName).path
            )
            let destination = shellQuote(entry.sourcePath)
            commands.append(
                "if [ -d \(stored) ]; then /usr/bin/ditto \(stored) \(destination); else /bin/cp -p \(stored) \(destination); fi"
            )
        }
        return commands.joined(separator: "\n")
    }

    static func validatedBackupName(_ name: String) -> String? {
        guard !name.isEmpty, name != ".", name != ".." else { return nil }
        let allowed = CharacterSet.alphanumerics
            .union(CharacterSet(charactersIn: "._-"))
        guard name.rangeOfCharacter(from: allowed.inverted) == nil else { return nil }
        return name
    }

    // MARK: - Private

    private static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private static func runElevated(_ script: String) async -> Bool {
        if geteuid() == 0 {
            return await runProcess(executable: "/bin/sh", arguments: ["-c", script])
        }
        let escaped = script
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        return await runProcess(
            executable: "/usr/bin/osascript",
            arguments: ["-e", #"do shell script "\#(escaped)" with administrator privileges"#]
        )
    }

    private static func runProcess(executable: String, arguments: [String]) async -> Bool {
        await withCheckedContinuation { continuation in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: executable)
            process.arguments = arguments
            process.standardOutput = Pipe()
            process.standardError = Pipe()
            process.terminationHandler = {
                continuation.resume(returning: $0.terminationStatus == 0)
            }
            do { try process.run() }
            catch { continuation.resume(returning: false) }
        }
    }
}
