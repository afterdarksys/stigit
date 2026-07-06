import Foundation

/// Installs a launchd job that re-runs the CLI on a schedule, so endpoints keep
/// scanning (and publishing to the fleet directory) without an operator present.
/// Root installs a LaunchDaemon (survives logout); everyone else gets a LaunchAgent.
public enum LaunchdScheduler {

    public static let label = "com.stigit.scheduled-scan"

    public enum Interval: String, CaseIterable, Sendable {
        case hourly
        case daily
        case weekly

        public var seconds: Int {
            switch self {
            case .hourly: return 3_600
            case .daily:  return 86_400
            case .weekly: return 604_800
            }
        }
    }

    public enum SchedulerError: LocalizedError {
        case launchctlFailed(String)

        public var errorDescription: String? {
            switch self {
            case .launchctlFailed(let detail): return "launchctl failed: \(detail)"
            }
        }
    }

    public static var isRoot: Bool { geteuid() == 0 }

    /// Where the job plist lives for the current privilege level.
    public static func plistURL() -> URL {
        if isRoot {
            return URL(fileURLWithPath: "/Library/LaunchDaemons/\(label).plist")
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/\(label).plist")
    }

    /// Renders the job plist. `executablePath` should be the resolved absolute path of
    /// stigit-cli; `arguments` are the scan arguments to run on each firing.
    public static func plistXML(
        executablePath: String,
        arguments: [String],
        interval: Interval,
        logPath: String = "/var/log/stigit-scan.log"
    ) -> String {
        let programArgs = ([executablePath] + arguments)
            .map { "        <string>\(xmlEscape($0))</string>" }
            .joined(separator: "\n")
        let log = isRoot ? logPath
            : FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent(".stigit/scheduled-scan.log").path
        return """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>\(label)</string>
            <key>ProgramArguments</key>
            <array>
        \(programArgs)
            </array>
            <key>StartInterval</key>
            <integer>\(interval.seconds)</integer>
            <key>RunAtLoad</key>
            <false/>
            <key>StandardOutPath</key>
            <string>\(xmlEscape(log))</string>
            <key>StandardErrorPath</key>
            <string>\(xmlEscape(log))</string>
        </dict>
        </plist>
        """
    }

    /// Writes the plist and loads it. Returns the plist path.
    @discardableResult
    public static func install(
        executablePath: String,
        arguments: [String],
        interval: Interval
    ) throws -> URL {
        let url = plistURL()
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true
        )
        let xml = plistXML(executablePath: executablePath, arguments: arguments, interval: interval)
        try xml.write(to: url, atomically: true, encoding: .utf8)
        // Reload cleanly if a previous version is running.
        _ = launchctl(["unload", url.path])
        let result = launchctl(["load", "-w", url.path])
        guard result.status == 0 else { throw SchedulerError.launchctlFailed(result.output) }
        return url
    }

    /// Unloads and removes the job. Returns true when a job existed.
    @discardableResult
    public static func uninstall() throws -> Bool {
        let url = plistURL()
        guard FileManager.default.fileExists(atPath: url.path) else { return false }
        _ = launchctl(["unload", url.path])
        try FileManager.default.removeItem(at: url)
        return true
    }

    public static func isInstalled() -> Bool {
        FileManager.default.fileExists(atPath: plistURL().path)
    }

    // MARK: - Private

    private static func launchctl(_ arguments: [String]) -> (status: Int32, output: String) {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = arguments
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return (1, error.localizedDescription)
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return (process.terminationStatus, String(data: data, encoding: .utf8) ?? "")
    }

    private static func xmlEscape(_ value: String) -> String {
        value
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
    }
}
