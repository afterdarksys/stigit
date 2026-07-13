import Foundation
import StigItCore

// MARK: - waiver list | add | remove

enum WaiverCommand {

    static func run(_ args: ArgScanner) -> Int32 {
        let action = args.positionals.first ?? "list"
        let fileURL = args.value(for: "--waivers").map { URL(fileURLWithPath: $0) }
            ?? WaiverStore.defaultFileURL()

        var store: WaiverStore
        do {
            store = try WaiverStore.load(from: fileURL)
        } catch {
            Console.error("Error: waiver file is unreadable or malformed: \(error.localizedDescription)")
            return ExitCode.error
        }

        switch action {
        case "list":
            return list(store, args: args)
        case "add":
            return add(&store, args: args)
        case "remove":
            guard let ruleID = args.positionals.dropFirst().first else {
                Console.error("Usage: stigit-cli waiver remove <rule-id> [--waivers FILE]")
                return ExitCode.error
            }
            guard store.remove(ruleID: ruleID) else {
                Console.error("No waiver found for '\(ruleID)'")
                return ExitCode.error
            }
            return save(store, message: "Removed waiver for '\(ruleID)'")
        default:
            Console.error("Unknown waiver action '\(action)'. Valid: list | add | remove")
            return ExitCode.error
        }
    }

    private static func list(_ store: WaiverStore, args: ArgScanner) -> Int32 {
        if args.value(for: "--format") == "json" {
            let encoder = ScanReport.jsonEncoder()
            if let data = try? encoder.encode(store.waivers) {
                print(String(data: data, encoding: .utf8) ?? "[]")
            }
            return ExitCode.success
        }
        guard !store.waivers.isEmpty else {
            print("No waivers in \(store.fileURL.path)")
            return ExitCode.success
        }
        print("Waivers (\(store.fileURL.path)):")
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd"
        dateFormatter.timeZone = TimeZone(identifier: "UTC")
        for waiver in store.waivers {
            let expiry = waiver.expiresAt.map { dateFormatter.string(from: $0) } ?? "never"
            let status = waiver.isActive() ? "" : "  [EXPIRED]"
            print("  \(waiver.ruleID)")
            print("    approved by \(waiver.approvedBy), expires \(expiry)\(status)")
            print("    reason: \(waiver.reason)")
            if let ticket = waiver.ticket { print("    ticket: \(ticket)") }
        }
        return ExitCode.success
    }

    private static func add(_ store: inout WaiverStore, args: ArgScanner) -> Int32 {
        guard let ruleID = args.positionals.dropFirst().first,
              let reason = args.value(for: "--reason"),
              let approvedBy = args.value(for: "--approved-by") else {
            Console.error("""
            Usage: stigit-cli waiver add <rule-id> --reason <text> --approved-by <name>
                                        [--ticket <id>] [--expires YYYY-MM-DD] [--waivers FILE]
            """)
            return ExitCode.error
        }

        var expiresAt: Date?
        if let raw = args.value(for: "--expires") {
            let dateFormatter = DateFormatter()
            dateFormatter.dateFormat = "yyyy-MM-dd"
            dateFormatter.timeZone = TimeZone(identifier: "UTC")
            guard let date = dateFormatter.date(from: raw) else {
                Console.error("Error: --expires must be YYYY-MM-DD (got '\(raw)')")
                return ExitCode.error
            }
            expiresAt = date
        }

        store.upsert(Waiver(
            ruleID: ruleID,
            reason: reason,
            approvedBy: approvedBy,
            ticket: args.value(for: "--ticket"),
            expiresAt: expiresAt
        ))
        return save(store, message: "Waiver recorded for '\(ruleID)'")
    }

    private static func save(_ store: WaiverStore, message: String) -> Int32 {
        do {
            try store.save()
            print(message)
            return ExitCode.success
        } catch {
            Console.error("Error: could not save waiver file: \(error.localizedDescription)")
            return ExitCode.error
        }
    }
}

// MARK: - fleet summarize

enum FleetCommand {

    static func run(_ args: ArgScanner) -> Int32 {
        let positionals = args.positionals
        guard positionals.first == "summarize", let dirPath = positionals.dropFirst().first else {
            Console.error("Usage: stigit-cli fleet summarize <directory> [--format text|json|csv] [--stale-days N]")
            return ExitCode.error
        }

        let staleDays = args.value(for: "--stale-days").flatMap(Int.init) ?? 7
        let reports: [ScanReport]
        do {
            reports = try FleetService.loadReports(from: URL(fileURLWithPath: dirPath))
        } catch {
            Console.error("Error: cannot read fleet directory '\(dirPath)': \(error.localizedDescription)")
            return ExitCode.error
        }
        guard !reports.isEmpty else {
            Console.error("No endpoint reports found in '\(dirPath)'")
            return ExitCode.error
        }

        let summary = FleetService.summarize(reports: reports, staleAfterDays: staleDays)
        switch args.value(for: "--format")?.lowercased() ?? "text" {
        case "json":
            print((try? FleetService.renderJSON(summary)) ?? "{}")
        case "csv":
            print(FleetService.renderCSV(summary))
        case "text":
            print(FleetService.renderText(summary))
        default:
            Console.error("Unknown format. Valid: text | json | csv")
            return ExitCode.error
        }
        return ExitCode.success
    }
}

// MARK: - schedule install | uninstall | status

enum ScheduleCommand {

    static func run(_ args: ArgScanner) -> Int32 {
        switch args.positionals.first {
        case "install":
            return install(args)
        case "uninstall":
            do {
                let removed = try LaunchdScheduler.uninstall()
                print(removed ? "Scheduled scan removed." : "No scheduled scan was installed.")
                return ExitCode.success
            } catch {
                Console.error("Error: \(error.localizedDescription)")
                return ExitCode.error
            }
        case "status":
            if LaunchdScheduler.isInstalled() {
                print("Scheduled scan installed: \(LaunchdScheduler.plistURL().path)")
            } else {
                print("No scheduled scan installed.")
            }
            return ExitCode.success
        default:
            Console.error("Usage: stigit-cli schedule install|uninstall|status [--interval hourly|daily|weekly] [scan options]")
            return ExitCode.error
        }
    }

    private static func install(_ args: ArgScanner) -> Int32 {
        let interval: LaunchdScheduler.Interval
        if let raw = args.value(for: "--interval") {
            guard let parsed = LaunchdScheduler.Interval(rawValue: raw.lowercased()) else {
                Console.error("Unknown interval '\(raw)'. Valid: hourly | daily | weekly")
                return ExitCode.error
            }
            interval = parsed
        } else {
            interval = .daily
        }

        // Forward the scan configuration into the scheduled job.
        var scanArgs = ["scan", "--quiet", "--history"]
        for flag in ["--profile", "--rules-dir", "--waivers", "--fleet-dir", "--export", "--output"] {
            if let value = args.value(for: flag) {
                scanArgs += [flag, value]
            }
        }

        do {
            let url = try LaunchdScheduler.install(
                executablePath: resolvedExecutablePath(),
                arguments: scanArgs,
                interval: interval
            )
            let scope = LaunchdScheduler.isRoot ? "LaunchDaemon" : "LaunchAgent (current user)"
            print("Scheduled \(interval.rawValue) scan installed as \(scope): \(url.path)")
            return ExitCode.success
        } catch {
            Console.error("Error: could not install schedule: \(error.localizedDescription)")
            return ExitCode.error
        }
    }

    private static func resolvedExecutablePath() -> String {
        let argv0 = CommandLine.arguments[0]
        if argv0.hasPrefix("/") { return argv0 }
        return FileManager.default.currentDirectoryPath + "/" + argv0
    }
}

// MARK: - mobileconfig

@MainActor
enum MobileConfigCommand {

    static func run(_ args: ArgScanner) -> Int32 {
        let profile = args.value(for: "--profile").flatMap(ScanOptions.resolveProfile) ?? .stig
        let orgName = args.value(for: "--org-name") ?? "Your Organization"
        let profileID = args.value(for: "--profile-identifier") ?? "com.stigit.baseline"
        let dir = args.value(for: "--output").map { URL(fileURLWithPath: $0) }
            ?? MobileConfigGenerator.defaultOutputDirectory()

        do {
            let url = try MobileConfigGenerator.write(
                rules: RuleStore.defaultRules(),
                profile: profile,
                orgName: orgName,
                profileIdentifier: profileID,
                to: dir
            )
            print("MobileConfig written to: \(url.path)")
            return ExitCode.success
        } catch {
            Console.error("MobileConfig generation failed: \(error.localizedDescription)")
            return ExitCode.error
        }
    }
}

// MARK: - rules list

@MainActor
enum RulesCommand {

    static func run(_ args: ArgScanner) -> Int32 {
        guard args.positionals.first ?? "list" == "list" else {
            Console.error("Usage: stigit-cli rules list [--profile P] [--severity S] [--rules-dir DIR] [--format text|json]")
            return ExitCode.error
        }
        guard let options = ScanOptions.parse(args) else { return ExitCode.error }

        let loadedRules = CLIPipeline.loadRules(
            rulesDir: options.rulesDir, quiet: true, profile: options.profile
        )
        guard !loadedRules.isEmpty else { return ExitCode.error }
        let rules = loadedRules
            .filter {
                $0.profiles.contains(options.profile)
                    && (options.severity == nil || $0.severity == options.severity)
            }

        if options.format == .json {
            let encoder = ScanReport.jsonEncoder()
            if let data = try? encoder.encode(rules) {
                print(String(data: data, encoding: .utf8) ?? "[]")
            }
            return ExitCode.success
        }

        print("Rules for \(options.profile.rawValue): \(rules.count)")
        for rule in rules {
            let stig = rule.stigId.map { " [\($0)]" } ?? ""
            let severity = rule.severity.rawValue.padding(toLength: 8, withPad: " ", startingAt: 0)
            let category = rule.category.rawValue.padding(toLength: 22, withPad: " ", startingAt: 0)
            print("  \(severity) \(category) \(rule.title)\(stig)")
        }
        return ExitCode.success
    }
}
