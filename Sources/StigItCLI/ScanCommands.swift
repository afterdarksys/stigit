import Foundation
import StigItCore

@MainActor
enum ScanCommand {

    static func run(_ args: ArgScanner) async -> Int32 {
        guard let options = ScanOptions.parse(args) else { return ExitCode.error }

        let waivers: WaiverStore
        do {
            waivers = try CLIPipeline.loadWaivers(path: options.waiversPath)
        } catch {
            Console.error("Error: waiver file is unreadable or malformed: \(error.localizedDescription)")
            return ExitCode.error
        }
        warnAboutExpired(waivers, options: options)

        var rules = CLIPipeline.loadRules(
            rulesDir: options.rulesDir, quiet: options.quiet, profile: options.profile
        )
        guard !rules.isEmpty else { return ExitCode.error }
        let scanned = await CLIPipeline.scan(rules: &rules, options: options)
        guard !scanned.isEmpty else {
            Console.error("No rules match profile '\(options.profile.key)'"
                + (options.severity.map { " at severity '\($0.rawValue)'" } ?? ""))
            return ExitCode.error
        }

        let report = CLIPipeline.buildReport(scannedRules: scanned, options: options, waivers: waivers)
        return CLIPipeline.emit(report: report, options: options)
    }

    static func warnAboutExpired(_ waivers: WaiverStore, options: ScanOptions) {
        guard options.format == .text else { return }
        for waiver in waivers.expiredWaivers() {
            Console.error("Warning: waiver for '\(waiver.ruleID)' expired \(waiver.expiresAt!) — finding is active again")
        }
    }
}

@MainActor
enum RemediateCommand {

    static func run(_ args: ArgScanner) async -> Int32 {
        guard let options = ScanOptions.parse(args) else { return ExitCode.error }
        let nonInteractive = args.has("--non-interactive")
        let dryRun = args.has("--dry-run")
        let backup = args.has("--backup")

        if nonInteractive && !RemediationService.canRunNonInteractively {
            Console.error("Error: --non-interactive requires root (run under sudo or an MDM script).")
            return ExitCode.error
        }

        let waivers: WaiverStore
        do {
            waivers = try CLIPipeline.loadWaivers(path: options.waiversPath)
        } catch {
            Console.error("Error: waiver file is unreadable or malformed: \(error.localizedDescription)")
            return ExitCode.error
        }

        var rules = CLIPipeline.loadRules(
            rulesDir: options.rulesDir, quiet: options.quiet, profile: options.profile
        )
        guard !rules.isEmpty else { return ExitCode.error }
        let scanned = await CLIPipeline.scan(rules: &rules, options: options)
        let failing = RemediationService.eligibleRules(from: scanned, waivers: waivers)

        guard !failing.isEmpty else {
            Console.error("Nothing to remediate — no unwaived failing rules.")
            return CLIPipeline.emit(report: CLIPipeline.buildReport(
                scannedRules: scanned, options: options, waivers: waivers
            ), options: options)
        }

        if dryRun {
            print(RemediationService.stagingScript(for: failing))
            Console.error("\nDry run: \(failing.count) remediation(s) staged, nothing executed.")
            return ExitCode.success
        }

        if backup {
            switch await BackupRestoreService.createBackup() {
            case .success(let url): Console.error("Backup saved to: \(url.path)")
            case .failure(let err): Console.error("Warning: backup failed – \(err.localizedDescription)")
            }
        }

        Console.error("Applying \(failing.count) remediation(s)…")
        let ok = nonInteractive
            ? await RemediationService.executeDirect(rules: failing)
            : await RemediationService.submit(rules: failing)
        guard ok else {
            Console.error("Remediation failed or was cancelled.")
            return ExitCode.error
        }

        Console.error("Applied. Re-scanning to verify…")
        let rescanned = await CLIPipeline.scan(rules: &rules, options: options)
        let report = CLIPipeline.buildReport(scannedRules: rescanned, options: options, waivers: waivers)
        return CLIPipeline.emit(report: report, options: options)
    }
}
