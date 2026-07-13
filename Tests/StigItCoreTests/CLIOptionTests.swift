@testable import StigItCLI
import Foundation
import Testing

@Suite("CLI option parsing")
struct CLIOptionTests {
    @Test("A value option without a value is rejected")
    func missingProfileValueIsRejected() {
        let options = ScanOptions.parse(ArgScanner(["--profile"]))

        #expect(options == nil)
    }

    @Test("Unknown scan options are rejected")
    func unknownOptionIsRejected() {
        let options = ScanOptions.parse(ArgScanner(["--definitely-unknown"]))

        #expect(options == nil)
    }

    @Test("An explicit nonexistent rule directory is rejected")
    func nonexistentRuleDirectoryIsRejected() {
        let options = ScanOptions.parse(ArgScanner([
            "--rules-dir", "/tmp/stigit-path-that-must-not-exist"
        ]))

        #expect(options == nil)
    }

    @Test("An explicit directory with no usable YAML rules does not fall back")
    @MainActor
    func emptyRuleDirectoryDoesNotFallBack() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let rules = CLIPipeline.loadRules(rulesDir: directory.path, quiet: true)

        #expect(rules.isEmpty)
    }

    @Test("Remediation rejects an explicit directory with no usable rules")
    @MainActor
    func remediationRejectsEmptyRuleDirectory() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let status = await RemediateCommand.run(ArgScanner([
            "--rules-dir", directory.path, "--dry-run"
        ]))

        #expect(status == ExitCode.error)
    }

    @Test("Rule listing rejects an explicit directory with no usable rules")
    @MainActor
    func ruleListingRejectsEmptyRuleDirectory() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let status = RulesCommand.run(ArgScanner(["list", "--rules-dir", directory.path]))

        #expect(status == ExitCode.error)
    }
}
