@testable import StigItCLI
@testable import StigItCore
import Foundation
import Testing

@Suite("YAML rule loading")
struct YAMLRuleLoaderTests {
    @Test("Numeric STIG ODV values override recommended values")
    func numericStigODVIsSelected() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("rule.yaml")
        try yamlRule(
            id: "odv_rule",
            title: "ODV Rule",
            check: "printf '$ODV'",
            result: "string: '14'",
            extra: """
            odv:
              recommended: 15
              stig: 14
            """
        ).write(to: file, atomically: true, encoding: .utf8)

        let loaded = try YAMLRuleLoader.loadRule(from: file, overrideProfile: .stig)
        let rule = try #require(loaded)

        #expect(rule.checkCommand == "printf '14'")
    }

    @Test("Malformed YAML is not silently ignored when valid rules are present")
    func malformedYAMLThrows() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        try yamlRule(
            id: "valid_rule", title: "Valid", check: "printf 1", result: "integer: 1"
        ).write(
            to: directory.appendingPathComponent("valid.yaml"),
            atomically: true,
            encoding: .utf8
        )
        try "[unterminated".write(
            to: directory.appendingPathComponent("broken.yaml"),
            atomically: true,
            encoding: .utf8
        )

        var rejected = false
        do {
            _ = try YAMLRuleLoader.loadRules(from: directory)
        } catch {
            rejected = true
        }

        #expect(rejected)
    }

    @Test("Explicit YAML rules replace stale built-in definitions")
    @MainActor
    func yamlRulesReplaceBuiltIns() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        try yamlRule(
            id: "system_settings_guest_account_disable",
            title: "Updated Guest Rule",
            check: "printf 1",
            result: "integer: 1"
        ).write(
            to: directory.appendingPathComponent("updated.yaml"),
            atomically: true,
            encoding: .utf8
        )

        let rules = CLIPipeline.loadRules(rulesDir: directory.path, quiet: true)
        let updated = try #require(
            rules.first { $0.id == "system_settings_guest_account_disable" }
        )

        #expect(updated.title == "Updated Guest Rule")
        #expect(rules.filter { $0.id == updated.id }.count == 1)
    }

    @Test("Rules for a different macOS major version are skipped")
    func incompatibleOSRuleIsSkipped() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("future.yaml")
        try yamlRule(
            id: "future_rule",
            title: "Future Rule",
            check: "printf 1",
            result: "integer: 1",
            extra: """
            macOS:
              - '99.0'
            """
        ).write(to: file, atomically: true, encoding: .utf8)

        let rule = try YAMLRuleLoader.loadRule(from: file)

        #expect(rule == nil)
    }

    private func temporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private func yamlRule(
        id: String,
        title: String,
        check: String,
        result: String,
        extra: String = ""
    ) -> String {
        """
        id: \(id)
        title: \(title)
        discussion: Test rule
        check: |-
          \(check)
        result:
          \(result)
        fix: printf fixed
        tags:
          - stig
        severity: high
        \(extra)
        """
    }
}
