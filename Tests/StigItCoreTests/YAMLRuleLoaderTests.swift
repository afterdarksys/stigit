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

    @Test("Revision 5 NIST tags map into versioned FISMA baselines")
    func revisionFiveTagsMapToFISMA() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("fisma.yaml")
        try """
        id: fisma_rule
        title: FISMA Rule
        discussion: Test rule
        check: printf 1
        result:
          integer: 1
        fix: printf fixed
        tags:
          - 800-53r5_moderate
          - 800-53r4_moderate
        references:
          800-53r5:
            - AC-11
        severity: medium
        """.write(to: file, atomically: true, encoding: .utf8)

        let loaded = try YAMLRuleLoader.loadRule(from: file)
        let rule = try #require(loaded)

        #expect(rule.profiles.contains(.nist))
        #expect(!rule.profiles.contains(.fismaLow))
        #expect(rule.profiles.contains(.fismaModerate))
        #expect(rule.profiles.contains(.fismaHigh))
        #expect(!rule.profiles.contains(.fedrampB))
        #expect(rule.profiles.contains(.fedrampC))
        #expect(rule.profiles.contains(.fedrampD))
    }

    @Test("FISMA profile overrides reject controls outside the selected baseline")
    func fismaOverrideFailsClosed() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("moderate-only.yaml")
        try """
        id: moderate_only
        title: Moderate Only
        discussion: Test rule
        check: printf 1
        result:
          integer: 1
        fix: printf fixed
        tags:
          - 800-53r5_moderate
        references:
          800-53r5:
            - AC-11
        severity: medium
        """.write(to: file, atomically: true, encoding: .utf8)

        let low = try YAMLRuleLoader.loadRule(from: file, overrideProfile: .fismaLow)
        let moderate = try YAMLRuleLoader.loadRule(from: file, overrideProfile: .fismaModerate)

        #expect(low == nil)
        #expect(moderate?.profiles.contains(.fismaModerate) == true)
    }

    @Test("FedRAMP profile overrides reject controls outside the selected class")
    func fedrampOverrideFailsClosed() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("class-c-only.yaml")
        try """
        id: class_c_only
        title: Class C Only
        discussion: Test rule
        check: printf 1
        result:
          integer: 1
        fix: printf fixed
        tags:
          - 800-53r5_moderate
        references:
          800-53r5:
            - AC-11
        severity: medium
        """.write(to: file, atomically: true, encoding: .utf8)

        let classB = try YAMLRuleLoader.loadRule(from: file, overrideProfile: .fedrampB)
        let classC = try YAMLRuleLoader.loadRule(from: file, overrideProfile: .fedrampC)

        #expect(classB == nil)
        #expect(classC?.profiles.contains(.fedrampC) == true)
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
