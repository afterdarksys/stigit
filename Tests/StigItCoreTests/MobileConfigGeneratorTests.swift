import Foundation
import StigItCore
import Testing

@Suite("MobileConfig generation")
struct MobileConfigGeneratorTests {
    @Test("Organization and identifier text is XML escaped")
    @MainActor
    func interpolatedTextProducesValidPlist() throws {
        let xml = MobileConfigGenerator.generate(
            rules: RuleStore.defaultRules(),
            profile: .stig,
            orgName: "A&B <Government>",
            profileIdentifier: "gov.example.stigit&test"
        )

        let data = try #require(xml.data(using: .utf8))
        _ = try PropertyListSerialization.propertyList(
            from: data, options: [], format: nil
        )
    }

    @Test("ISO profile output uses one filesystem-safe filename")
    @MainActor
    func isoFilenameIsSafe() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let url = try MobileConfigGenerator.write(
            rules: RuleStore.defaultRules(),
            profile: .iso27001,
            profileIdentifier: "gov.example.iso",
            to: directory
        )

        #expect(url.deletingLastPathComponent() == directory)
        #expect(url.lastPathComponent == "gov.example.iso_iso_iec_27001.mobileconfig")
        #expect(FileManager.default.fileExists(atPath: url.path))
    }

    @Test("Managed preferences use Apple's PayloadContent structure")
    @MainActor
    func managedPreferencesHavePayloadContent() throws {
        let xml = MobileConfigGenerator.generate(
            rules: RuleStore.defaultRules(), profile: .stig
        )
        let data = try #require(xml.data(using: .utf8))
        let root = try #require(
            try PropertyListSerialization.propertyList(
                from: data, options: [], format: nil
            ) as? [String: Any]
        )
        let payloads = try #require(root["PayloadContent"] as? [[String: Any]])
        let firewall = try #require(payloads.first {
            $0["PayloadDisplayName"] as? String == "com.apple.security.firewall"
        })
        let domains = try #require(firewall["PayloadContent"] as? [String: Any])
        let domain = try #require(
            domains["com.apple.security.firewall"] as? [String: Any]
        )
        let forced = try #require(domain["Forced"] as? [[String: Any]])
        let settings = try #require(
            forced.first?["mcx_preference_settings"] as? [String: Any]
        )

        #expect(settings["EnableFirewall"] as? Bool == true)
    }

    @Test("FISMA configuration profiles preserve the authorization boundary")
    @MainActor
    func fismaDescriptionDoesNotOverclaim() throws {
        let xml = MobileConfigGenerator.generate(
            rules: RuleStore.defaultRules(), profile: .fismaModerate
        )
        let data = try #require(xml.data(using: .utf8))
        let root = try #require(
            try PropertyListSerialization.propertyList(
                from: data, options: [], format: nil
            ) as? [String: Any]
        )

        #expect(root["PayloadDisplayName"] as? String == "StigIt FISMA Moderate Impact Endpoint Controls")
        #expect((root["PayloadDescription"] as? String)?.contains(
            "does not establish FISMA compliance or authorization"
        ) == true)
    }
}
