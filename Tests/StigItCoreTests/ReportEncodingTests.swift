import Foundation
import StigItCore
import Testing

@Suite("Report encoding")
struct ReportEncodingTests {
    @Test("Canonical JSON contains summary counts")
    func jsonContainsSummary() throws {
        let report = ScanReport(
            rules: [TestFixtures.rule(status: .compliant)],
            profile: .stig,
            endpoint: TestFixtures.endpoint
        )

        let object = try #require(
            JSONSerialization.jsonObject(with: report.jsonData()) as? [String: Any]
        )
        let summary = try #require(object["summary"] as? [String: Any])

        #expect(summary["total"] as? Int == 1)
        #expect(summary["compliant"] as? Int == 1)
    }

    @Test("Unsupported report schema versions are rejected")
    func unsupportedSchemaIsRejected() throws {
        let report = ScanReport(
            rules: [TestFixtures.rule(status: .compliant)],
            profile: .stig,
            endpoint: TestFixtures.endpoint
        )
        var object = try #require(
            JSONSerialization.jsonObject(with: report.jsonData()) as? [String: Any]
        )
        object["schemaVersion"] = 999
        let data = try JSONSerialization.data(withJSONObject: object)

        var rejected = false
        do {
            _ = try ScanReport.from(jsonData: data)
        } catch {
            rejected = true
        }

        #expect(rejected)
    }
}
