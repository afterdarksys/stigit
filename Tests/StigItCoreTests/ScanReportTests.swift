import StigItCore
import Testing

@Suite("Scan report")
struct ScanReportTests {
    @Test("A report with only evaluation errors never scores as compliant")
    func errorsDoNotScoreOneHundredPercent() {
        let report = ScanReport(
            rules: [TestFixtures.rule(status: .error)],
            profile: .stig,
            endpoint: TestFixtures.endpoint
        )

        #expect(report.summary.errors == 1)
        #expect(report.summary.score == 0)
    }

    @Test("A report with only unknown controls never scores as compliant")
    func unknownsDoNotScoreOneHundredPercent() {
        let report = ScanReport(
            rules: [TestFixtures.rule(status: .unknown)],
            profile: .stig,
            endpoint: TestFixtures.endpoint
        )

        #expect(report.summary.unknown == 1)
        #expect(report.summary.score == 0)
    }

    @Test("Evaluation errors block the severity gate")
    func errorsBlockSeverityGate() {
        let report = ScanReport(
            rules: [TestFixtures.rule(severity: .high, status: .error)],
            profile: .stig,
            endpoint: TestFixtures.endpoint
        )

        #expect(report.failures(atOrAbove: .high).map(\.id) == ["test_rule"])
    }
}
