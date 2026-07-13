import StigItCore
import Testing

@Suite("Fleet exports")
struct FleetServiceTests {
    @Test("Fleet CSV escapes delimiters and neutralizes spreadsheet formulas")
    func csvEscaping() {
        let endpoint = EndpointInfo(
            hostname: "=cmd,host",
            serialNumber: "SERIAL",
            hardwareModel: nil,
            osVersion: "15.0",
            osBuild: nil
        )
        let report = ScanReport(
            rules: [TestFixtures.rule(status: .compliant)],
            profile: .stig,
            endpoint: endpoint
        )
        let summary = FleetService.summarize(reports: [report])

        let csv = FleetService.renderCSV(summary)

        #expect(csv.contains("\"'=cmd,host\""))
    }
}
