import Foundation
import StigItCore
import Testing

@Suite("Finding annotations")
struct FindingAnnotationTests {
    @Test("Annotations are scoped to endpoint, profile, and rule")
    func scopedLookup() {
        let annotation = fixture()
        let store = FindingAnnotationStore(annotations: [annotation])

        #expect(store.annotation(
            for: "test_rule", profileKey: "stig", endpoint: TestFixtures.endpoint
        )?.labels == [.needsReview])
        #expect(store.annotation(
            for: "other_rule", profileKey: "stig", endpoint: TestFixtures.endpoint
        ) == nil)
    }

    @Test("Annotations persist with scan reports without changing outcomes")
    func reportSnapshot() throws {
        let annotation = fixture()
        let report = ScanReport(
            rules: [TestFixtures.rule(status: .nonCompliant)],
            profile: .stig,
            endpoint: TestFixtures.endpoint,
            annotations: FindingAnnotationStore(annotations: [annotation])
        )

        #expect(report.results.first?.outcome == .nonCompliant)
        #expect(report.results.first?.annotation?.labels == [.needsReview])

        let decoded = try ScanReport.from(jsonData: report.jsonData())
        #expect(decoded.results.first?.annotation?.note == "Investigating with endpoint team")
    }

    @Test("Version one reports remain readable")
    func versionOneMigration() throws {
        let report = ScanReport(
            rules: [TestFixtures.rule(status: .compliant)],
            profile: .stig,
            endpoint: TestFixtures.endpoint
        )
        var object = try #require(
            JSONSerialization.jsonObject(with: report.jsonData()) as? [String: Any]
        )
        object["schemaVersion"] = 1
        if var results = object["results"] as? [[String: Any]] {
            results[0].removeValue(forKey: "annotation")
            object["results"] = results
        }

        let decoded = try ScanReport.from(
            jsonData: JSONSerialization.data(withJSONObject: object)
        )
        #expect(decoded.results.first?.annotation == nil)
    }

    @Test("Every report export carries annotation context")
    func annotationExports() throws {
        let report = ScanReport(
            rules: [TestFixtures.rule(status: .nonCompliant)],
            profile: .stig,
            endpoint: TestFixtures.endpoint,
            annotations: FindingAnnotationStore(annotations: [fixture()])
        )

        let csv = try ReportExporter.export(report: report, format: .csv)
        let summary = try ReportExporter.export(report: report, format: .summary)
        let ndjson = try ReportExporter.export(report: report, format: .ndjson)
        let junit = try ReportExporter.export(report: report, format: .junit)

        #expect(csv.contains("Needs Review"))
        #expect(csv.contains("SEC-42"))
        #expect(summary.contains("ANNOTATED CONTROLS"))
        #expect(ndjson.contains("Needs Review"))
        #expect(junit.contains("StigIt annotation"))
    }

    @Test("Annotation files round trip atomically")
    func storeRoundTrip() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let url = root.appendingPathComponent("annotations.json")
        let annotation = fixture()
        let store = FindingAnnotationStore(annotations: [annotation], fileURL: url)
        try store.save()
        defer { try? FileManager.default.removeItem(at: root) }

        let loaded = try FindingAnnotationStore.load(from: url)
        #expect(loaded.annotations.count == 1)
        #expect(loaded.annotations.first?.id == annotation.id)
        #expect(loaded.annotations.first?.labels == annotation.labels)
        #expect(loaded.annotations.first?.note == annotation.note)
        #expect(loaded.annotations.first?.ticket == annotation.ticket)
    }

    private func fixture() -> FindingAnnotation {
        FindingAnnotation(
            endpointID: "SERIAL",
            profileKey: "stig",
            ruleID: "test_rule",
            labels: [.needsReview],
            customTags: ["Q3"],
            note: "Investigating with endpoint team",
            owner: "Security Operations",
            ticket: "SEC-42",
            updatedBy: "Analyst"
        )
    }
}
