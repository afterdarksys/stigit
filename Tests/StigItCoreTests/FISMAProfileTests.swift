import Foundation
import StigItCore
import Testing

@Suite("FISMA profiles")
struct FISMAProfileTests {
    @Test("Official NIST 5.2.0 baseline counts are version locked")
    func baselineCounts() {
        #expect(FISMAControlBaselines.version == "5.2.0")
        #expect(FISMAControlBaselines.low.count == 149)
        #expect(FISMAControlBaselines.moderate.count == 287)
        #expect(FISMAControlBaselines.high.count == 370)
        #expect(FISMAControlBaselines.low.isSubset(of: FISMAControlBaselines.moderate))
        #expect(FISMAControlBaselines.moderate.isSubset(of: FISMAControlBaselines.high))
    }

    @Test("Control references map to only their official impact baselines")
    func controlMapping() {
        #expect(FISMAControlBaselines.profiles(for: ["AC-17"]) == [
            .fismaLow, .fismaModerate, .fismaHigh,
        ])
        #expect(FISMAControlBaselines.profiles(for: ["AC-11"]) == [
            .fismaModerate, .fismaHigh,
        ])
        #expect(FISMAControlBaselines.profiles(for: ["AU-5(1)"]) == [.fismaHigh])
        #expect(FISMAControlBaselines.profiles(for: ["AU-8(1)"]).isEmpty)
    }

    @Test("FISMA keys and report metadata are explicit")
    func profileMetadata() {
        #expect(ComplianceProfile.from(key: "fisma-low") == .fismaLow)
        #expect(ComplianceProfile.from(key: "fisma-moderate") == .fismaModerate)
        #expect(ComplianceProfile.from(key: "fisma-high") == .fismaHigh)
        #expect(ComplianceProfile.fismaModerate.frameworkInfo?.version == "5.2.0")
        #expect(ComplianceProfile.fismaModerate.frameworkInfo?.baselineControlCount == 287)
    }

    @Test("Built-in NIST rules are exposed through applicable FISMA profiles")
    @MainActor
    func builtInCoverage() {
        let rules = RuleStore.defaultRules()
        let low = rules.filter { $0.profiles.contains(.fismaLow) }
        let moderate = rules.filter { $0.profiles.contains(.fismaModerate) }
        let high = rules.filter { $0.profiles.contains(.fismaHigh) }

        #expect(!low.isEmpty)
        #expect(low.count <= moderate.count)
        #expect(moderate.count <= high.count)
        #expect(high.allSatisfy { !$0.nistControls.isEmpty })
    }

    @Test("FISMA reports expose mapping coverage without changing scan scoring")
    func reportMetadata() throws {
        let rule = Rule(
            id: "remote_access",
            title: "Remote access",
            description: "Test",
            profiles: [.nist],
            category: .accessControl,
            nistControls: ["AC-17"],
            checkCommand: "printf pass",
            expectedResult: .string("pass"),
            remediateCommand: "printf fixed",
            status: .compliant
        )
        let report = ScanReport(
            rules: [rule],
            profile: .fismaLow,
            endpoint: TestFixtures.endpoint
        )

        #expect(report.framework?.baseline == "Low")
        #expect(report.framework?.baselineControlCount == 149)
        #expect(report.assessedFrameworkControls == ["ac-17"])
        #expect(report.summary.score == 1)

        let summary = try ReportExporter.export(report: report, format: .summary)
        #expect(summary.contains("1 of 149 baseline controls have endpoint rule mappings"))
        #expect(summary.contains("Endpoint technical assessment only"))

        let junit = try ReportExporter.export(report: report, format: .junit)
        #expect(junit.contains("fisma.baseline"))
        #expect(junit.contains("nist.sp800-53.version\" value=\"5.2.0"))
    }
}
