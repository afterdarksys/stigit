import Foundation
import StigItCore
import Testing

@Suite("FedRAMP profiles")
struct FedRAMPProfileTests {
    @Test("Official 2026 Rev. 5 certification-class counts are version locked")
    func baselineCounts() {
        #expect(FedRAMPControlBaselines.version == "2026.07.14.01")
        #expect(FedRAMPControlBaselines.catalogVersion == "5.2.0")
        #expect(FedRAMPControlBaselines.sourceCommit == "58efbf3d898496dd4a3a419eba78e458bbad5cb6")
        #expect(FedRAMPControlBaselines.classB.count == 155)
        #expect(FedRAMPControlBaselines.classC.count == 322)
        #expect(FedRAMPControlBaselines.classD.count == 409)
        #expect(FedRAMPControlBaselines.classB.isSubset(of: FedRAMPControlBaselines.classC))
        #expect(FedRAMPControlBaselines.classC.isSubset(of: FedRAMPControlBaselines.classD))
    }

    @Test("FedRAMP and rule control spellings normalize identically")
    func controlNormalization() {
        #expect(NISTControlID.normalize("AC-02 (01)") == "ac-2.1")
        #expect(NISTControlID.normalize("AC-2(1)") == "ac-2.1")
        #expect(NISTControlID.normalize("ac-02.01") == "ac-2.1")
    }

    @Test("Control references map only to applicable certification classes")
    func controlMapping() {
        #expect(FedRAMPControlBaselines.profiles(for: ["AC-17"]) == [
            .fedrampB, .fedrampC, .fedrampD,
        ])
        #expect(FedRAMPControlBaselines.profiles(for: ["AC-11"]) == [
            .fedrampC, .fedrampD,
        ])
        #expect(FedRAMPControlBaselines.profiles(for: ["AU-5(1)"]) == [.fedrampD])
        #expect(FedRAMPControlBaselines.profiles(for: ["PM-1"]).isEmpty)
    }

    @Test("Canonical keys and legacy impact aliases resolve to current classes")
    func profileKeysAndAliases() {
        #expect(ComplianceProfile.from(key: "fedramp-b") == .fedrampB)
        #expect(ComplianceProfile.from(key: "fedramp-c") == .fedrampC)
        #expect(ComplianceProfile.from(key: "fedramp-d") == .fedrampD)
        #expect(ComplianceProfile.from(key: "fedramp-low") == .fedrampB)
        #expect(ComplianceProfile.from(key: "fedramp-li-saas") == .fedrampB)
        #expect(ComplianceProfile.from(key: "fedramp-moderate") == .fedrampC)
        #expect(ComplianceProfile.from(key: "fedramp-high") == .fedrampD)
        #expect(ComplianceProfile.fedrampC.frameworkInfo?.baselineControlCount == 322)
    }

    @Test("Built-in NIST rules are exposed through applicable FedRAMP classes")
    @MainActor
    func builtInCoverage() {
        let rules = RuleStore.defaultRules()
        let classB = rules.filter { $0.profiles.contains(.fedrampB) }
        let classC = rules.filter { $0.profiles.contains(.fedrampC) }
        let classD = rules.filter { $0.profiles.contains(.fedrampD) }

        #expect(!classB.isEmpty)
        #expect(classB.count <= classC.count)
        #expect(classC.count <= classD.count)
        #expect(classD.allSatisfy { !$0.nistControls.isEmpty })
    }

    @Test("FedRAMP reports disclose mapping coverage and certification boundary")
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
            profile: .fedrampB,
            endpoint: TestFixtures.endpoint
        )

        #expect(report.framework?.baseline.contains("Class B") == true)
        #expect(report.framework?.version == "2026.07.14.01")
        #expect(report.framework?.baselineControlCount == 155)
        #expect(report.assessedFrameworkControls == ["ac-17"])
        #expect(report.summary.score == 1)

        let summary = try ReportExporter.export(report: report, format: .summary)
        #expect(summary.contains("1 of 155 baseline controls have endpoint rule mappings"))
        #expect(summary.contains("Endpoint technical evidence only"))

        let junit = try ReportExporter.export(report: report, format: .junit)
        #expect(junit.contains("compliance.framework"))
        #expect(junit.contains("fedramp.class"))
        #expect(junit.contains("nist.sp800-53.version\" value=\"5.2.0"))
    }
}
