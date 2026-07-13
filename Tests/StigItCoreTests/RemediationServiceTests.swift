import StigItCore
import Foundation
import Testing

@Suite("Remediation selection")
struct RemediationServiceTests {
    @Test("Only selected non-compliant rules are staged")
    func onlySelectedFailuresAreStaged() {
        let rules = [
            TestFixtures.rule(id: "passing", status: .compliant),
            TestFixtures.rule(id: "unknown", status: .unknown),
            TestFixtures.rule(id: "error", status: .error),
            TestFixtures.rule(id: "unselected", status: .nonCompliant, selected: false),
            TestFixtures.rule(id: "failing", status: .nonCompliant),
        ]

        let script = RemediationService.stagingScript(for: rules)

        #expect(script == "set -e\nprintf remediate")
    }

    @Test("Active waivers are excluded from eligible remediation")
    func activeWaiversAreExcluded() {
        let now = Date(timeIntervalSince1970: 1_000)
        let waivers = WaiverStore(waivers: [
            Waiver(
                ruleID: "waived",
                reason: "Accepted risk",
                approvedBy: "Approver",
                createdAt: now,
                expiresAt: now.addingTimeInterval(60)
            )
        ])
        let rules = [
            TestFixtures.rule(id: "waived", status: .nonCompliant),
            TestFixtures.rule(id: "eligible", status: .nonCompliant),
            TestFixtures.rule(id: "unknown", status: .unknown),
        ]

        let eligible = RemediationService.eligibleRules(
            from: rules, waivers: waivers, at: now
        )

        #expect(eligible.map(\.id) == ["eligible"])
    }
}
