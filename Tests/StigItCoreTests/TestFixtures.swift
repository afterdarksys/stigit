import Foundation
import StigItCore

enum TestFixtures {
    static let endpoint = EndpointInfo(
        hostname: "test-mac",
        serialNumber: "SERIAL",
        hardwareModel: "MacTest1,1",
        osVersion: "15.0",
        osBuild: "TEST"
    )

    static func rule(
        id: String = "test_rule",
        severity: RuleSeverity = .high,
        checkCommand: String = "printf pass",
        expectedResult: ExpectedResult = .string("pass"),
        status: RuleStatus = .unknown,
        selected: Bool = true,
        executionContext: RuleExecutionContext = .system
    ) -> Rule {
        Rule(
            id: id,
            title: id,
            description: "Test rule",
            profiles: [.stig],
            category: .systemConfig,
            severity: severity,
            checkCommand: checkCommand,
            expectedResult: expectedResult,
            remediateCommand: "printf remediate",
            executionContext: executionContext,
            status: status,
            isSelectedForRemediation: selected
        )
    }
}
