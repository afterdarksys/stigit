import Foundation
import Observation

@MainActor
@Observable
public class RuleStore {
    public var rules: [Rule] = []
    public var activeProfile: ComplianceProfile = .stig
    public var isScanning: Bool = false
    public var scanProgress: Double = 0.0
    public var lastScanDate: Date? = nil

    public init() {
        rules = Self.defaultRules()
    }

    // MARK: - Derived

    public var activeRules: [Rule] {
        rules.filter { $0.profiles.contains(activeProfile) }
    }

    public var compliantCount: Int    { activeRules.filter { $0.status == .compliant }.count }
    public var totalCount: Int        { activeRules.count }

    public var complianceScore: Double {
        guard totalCount > 0 else { return 0 }
        return Double(compliantCount) / Double(totalCount)
    }

    // MARK: - Default rule library (assembled from category extensions)

    public static func defaultRules() -> [Rule] {
        var rules: [Rule] = []
        rules += accessControlRules()
        rules += authenticationRules()
        rules += networkSecurityRules()
        rules += auditingRules()
        rules += dataProtectionRules()
        rules += passwordPolicyRules()
        rules += mediaControlRules()
        rules += miscRules()
        rules += financialHealthcareRules()
        return rules
    }
}
