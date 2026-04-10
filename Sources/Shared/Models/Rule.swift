import Foundation

public enum ComplianceProfile: String, Codable, CaseIterable, Sendable, Identifiable {
    case stig     = "DISA STIG"
    case nist     = "NIST 800-53"
    case soc2     = "SOC2"
    case iso27001 = "ISO/IEC 27001"
    case gdpr     = "GDPR"
    case cmmc1    = "CMMC Level 1"
    case cmmc2    = "CMMC Level 2"
    case cisL1    = "CIS Level 1"
    case cisL2    = "CIS Level 2"
    case cnssi    = "CNSSI-1253"
    case nist171  = "NIST 800-171"
    case sox      = "SOX"
    case hipaa    = "HIPAA"
    case glba     = "GLBA"
    case other    = "Other / OS Tweaks"

    public var id: String { rawValue }

    /// Maps the YAML tag strings from the macos_security project to profiles
    public static func from(tag: String) -> ComplianceProfile? {
        switch tag {
        case "stig":                        return .stig
        case "800-53r5_low", "800-53r5_moderate", "800-53r5_high",
             "800-53r4_low",  "800-53r4_moderate", "800-53r4_high": return .nist
        case "800-171":                     return .nist171
        case "cis_lvl1":                    return .cisL1
        case "cis_lvl2":                    return .cisL2
        case "cisv8":                       return .cisL2
        case "cmmc_lvl1":                   return .cmmc1
        case "cmmc_lvl2":                   return .cmmc2
        case "cnssi-1253_low", "cnssi-1253_moderate", "cnssi-1253_high": return .cnssi
        default:                            return nil
        }
    }
}

public enum RuleCategory: String, Codable, CaseIterable, Sendable, Identifiable {
    case accessControl    = "Access Control"
    case authentication   = "Authentication"
    case networkSecurity  = "Network Security"
    case systemConfig     = "System Configuration"
    case auditingLogging  = "Auditing & Logging"
    case dataProtection   = "Data Protection"
    case encryptionPki    = "Encryption & PKI"
    case mediaControls    = "Media Controls"
    case passwordPolicy   = "Password Policy"
    case misc             = "Misc Utilities"

    public var id: String { rawValue }
}

public enum RuleSeverity: String, Codable, CaseIterable, Sendable {
    case high    = "High"
    case medium  = "Medium"
    case low     = "Low"
    case na      = "N/A"
}

/// The expected result type from a check command
public enum ExpectedResult: Codable, Sendable, Equatable {
    case string(String)
    case integer(Int)

    public var description: String {
        switch self {
        case .string(let s):  return s
        case .integer(let i): return String(i)
        }
    }
}

public enum RuleStatus: String, Codable, CaseIterable, Sendable {
    case compliant    = "Compliant"
    case nonCompliant = "Non-Compliant"
    case unknown      = "Unknown"
    case error        = "Error"
}

public struct Rule: Identifiable, Codable, Hashable, Sendable {
    // Identity
    public let id: String
    public let title: String
    public let description: String

    // Classification
    public let profiles: [ComplianceProfile]
    public let category: RuleCategory
    public let severity: RuleSeverity

    // Compliance metadata
    public let stigId: String?      // e.g. "APPL-26-001003"
    public let cceId: String?       // e.g. "CCE-95104-6"
    public let cciIds: [String]     // e.g. ["CCI-000130", ...]
    public let nistControls: [String] // e.g. ["AU-3", "AU-12"]

    // Check / remediate
    public let checkCommand: String
    public let expectedResult: ExpectedResult
    public let remediateCommand: String

    // MDM support
    public let mobileconfig: Bool

    // Application state (mutable)
    public var status: RuleStatus = .unknown
    public var isSelectedForRemediation: Bool = true

    // Convenience initialiser with sensible defaults for non-STIG rules
    public init(
        id: String,
        title: String,
        description: String,
        profiles: [ComplianceProfile],
        category: RuleCategory,
        severity: RuleSeverity = .medium,
        stigId: String? = nil,
        cceId: String? = nil,
        cciIds: [String] = [],
        nistControls: [String] = [],
        checkCommand: String,
        expectedResult: ExpectedResult,
        remediateCommand: String,
        mobileconfig: Bool = false,
        status: RuleStatus = .unknown,
        isSelectedForRemediation: Bool = true
    ) {
        self.id = id
        self.title = title
        self.description = description
        self.profiles = profiles
        self.category = category
        self.severity = severity
        self.stigId = stigId
        self.cceId = cceId
        self.cciIds = cciIds
        self.nistControls = nistControls
        self.checkCommand = checkCommand
        self.expectedResult = expectedResult
        self.remediateCommand = remediateCommand
        self.mobileconfig = mobileconfig
        self.status = status
        self.isSelectedForRemediation = isSelectedForRemediation
    }

    public func hash(into hasher: inout Hasher) { hasher.combine(id) }
    public static func == (lhs: Rule, rhs: Rule) -> Bool { lhs.id == rhs.id }
}
