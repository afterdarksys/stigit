import Foundation

public enum ComplianceProfile: String, Codable, CaseIterable, Sendable, Identifiable {
    case stig     = "DISA STIG"
    case nist     = "NIST 800-53"
    case fismaLow = "FISMA Low Impact"
    case fismaModerate = "FISMA Moderate Impact"
    case fismaHigh = "FISMA High Impact"
    case fedrampB = "FedRAMP Rev. 5 Class B"
    case fedrampC = "FedRAMP Rev. 5 Class C"
    case fedrampD = "FedRAMP Rev. 5 Class D"
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

    /// Short machine key used by the CLI, report schemas, and history filenames.
    public var key: String {
        switch self {
        case .stig:     return "stig"
        case .nist:     return "nist"
        case .fismaLow: return "fisma-low"
        case .fismaModerate: return "fisma-moderate"
        case .fismaHigh: return "fisma-high"
        case .fedrampB: return "fedramp-b"
        case .fedrampC: return "fedramp-c"
        case .fedrampD: return "fedramp-d"
        case .soc2:     return "soc2"
        case .iso27001: return "iso27001"
        case .gdpr:     return "gdpr"
        case .cmmc1:    return "cmmc1"
        case .cmmc2:    return "cmmc2"
        case .cisL1:    return "cis1"
        case .cisL2:    return "cis2"
        case .cnssi:    return "cnssi"
        case .nist171:  return "nist171"
        case .sox:      return "sox"
        case .hipaa:    return "hipaa"
        case .glba:     return "glba"
        case .other:    return "other"
        }
    }

    public static func from(key: String) -> ComplianceProfile? {
        let normalized = key.lowercased()
        if let canonical = allCases.first(where: { $0.key == normalized }) {
            return canonical
        }
        switch normalized {
        case "fedramp-class-b", "fedramp-low", "fedramp-li-saas", "fedramp-lisaas":
            return .fedrampB
        case "fedramp-class-c", "fedramp-moderate":
            return .fedrampC
        case "fedramp-class-d", "fedramp-high":
            return .fedrampD
        default:
            return nil
        }
    }

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

    /// One tag can contribute both the general NIST profile and a versioned
    /// FISMA impact baseline. Revision 4 tags intentionally remain NIST-only.
    public static func all(fromTag tag: String) -> [ComplianceProfile] {
        switch tag {
        case "800-53r5_low":      return [.nist, .fismaLow]
        case "800-53r5_moderate": return [.nist, .fismaModerate]
        case "800-53r5_high":     return [.nist, .fismaHigh]
        default:                   return from(tag: tag).map { [$0] } ?? []
        }
    }

    public var frameworkInfo: ComplianceFrameworkInfo? {
        switch self {
        case .fismaLow, .fismaModerate, .fismaHigh:
            guard let controls = FISMAControlBaselines.controls(for: self) else { return nil }
            let baseline: String
            switch self {
            case .fismaLow:      baseline = "Low"
            case .fismaModerate: baseline = "Moderate"
            case .fismaHigh:     baseline = "High"
            default:             return nil
            }
            return ComplianceFrameworkInfo(
                name: "Federal Information Security Modernization Act (FISMA)",
                version: FISMAControlBaselines.version,
                baseline: baseline,
                baselineControlCount: controls.count,
                source: FISMAControlBaselines.source,
                scopeNote: FISMAControlBaselines.scopeNote
            )
        case .fedrampB, .fedrampC, .fedrampD:
            guard let controls = FedRAMPControlBaselines.controls(for: self) else { return nil }
            let baseline: String
            switch self {
            case .fedrampB: baseline = "Rev. 5 Class B (Low / LI-SaaS successor)"
            case .fedrampC: baseline = "Rev. 5 Class C (Moderate successor)"
            case .fedrampD: baseline = "Rev. 5 Class D (High successor)"
            default: return nil
            }
            return ComplianceFrameworkInfo(
                name: "FedRAMP Consolidated Rules for 2026",
                version: FedRAMPControlBaselines.version,
                baseline: baseline,
                baselineControlCount: controls.count,
                source: FedRAMPControlBaselines.source,
                scopeNote: FedRAMPControlBaselines.scopeNote
            )
        default:
            return nil
        }
    }

    public var baselineControls: Set<String>? {
        FISMAControlBaselines.controls(for: self) ?? FedRAMPControlBaselines.controls(for: self)
    }
}

public struct ComplianceFrameworkInfo: Codable, Hashable, Sendable {
    public let name: String
    public let version: String
    public let baseline: String
    public let baselineControlCount: Int
    public let source: String
    public let scopeNote: String

    public var versionDescription: String {
        name.hasPrefix("FedRAMP")
            ? "rules version \(version) · NIST SP 800-53 Rev. 5.2.0"
            : "NIST SP 800-53B \(version)"
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

public enum RuleExecutionContext: String, Codable, Sendable {
    case system
    case consoleUser = "console_user"
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
    public let executionContext: RuleExecutionContext

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
        executionContext: RuleExecutionContext = .system,
        mobileconfig: Bool = false,
        status: RuleStatus = .unknown,
        isSelectedForRemediation: Bool = true,
        mapNISTControlsToFISMA: Bool = true,
        mapNISTControlsToFedRAMP: Bool = true
    ) {
        self.id = id
        self.title = title
        self.description = description
        var resolvedProfiles = profiles
        if mapNISTControlsToFISMA && profiles.contains(.nist) {
            for profile in FISMAControlBaselines.profiles(for: nistControls)
                where !resolvedProfiles.contains(profile) {
                resolvedProfiles.append(profile)
            }
        }
        if mapNISTControlsToFedRAMP && profiles.contains(.nist) {
            for profile in FedRAMPControlBaselines.profiles(for: nistControls)
                where !resolvedProfiles.contains(profile) {
                resolvedProfiles.append(profile)
            }
        }
        self.profiles = resolvedProfiles
        self.category = category
        self.severity = severity
        self.stigId = stigId
        self.cceId = cceId
        self.cciIds = cciIds
        self.nistControls = nistControls
        self.checkCommand = checkCommand
        self.expectedResult = expectedResult
        self.remediateCommand = remediateCommand
        self.executionContext = executionContext
        self.mobileconfig = mobileconfig
        self.status = status
        self.isSelectedForRemediation = isSelectedForRemediation
    }

    public func hash(into hasher: inout Hasher) { hasher.combine(id) }
    public static func == (lhs: Rule, rhs: Rule) -> Bool { lhs.id == rhs.id }
}
