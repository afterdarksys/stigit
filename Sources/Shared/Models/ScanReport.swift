import Foundation

/// Outcome of a single rule after waivers are applied. Distinct from `RuleStatus`:
/// a rule can be technically non-compliant but `waived` for reporting and gating.
public enum RuleOutcome: String, Codable, CaseIterable, Sendable {
    case compliant    = "compliant"
    case nonCompliant = "non_compliant"
    case waived       = "waived"
    case unknown      = "unknown"
    case error        = "error"
}

/// The canonical, schema-versioned scan result. Every exporter, the history store,
/// and the fleet layer consume this one model so all outputs agree.
public struct ScanReport: Codable, Sendable {
    public struct RuleResult: Codable, Sendable, Identifiable {
        public let id: String
        public let title: String
        public let category: String
        public let severity: RuleSeverity
        public let outcome: RuleOutcome
        public let stigId: String?
        public let cceId: String?
        public let nistControls: [String]
        public let waiver: Waiver?
    }

    public struct Summary: Codable, Sendable {
        public let total: Int
        public let compliant: Int
        public let nonCompliant: Int
        public let waived: Int
        public let unknown: Int
        public let errors: Int
        /// Fraction 0…1 of decided rules that pass; waived rules count as neither.
        public let score: Double
    }

    public struct Drift: Codable, Sendable {
        public struct Change: Codable, Sendable {
            public let ruleID: String
            public let title: String
            public let severity: RuleSeverity
        }
        public let baselineDate: Date
        /// Rules that passed in the baseline and fail now.
        public let regressions: [Change]
        /// Rules that failed in the baseline and pass now.
        public let fixes: [Change]
    }

    public static let currentSchemaVersion = 1

    public let schemaVersion: Int
    public let generatedAt: Date
    public let endpoint: EndpointInfo
    public let profileName: String
    public let profileKey: String
    public let results: [RuleResult]
    public var drift: Drift?

    public var summary: Summary {
        let counts = Dictionary(grouping: results, by: \.outcome).mapValues(\.count)
        let compliant = counts[.compliant] ?? 0
        let nonCompliant = counts[.nonCompliant] ?? 0
        let decided = compliant + nonCompliant
        return Summary(
            total: results.count,
            compliant: compliant,
            nonCompliant: nonCompliant,
            waived: counts[.waived] ?? 0,
            unknown: counts[.unknown] ?? 0,
            errors: counts[.error] ?? 0,
            score: decided == 0 ? 1.0 : Double(compliant) / Double(decided)
        )
    }

    /// Unwaived failing rules at or above the given severity — the exit-code gate.
    public func failures(atOrAbove threshold: RuleSeverity) -> [RuleResult] {
        let order: [RuleSeverity: Int] = [.high: 3, .medium: 2, .low: 1, .na: 0]
        let floor = order[threshold] ?? 0
        return results.filter { $0.outcome == .nonCompliant && (order[$0.severity] ?? 0) >= floor }
    }

    /// Builds a report from scanned rules, applying any active waivers.
    public init(
        rules: [Rule],
        profile: ComplianceProfile,
        endpoint: EndpointInfo = .current(),
        waivers: WaiverStore? = nil,
        generatedAt: Date = Date()
    ) {
        self.schemaVersion = Self.currentSchemaVersion
        self.generatedAt = generatedAt
        self.endpoint = endpoint
        self.profileName = profile.rawValue
        self.profileKey = profile.key
        self.results = rules
            .filter { $0.profiles.contains(profile) }
            .map { rule in
                let waiver = waivers?.activeWaiver(for: rule.id, at: generatedAt)
                let outcome: RuleOutcome
                switch rule.status {
                case .compliant:    outcome = .compliant
                case .nonCompliant: outcome = waiver != nil ? .waived : .nonCompliant
                case .unknown:      outcome = .unknown
                case .error:        outcome = .error
                }
                return RuleResult(
                    id: rule.id,
                    title: rule.title,
                    category: rule.category.rawValue,
                    severity: rule.severity,
                    outcome: outcome,
                    stigId: rule.stigId,
                    cceId: rule.cceId,
                    nistControls: rule.nistControls,
                    waiver: outcome == .waived ? waiver : nil
                )
            }
    }

    // MARK: - JSON round-trip

    public static func jsonEncoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }

    public static func jsonDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }

    public func jsonData() throws -> Data {
        try Self.jsonEncoder().encode(self)
    }

    public static func from(jsonData: Data) throws -> ScanReport {
        try jsonDecoder().decode(ScanReport.self, from: jsonData)
    }
}
