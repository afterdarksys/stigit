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
    private enum CodingKeys: String, CodingKey {
        case schemaVersion, generatedAt, endpoint, profileName, profileKey
        case results, drift, summary
    }
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
        public let annotation: FindingAnnotation?
    }

    public struct Summary: Codable, Sendable {
        public let total: Int
        public let compliant: Int
        public let nonCompliant: Int
        public let waived: Int
        public let unknown: Int
        public let errors: Int
        /// Fraction 0…1 of unwaived rules that pass. Unknown and errored controls
        /// count as not passing so an incomplete evaluation never appears compliant.
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

    public static let currentSchemaVersion = 2

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
        let evaluated = compliant + nonCompliant
            + (counts[.unknown] ?? 0) + (counts[.error] ?? 0)
        return Summary(
            total: results.count,
            compliant: compliant,
            nonCompliant: nonCompliant,
            waived: counts[.waived] ?? 0,
            unknown: counts[.unknown] ?? 0,
            errors: counts[.error] ?? 0,
            score: evaluated == 0 ? 0 : Double(compliant) / Double(evaluated)
        )
    }

    /// Unwaived failing or errored rules at or above the given severity — the
    /// exit-code gate. A check that could not be evaluated must never pass CI.
    public func failures(atOrAbove threshold: RuleSeverity) -> [RuleResult] {
        let order: [RuleSeverity: Int] = [.high: 3, .medium: 2, .low: 1, .na: 0]
        let floor = order[threshold] ?? 0
        return results.filter {
            ($0.outcome == .nonCompliant || $0.outcome == .error)
                && (order[$0.severity] ?? 0) >= floor
        }
    }

    /// Builds a report from scanned rules, applying any active waivers.
    public init(
        rules: [Rule],
        profile: ComplianceProfile,
        endpoint: EndpointInfo = .current(),
        waivers: WaiverStore? = nil,
        annotations: FindingAnnotationStore? = nil,
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
                    waiver: outcome == .waived ? waiver : nil,
                    annotation: annotations?.annotation(
                        for: rule.id,
                        profileKey: profile.key,
                        endpoint: endpoint
                    )
                )
            }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let version = try container.decode(Int.self, forKey: .schemaVersion)
        guard version == 1 || version == Self.currentSchemaVersion else {
            throw DecodingError.dataCorruptedError(
                forKey: .schemaVersion,
                in: container,
                debugDescription: "Unsupported ScanReport schema version \(version)"
            )
        }
        schemaVersion = version
        generatedAt = try container.decode(Date.self, forKey: .generatedAt)
        endpoint = try container.decode(EndpointInfo.self, forKey: .endpoint)
        profileName = try container.decode(String.self, forKey: .profileName)
        profileKey = try container.decode(String.self, forKey: .profileKey)
        results = try container.decode([RuleResult].self, forKey: .results)
        drift = try container.decodeIfPresent(Drift.self, forKey: .drift)
        // `summary` is derived from results. Decode is intentionally optional so
        // schema-v1 reports produced before it was explicitly encoded still load.
        _ = try container.decodeIfPresent(Summary.self, forKey: .summary)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(schemaVersion, forKey: .schemaVersion)
        try container.encode(generatedAt, forKey: .generatedAt)
        try container.encode(endpoint, forKey: .endpoint)
        try container.encode(profileName, forKey: .profileName)
        try container.encode(profileKey, forKey: .profileKey)
        try container.encode(results, forKey: .results)
        try container.encodeIfPresent(drift, forKey: .drift)
        try container.encode(summary, forKey: .summary)
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
