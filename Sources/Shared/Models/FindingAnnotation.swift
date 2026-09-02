import Foundation

/// Operational disposition applied by an analyst after a scan. Labels describe
/// workflow state only; they never change a rule's measured compliance outcome.
public enum FindingLabel: String, Codable, CaseIterable, Sendable, Identifiable {
    case needsReview = "Needs Review"
    case remediationPlanned = "Remediation Planned"
    case compensatingControl = "Compensating Control"
    case notApplicable = "Not Applicable"
    case possibleFalsePositive = "Possible False Positive"

    public var id: String { rawValue }
}

/// Durable analyst context for one rule, profile, and endpoint.
public struct FindingAnnotation: Codable, Hashable, Sendable, Identifiable {
    public let endpointID: String
    public let profileKey: String
    public let ruleID: String
    public var labels: [FindingLabel]
    public var customTags: [String]
    public var note: String
    public var owner: String?
    public var ticket: String?
    public var dueDate: Date?
    public let createdAt: Date
    public var updatedAt: Date
    public var updatedBy: String

    public var id: String { "\(endpointID)|\(profileKey)|\(ruleID)" }

    public init(
        endpointID: String,
        profileKey: String,
        ruleID: String,
        labels: [FindingLabel] = [],
        customTags: [String] = [],
        note: String = "",
        owner: String? = nil,
        ticket: String? = nil,
        dueDate: Date? = nil,
        createdAt: Date = Date(),
        updatedAt: Date = Date(),
        updatedBy: String
    ) {
        self.endpointID = endpointID
        self.profileKey = profileKey
        self.ruleID = ruleID
        self.labels = Array(Set(labels)).sorted { $0.rawValue < $1.rawValue }
        self.customTags = Array(Set(customTags.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty })).sorted()
        self.note = note.trimmingCharacters(in: .whitespacesAndNewlines)
        self.owner = Self.nonEmpty(owner)
        self.ticket = Self.nonEmpty(ticket)
        self.dueDate = dueDate
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.updatedBy = updatedBy.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    public static func endpointID(for endpoint: EndpointInfo) -> String {
        endpoint.serialNumber ?? endpoint.hostname
    }

    public var isEmpty: Bool {
        labels.isEmpty && customTags.isEmpty && note.isEmpty
            && owner == nil && ticket == nil && dueDate == nil
    }

    private static func nonEmpty(_ value: String?) -> String? {
        guard let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines),
              !trimmed.isEmpty else { return nil }
        return trimmed
    }
}

/// Local annotation persistence shared by the app and report pipeline.
public struct FindingAnnotationStore: Sendable {
    public private(set) var annotations: [FindingAnnotation]
    public let fileURL: URL

    public static func defaultFileURL() -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".stigit/annotations.json")
    }

    public static func load(from url: URL = defaultFileURL()) throws -> FindingAnnotationStore {
        guard FileManager.default.fileExists(atPath: url.path) else {
            return FindingAnnotationStore(annotations: [], fileURL: url)
        }
        let data = try Data(contentsOf: url)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return FindingAnnotationStore(
            annotations: try decoder.decode([FindingAnnotation].self, from: data),
            fileURL: url
        )
    }

    public init(
        annotations: [FindingAnnotation],
        fileURL: URL = FindingAnnotationStore.defaultFileURL()
    ) {
        self.annotations = annotations.sorted { $0.id < $1.id }
        self.fileURL = fileURL
    }

    public func annotation(
        for ruleID: String,
        profileKey: String,
        endpoint: EndpointInfo
    ) -> FindingAnnotation? {
        let endpointID = FindingAnnotation.endpointID(for: endpoint)
        return annotations.first {
            $0.ruleID == ruleID && $0.profileKey == profileKey && $0.endpointID == endpointID
        }
    }

    public mutating func upsert(_ annotation: FindingAnnotation) {
        annotations.removeAll { $0.id == annotation.id }
        if !annotation.isEmpty {
            annotations.append(annotation)
            annotations.sort { $0.id < $1.id }
        }
    }

    @discardableResult
    public mutating func remove(
        ruleID: String,
        profileKey: String,
        endpoint: EndpointInfo
    ) -> Bool {
        let endpointID = FindingAnnotation.endpointID(for: endpoint)
        let before = annotations.count
        annotations.removeAll {
            $0.ruleID == ruleID && $0.profileKey == profileKey && $0.endpointID == endpointID
        }
        return annotations.count != before
    }

    public func save() throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(annotations)
        try FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try data.write(to: fileURL, options: .atomic)
    }
}
