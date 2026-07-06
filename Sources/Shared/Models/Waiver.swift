import Foundation

/// A documented, time-boxed exception for a single rule. Auditors expect waivers to
/// carry an owner, a justification, and an expiry — an expired waiver is a finding again.
public struct Waiver: Codable, Hashable, Sendable, Identifiable {
    public let ruleID: String
    public let reason: String
    public let approvedBy: String
    public let ticket: String?
    public let createdAt: Date
    public let expiresAt: Date?

    public var id: String { ruleID }

    public init(
        ruleID: String,
        reason: String,
        approvedBy: String,
        ticket: String? = nil,
        createdAt: Date = Date(),
        expiresAt: Date? = nil
    ) {
        self.ruleID = ruleID
        self.reason = reason
        self.approvedBy = approvedBy
        self.ticket = ticket
        self.createdAt = createdAt
        self.expiresAt = expiresAt
    }

    public func isActive(at date: Date = Date()) -> Bool {
        guard let expiresAt else { return true }
        return date < expiresAt
    }
}

/// Loads and persists the waiver file (JSON array of `Waiver`).
public struct WaiverStore: Sendable {
    public private(set) var waivers: [Waiver]
    public let fileURL: URL

    public static func defaultFileURL() -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".stigit/waivers.json")
    }

    /// Loads the store from disk; a missing file yields an empty store, but a
    /// malformed file throws so a typo never silently drops every waiver.
    public static func load(from url: URL = defaultFileURL()) throws -> WaiverStore {
        guard FileManager.default.fileExists(atPath: url.path) else {
            return WaiverStore(waivers: [], fileURL: url)
        }
        let data = try Data(contentsOf: url)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return WaiverStore(waivers: try decoder.decode([Waiver].self, from: data), fileURL: url)
    }

    public init(waivers: [Waiver], fileURL: URL = WaiverStore.defaultFileURL()) {
        self.waivers = waivers
        self.fileURL = fileURL
    }

    public func activeWaiver(for ruleID: String, at date: Date = Date()) -> Waiver? {
        waivers.first { $0.ruleID == ruleID && $0.isActive(at: date) }
    }

    public func expiredWaivers(at date: Date = Date()) -> [Waiver] {
        waivers.filter { !$0.isActive(at: date) }
    }

    /// Adds or replaces the waiver for a rule (one waiver per rule).
    public mutating func upsert(_ waiver: Waiver) {
        waivers.removeAll { $0.ruleID == waiver.ruleID }
        waivers.append(waiver)
        waivers.sort { $0.ruleID < $1.ruleID }
    }

    @discardableResult
    public mutating func remove(ruleID: String) -> Bool {
        let before = waivers.count
        waivers.removeAll { $0.ruleID == ruleID }
        return waivers.count != before
    }

    public func save() throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(waivers)
        try FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try data.write(to: fileURL, options: .atomic)
    }
}
