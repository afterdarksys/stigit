import Foundation
import Yams

/// Loads Rule objects from the macos_security YAML rule files at runtime.
///
/// Usage:
/// ```swift
/// let rulesDir = URL(fileURLWithPath: "/path/to/macos_security/rules")
/// let loaded = try YAMLRuleLoader.loadRules(from: rulesDir)
/// store.rules += loaded
/// ```
///
/// This allows enterprises to:
/// - Deploy updated rule sets without recompiling the app
/// - Add custom organisational rules alongside the Apple STIG reference
/// - Pin rule sets to specific versions of the macos_security project
public struct YAMLRuleLoader {

    // MARK: - Public

    /// Load all YAML rule files found under `directory` (searches recursively).
    public static func loadRules(
        from directory: URL,
        profile overrideProfile: ComplianceProfile? = nil
    ) throws -> [Rule] {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(
            at: directory,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else { return [] }

        var rules: [Rule] = []
        for case let fileURL as URL in enumerator {
            guard fileURL.pathExtension == "yaml" else { continue }
            if let rule = try? loadRule(from: fileURL, overrideProfile: overrideProfile) {
                rules.append(rule)
            }
        }
        return rules
    }

    /// Load a single YAML file and return a Rule, or nil if the file cannot be parsed.
    public static func loadRule(from url: URL, overrideProfile: ComplianceProfile? = nil) throws -> Rule? {
        let raw = try String(contentsOf: url, encoding: .utf8)
        guard let dict = try Yams.load(yaml: raw) as? [String: Any] else { return nil }

        guard let id    = dict["id"]    as? String,
              let title = dict["title"] as? String
        else { return nil }

        let discussion = dict["discussion"] as? String ?? ""

        // --- Check command ---
        let checkCommand = (dict["check"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard !checkCommand.isEmpty else { return nil }

        // --- Expected result ---
        let expectedResult: ExpectedResult
        if let resultDict = dict["result"] as? [String: Any] {
            if let intVal = resultDict["integer"] as? Int {
                expectedResult = .integer(intVal)
            } else if let strVal = resultDict["string"] as? String {
                expectedResult = .string(strVal)
            } else if let boolVal = resultDict["boolean"] as? Bool {
                expectedResult = .integer(boolVal ? 1 : 0)
            } else {
                return nil  // No usable result type
            }
        } else {
            return nil  // Rules without a check result are informational only
        }

        // --- Fix / remediation command (strip AsciiDoc markup) ---
        let rawFix = dict["fix"] as? String ?? ""
        let remediateCommand = stripAsciiDoc(rawFix)

        // --- References ---
        let refs        = dict["references"]  as? [String: Any] ?? [:]
        let cceList     = refs["cce"]         as? [String] ?? []
        let cciList     = refs["cci"]         as? [String] ?? []
        let nist53r5    = refs["800-53r5"]    as? [String] ?? []
        let disaStigIds = refs["disa_stig"]   as? [String] ?? []

        // --- Severity ---
        let severityStr = dict["severity"] as? String ?? "medium"
        let severity: RuleSeverity
        switch severityStr.lowercased() {
        case "high":   severity = .high
        case "low":    severity = .low
        case "medium": severity = .medium
        default:       severity = .medium
        }

        // --- MobileConfig ---
        let mobileconfig = dict["mobileconfig"] as? Bool ?? false

        // --- Profiles from tags ---
        let tags = dict["tags"] as? [String] ?? []
        var profiles = Set(tags.compactMap { ComplianceProfile.from(tag: $0) })
        if let forced = overrideProfile { profiles.insert(forced) }
        if profiles.isEmpty { profiles.insert(.other) }

        // --- Category from file path ---
        let category = inferCategory(from: url, ruleId: id)

        // --- ODV substitution ---
        let finalCheck     = substituteODV(checkCommand,     odv: dict["odv"])
        let finalRemediate = substituteODV(remediateCommand, odv: dict["odv"])

        return Rule(
            id: id,
            title: title,
            description: discussion.trimmingCharacters(in: .whitespacesAndNewlines),
            profiles: Array(profiles),
            category: category,
            severity: severity,
            stigId: disaStigIds.first,
            cceId: cceList.first,
            cciIds: cciList,
            nistControls: nist53r5,
            checkCommand: finalCheck,
            expectedResult: expectedResult,
            remediateCommand: finalRemediate,
            mobileconfig: mobileconfig
        )
    }

    // MARK: - Private helpers

    /// Infer a RuleCategory from the file path and rule ID.
    private static func inferCategory(from url: URL, ruleId: String) -> RuleCategory {
        let dir = url.deletingLastPathComponent().lastPathComponent
        switch dir {
        case "audit":          return .auditingLogging
        case "auth":           return .authentication
        case "pwpolicy":       return .passwordPolicy
        case "icloud":         return .networkSecurity
        default: break
        }
        // Deeper inference from rule ID prefix
        if ruleId.hasPrefix("os_sshd") || ruleId.hasPrefix("os_ssh") || ruleId.hasPrefix("auth_ssh") {
            return .authentication
        }
        if ruleId.contains("filevault") || ruleId.contains("sip") || ruleId.contains("gatekeeper") {
            return .dataProtection
        }
        if ruleId.contains("bluetooth") || ruleId.contains("wifi") || ruleId.contains("firewall")
            || ruleId.contains("bonjour") || ruleId.contains("sharing") || ruleId.contains("airdrop") {
            return .networkSecurity
        }
        if ruleId.contains("camera") || ruleId.contains("bluray") || ruleId.contains("_cd_")
            || ruleId.contains("_dvd_") || ruleId.contains("media") {
            return .mediaControls
        }
        if ruleId.contains("smartcard") || ruleId.contains("pam_") || ruleId.contains("pki") {
            return .authentication
        }
        if ruleId.contains("password") || ruleId.contains("pwpolicy") {
            return .passwordPolicy
        }
        return .systemConfig
    }

    /// Replace `$ODV` placeholders with the recommended (or STIG) value.
    private static func substituteODV(_ text: String, odv: Any?) -> String {
        guard text.contains("$ODV"), let odvDict = odv as? [String: Any] else { return text }
        // Prefer the STIG value; fall back to recommended
        let value: String
        if let stig = odvDict["stig"] as? String {
            value = stig
        } else if let rec = odvDict["recommended"] {
            value = String(describing: rec)
        } else {
            return text
        }
        return text.replacingOccurrences(of: "$ODV", with: value)
    }

    /// Strip AsciiDoc source block markers that appear in fix: fields of macos_security YAMLs.
    ///
    /// Example input:
    /// ```
    /// [source,bash]
    /// ----
    /// /bin/launchctl enable system/com.apple.auditd
    /// ----
    /// ```
    private static func stripAsciiDoc(_ text: String) -> String {
        var lines = text.components(separatedBy: "\n")
        lines = lines.filter { line in
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            return trimmed != "----" && !trimmed.hasPrefix("[source,")
        }
        return lines.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
