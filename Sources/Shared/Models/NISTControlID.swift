import Foundation

/// Canonicalizes common NIST control spellings so OSCAL-style IDs such as
/// `AC-2.1`, FedRAMP IDs such as `AC-02 (01)`, and rule references such as
/// `AC-2(1)` compare as the same control.
public enum NISTControlID {
    public static func normalize(_ control: String) -> String {
        let compact = control
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "(", with: ".")
            .replacingOccurrences(of: ")", with: "")

        let components = compact.split(separator: ".", omittingEmptySubsequences: true)
        guard let base = components.first else { return compact }
        let baseParts = base.split(separator: "-", maxSplits: 1)
        guard baseParts.count == 2 else { return compact }

        let family = String(baseParts[0])
        let number = Int(baseParts[1]).map(String.init) ?? String(baseParts[1])
        let enhancements = components.dropFirst().map { component in
            Int(component).map(String.init) ?? String(component)
        }
        return (["\(family)-\(number)"] + enhancements).joined(separator: ".")
    }
}
