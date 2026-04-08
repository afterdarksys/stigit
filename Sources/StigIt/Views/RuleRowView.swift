import SwiftUI
import StigItCore

struct RuleRowView: View {
    let rule: Rule
    @Binding var isSelected: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .top) {
                Toggle(isOn: $isSelected) {
                    Text(rule.title).font(.headline)
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 4) {
                    statusBadge(rule.status)
                    severityBadge(rule.severity)
                }
            }
            Text(rule.description)
                .font(.subheadline)
                .foregroundColor(.secondary)
                .lineLimit(2)
            metaTags
        }
        .padding(.vertical, 6)
    }

    // MARK: - Private

    private var metaTags: some View {
        HStack(spacing: 8) {
            if let stigId = rule.stigId   { tag(stigId,                                     color: .purple) }
            if let cceId  = rule.cceId    { tag(cceId,                                      color: .blue)   }
            if !rule.nistControls.isEmpty { tag(rule.nistControls.prefix(2).joined(separator: ", "), color: .gray) }
            if rule.mobileconfig          { tag("MDM",                                       color: .green)  }
        }
    }

    private func tag(_ label: String, color: Color) -> some View {
        Text(label)
            .font(.system(size: 9, weight: .medium, design: .monospaced))
            .foregroundColor(color)
            .padding(.horizontal, 4).padding(.vertical, 1)
            .overlay(RoundedRectangle(cornerRadius: 3).stroke(color.opacity(0.5)))
    }

    private func statusBadge(_ status: RuleStatus) -> some View {
        let (image, color): (String, Color) = switch status {
        case .compliant:    ("checkmark.circle.fill", .green)
        case .nonCompliant: ("xmark.circle.fill",     .red)
        case .unknown:      ("questionmark.circle.fill", .gray)
        case .error:        ("exclamationmark.triangle.fill", .orange)
        }
        return Label(status.rawValue, systemImage: image).foregroundColor(color)
    }

    private func severityBadge(_ severity: RuleSeverity) -> some View {
        let color: Color = switch severity {
        case .high:   .red
        case .medium: .orange
        case .low:    .blue
        case .na:     .gray
        }
        return Text(severity.rawValue.uppercased())
            .font(.system(size: 9, weight: .bold))
            .foregroundColor(.white)
            .padding(.horizontal, 5).padding(.vertical, 2)
            .background(RoundedRectangle(cornerRadius: 3).fill(color))
    }
}
