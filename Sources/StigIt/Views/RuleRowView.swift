import SwiftUI
import StigItCore

struct RuleRowView: View {
    let rule: Rule
    @Binding var isSelected: Bool
    let annotation: FindingAnnotation?
    let onAnnotate: () -> Void

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
                    Button(action: onAnnotate) {
                        Label(annotation == nil ? "Label" : "Edit labels",
                              systemImage: annotation == nil ? "tag" : "tag.fill")
                            .font(.caption)
                    }
                    .buttonStyle(.plain)
                    .foregroundColor(annotation == nil ? .secondary : .accentColor)
                    .accessibilityHint("Add workflow labels, notes, ownership, and ticket details")
                }
            }
            Text(rule.description)
                .font(.subheadline)
                .foregroundColor(.secondary)
                .lineLimit(2)
            metaTags
            if let annotation {
                annotationTags(annotation)
            }
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

    private func annotationTags(_ annotation: FindingAnnotation) -> some View {
        HStack(spacing: 6) {
            ForEach(annotation.labels.prefix(3)) { label in
                tag(label.rawValue, color: labelColor(label))
            }
            ForEach(annotation.customTags.prefix(max(0, 3 - annotation.labels.count)), id: \.self) {
                tag($0, color: .teal)
            }
            let remaining = annotation.labels.count + annotation.customTags.count - 3
            if remaining > 0 { tag("+\(remaining)", color: .secondary) }
            if annotation.owner != nil { Image(systemName: "person.crop.circle").foregroundColor(.secondary) }
            if annotation.ticket != nil { Image(systemName: "number.square").foregroundColor(.secondary) }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Finding labels")
    }

    private func labelColor(_ label: FindingLabel) -> Color {
        switch label {
        case .needsReview:           return .orange
        case .remediationPlanned:    return .blue
        case .compensatingControl:   return .indigo
        case .notApplicable:         return .gray
        case .possibleFalsePositive: return .pink
        }
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
