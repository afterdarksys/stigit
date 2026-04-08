import SwiftUI
import StigItCore

struct SeverityFilterBar: View {
    @Binding var selection: RuleSeverity?

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                chip(label: "All",    value: nil,     activeColor: .accentColor)
                chip(label: "High",   value: .high,   activeColor: .red)
                chip(label: "Medium", value: .medium, activeColor: .orange)
                chip(label: "Low",    value: .low,    activeColor: .blue)
            }
            .padding(.horizontal, 16).padding(.vertical, 8)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private func chip(label: String, value: RuleSeverity?, activeColor: Color) -> some View {
        Button(label) { selection = value }
            .buttonStyle(.bordered)
            .tint(selection == value ? activeColor : .secondary)
            .controlSize(.small)
    }
}
