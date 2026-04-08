import SwiftUI
import StigItCore

struct CategorySidebarView: View {
    @Environment(RuleStore.self) var store
    let profile: ComplianceProfile
    @Binding var selection: RuleCategory?

    var categories: [RuleCategory] {
        let used = Set(store.rules.filter { $0.profiles.contains(profile) }.map(\.category))
        return Array(used).sorted { $0.rawValue < $1.rawValue }
    }

    var body: some View {
        VStack(spacing: 0) {
            List(selection: $selection) {
                ForEach(categories) { category in
                    HStack {
                        NavigationLink(value: category) {
                            Label(category.rawValue, systemImage: category.systemImage)
                        }
                        Spacer()
                        let failing = store.rules.filter {
                            $0.profiles.contains(profile) && $0.category == category && $0.status == .nonCompliant
                        }.count
                        if failing > 0 {
                            Text("\(failing)")
                                .font(.caption2).bold()
                                .foregroundColor(.white)
                                .padding(.horizontal, 6).padding(.vertical, 2)
                                .background(Capsule().fill(Color.red))
                        }
                    }
                }
            }
            .navigationTitle("Categories")

            Divider()
            complianceSummary
        }
    }

    private var complianceSummary: some View {
        let profileRules = store.rules.filter { $0.profiles.contains(profile) }
        let compliant    = profileRules.filter { $0.status == .compliant }.count
        let score        = profileRules.isEmpty ? 0.0 : Double(compliant) / Double(profileRules.count)

        return VStack(alignment: .leading, spacing: 6) {
            Text(profile.rawValue).font(.caption).foregroundColor(.secondary)
            HStack {
                Text(String(format: "%.0f%%", score * 100))
                    .font(.title3).bold()
                    .foregroundColor(scoreColor(score))
                Spacer()
                Text("\(compliant)/\(profileRules.count)").font(.caption).foregroundColor(.secondary)
            }
            ProgressView(value: score).tint(scoreColor(score))
        }
        .padding(12)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private func scoreColor(_ score: Double) -> Color {
        score >= 0.9 ? .green : score >= 0.6 ? .orange : .red
    }
}

private extension RuleCategory {
    var systemImage: String {
        switch self {
        case .accessControl:   "person.badge.key"
        case .authentication:  "lock.shield"
        case .networkSecurity: "network.badge.shield.half.filled"
        case .systemConfig:    "gear.badge.checkmark"
        case .auditingLogging: "doc.text.magnifyingglass"
        case .dataProtection:  "externaldrive.badge.lock"
        case .encryptionPki:   "key.horizontal"
        case .mediaControls:   "opticaldisc"
        case .passwordPolicy:  "textformat.123"
        case .misc:            "wrench.and.screwdriver"
        }
    }
}
