import SwiftUI
import StigItCore

struct DashboardView: View {
    @Environment(RuleStore.self) var store

    var body: some View {
        ScrollView {
            VStack(spacing: 30) {
                Text("Security Compliance Dashboard")
                    .font(.largeTitle).fontWeight(.bold)

                // Profile picker
                Picker("Compliance Standard", selection: Bindable(store).activeProfile) {
                    ForEach(ComplianceProfile.allCases) { profile in
                        Text(profile.rawValue).tag(profile)
                    }
                }
                .pickerStyle(.segmented)
                .padding(.horizontal)

                // Score + stats
                HStack(spacing: 50) {
                    VStack(spacing: 4) {
                        Text("Score")
                            .font(.headline)
                        Text(String(format: "%.0f%%", store.complianceScore * 100))
                            .font(.system(size: 64, weight: .bold, design: .rounded))
                            .foregroundColor(scoreColor)
                        Text("\(store.compliantCount) / \(store.totalCount)")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }

                    VStack(alignment: .leading, spacing: 10) {
                        statRow("Total Rules",    value: store.totalCount,     color: .primary)
                        statRow("Compliant",      value: store.compliantCount, color: .green)
                        statRow("Non-Compliant",
                                value: store.activeRules.filter { $0.status == .nonCompliant }.count,
                                color: .red)
                        statRow("Unknown",
                                value: store.activeRules.filter { $0.status == .unknown }.count,
                                color: .gray)
                    }
                    .font(.title3)
                }
                .padding(30)
                .background(RoundedRectangle(cornerRadius: 16).fill(Color(nsColor: .windowBackgroundColor)))
                .shadow(color: .black.opacity(0.08), radius: 8, x: 0, y: 2)

                // Severity breakdown
                if store.totalCount > 0 {
                    severityBreakdown
                }

                // Scan button + progress
                VStack(spacing: 10) {
                    Button {
                        Task {
                            store.isScanning = true
                            store.scanProgress = 0
                            var snapshot = store.rules
                            await ScannerService.scan(rules: &snapshot, profile: store.activeProfile) { done, total in
                                store.scanProgress = Double(done) / Double(total)
                            }
                            store.rules = snapshot
                            store.lastScanDate = Date()
                            store.isScanning = false
                        }
                    } label: {
                        Label("Run Full Scan", systemImage: "magnifyingglass.circle.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .disabled(store.isScanning)

                    if store.isScanning {
                        VStack(spacing: 4) {
                            ProgressView(value: store.scanProgress)
                                .frame(maxWidth: 400)
                            Text(String(format: "Scanning… %.0f%%", store.scanProgress * 100))
                                .font(.caption).foregroundColor(.secondary)
                        }
                    }

                    if let date = store.lastScanDate {
                        Text("Last scan: \(date.formatted(date: .abbreviated, time: .shortened))")
                            .font(.caption2).foregroundColor(.secondary)
                    }
                }

                Spacer()
            }
            .padding(40)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Subviews

    private var severityBreakdown: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Severity Breakdown").font(.headline)

            ForEach([RuleSeverity.high, .medium, .low], id: \.self) { sev in
                let sevRules = store.activeRules.filter { $0.severity == sev }
                if !sevRules.isEmpty {
                    let passing = sevRules.filter { $0.status == .compliant }.count
                    let score   = Double(passing) / Double(sevRules.count)
                    HStack(spacing: 12) {
                        severityDot(sev)
                        Text(sev.rawValue).frame(width: 60, alignment: .leading)
                        ProgressView(value: score)
                            .tint(severityColor(sev))
                            .frame(maxWidth: .infinity)
                        Text("\(passing)/\(sevRules.count)")
                            .font(.caption).foregroundColor(.secondary)
                            .frame(width: 40, alignment: .trailing)
                    }
                }
            }
        }
        .padding(20)
        .background(RoundedRectangle(cornerRadius: 12).fill(Color(nsColor: .windowBackgroundColor)))
        .shadow(color: .black.opacity(0.06), radius: 6)
        .padding(.horizontal)
    }

    // MARK: - Helpers

    private func statRow(_ label: String, value: Int, color: Color) -> some View {
        HStack(spacing: 12) {
            Circle()
                .fill(color)
                .frame(width: 8, height: 8)
            Text(label).foregroundColor(.secondary)
            Spacer()
            Text("\(value)").bold()
        }
    }

    private func severityDot(_ sev: RuleSeverity) -> some View {
        Circle()
            .fill(severityColor(sev))
            .frame(width: 10, height: 10)
    }

    private func severityColor(_ sev: RuleSeverity) -> Color {
        switch sev {
        case .high:   return .red
        case .medium: return .orange
        case .low:    return .blue
        case .na:     return .gray
        }
    }

    private var scoreColor: Color {
        let s = store.complianceScore
        if s >= 0.9 { return .green }
        if s >= 0.6 { return .orange }
        return .red
    }
}
