import SwiftUI
import StigItCore

struct StandardWorkflowView: View {
    @Environment(RuleStore.self) var store
    let profile: ComplianceProfile

    @State private var selectedCategory: RuleCategory? = nil
    @State private var showingStaging = false
    @State private var severityFilter: RuleSeverity? = nil
    @State private var exportError: String? = nil
    @State private var showExportSuccess = false
    @State private var exportedURL: URL? = nil

    var filteredRules: [Rule] {
        store.rules.filter {
            $0.profiles.contains(profile)
            && $0.category == selectedCategory
            && (severityFilter == nil || $0.severity == severityFilter)
        }
    }

    var categoriesForProfile: [RuleCategory] {
        let cats = Set(store.rules.filter { $0.profiles.contains(profile) }.map(\.category))
        return Array(cats).sorted { $0.rawValue < $1.rawValue }
    }

    var body: some View {
        NavigationSplitView {
            sidebarView
        } detail: {
            detailView
        }
        .sheet(isPresented: $showingStaging) {
            StagingModalView(profile: profile)
                .frame(minWidth: 600, minHeight: 400)
        }
        .onAppear {
            if selectedCategory == nil {
                selectedCategory = categoriesForProfile.first
            }
        }
        .alert("Export Error", isPresented: Binding(
            get: { exportError != nil },
            set: { if !$0 { exportError = nil } }
        )) {
            Button("OK") { exportError = nil }
        } message: {
            Text(exportError ?? "")
        }
        .alert("Export Complete", isPresented: $showExportSuccess) {
            Button("OK") { showExportSuccess = false }
        } message: {
            if let url = exportedURL {
                Text("Report saved to:\n\(url.path)")
            }
        }
    }

    // MARK: - Sidebar

    private var sidebarView: some View {
        VStack(spacing: 0) {
            List(selection: $selectedCategory) {
                ForEach(categoriesForProfile) { category in
                    HStack {
                        NavigationLink(value: category) {
                            Label(category.rawValue, systemImage: categoryIcon(category))
                        }
                        Spacer()
                        let count = store.rules.filter {
                            $0.profiles.contains(profile) && $0.category == category && $0.status == .nonCompliant
                        }.count
                        if count > 0 {
                            Text("\(count)")
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
            complianceMiniSummary
        }
    }

    private var complianceMiniSummary: some View {
        let profileRules = store.rules.filter { $0.profiles.contains(profile) }
        let score = profileRules.isEmpty ? 0.0 :
            Double(profileRules.filter { $0.status == .compliant }.count) / Double(profileRules.count)

        return VStack(alignment: .leading, spacing: 6) {
            Text(profile.rawValue).font(.caption).foregroundColor(.secondary)
            HStack {
                Text(String(format: "%.0f%%", score * 100))
                    .font(.title3).bold()
                    .foregroundColor(scoreColor(score))
                Spacer()
                Text("\(profileRules.filter { $0.status == .compliant }.count)/\(profileRules.count)")
                    .font(.caption).foregroundColor(.secondary)
            }
            ProgressView(value: score)
                .tint(scoreColor(score))
        }
        .padding(12)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    // MARK: - Detail

    private var detailView: some View {
        VStack(spacing: 0) {
            // Severity filter chips
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    filterChip(label: "All", value: nil)
                    filterChip(label: "High",   value: .high,   color: .red)
                    filterChip(label: "Medium", value: .medium, color: .orange)
                    filterChip(label: "Low",    value: .low,    color: .blue)
                }
                .padding(.horizontal, 16).padding(.vertical, 8)
            }
            .background(Color(nsColor: .windowBackgroundColor))

            Divider()

            // Rule list
            List {
                ForEach(filteredRules) { rule in
                    if let index = store.rules.firstIndex(where: { $0.id == rule.id }) {
                        @Bindable var bindableStore = store
                        ruleRow(rule: rule, binding: $bindableStore.rules[index])
                    }
                }
            }
            .navigationTitle(selectedCategory.map {
                "\(profile.rawValue)  ·  \($0.rawValue)"
            } ?? profile.rawValue)
            .toolbar { toolbarItems }

            // Bottom action bar
            Divider()
            actionBar
        }
    }

    @ToolbarContentBuilder
    private var toolbarItems: some ToolbarContent {
        ToolbarItem(placement: .automatic) {
            if store.isScanning {
                HStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    Text("Scanning…").font(.caption)
                }
            }
        }
        ToolbarItem(placement: .automatic) {
            Menu {
                Button("Export JSON") { exportReport(.json) }
                Button("Export CSV")  { exportReport(.csv) }
                Button("Export Summary") { exportReport(.summary) }
                Divider()
                Button("Generate .mobileconfig") { generateMobileConfig() }
            } label: {
                Label("Export", systemImage: "square.and.arrow.up")
            }
        }
    }

    // MARK: - Rule Row

    private func ruleRow(rule: Rule, binding: Binding<Rule>) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .top) {
                Toggle(isOn: binding.isSelectedForRemediation) {
                    Text(rule.title).font(.headline)
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 4) {
                    statusIcon(for: rule.status)
                    severityBadge(rule.severity)
                }
            }
            Text(rule.description)
                .font(.subheadline)
                .foregroundColor(.secondary)
                .lineLimit(2)
            HStack(spacing: 8) {
                if let stigId = rule.stigId {
                    metaTag(stigId, color: .purple)
                }
                if let cceId = rule.cceId {
                    metaTag(cceId, color: .blue)
                }
                if !rule.nistControls.isEmpty {
                    metaTag(rule.nistControls.prefix(2).joined(separator: ", "), color: .gray)
                }
                if rule.mobileconfig {
                    metaTag("MDM", color: .green)
                }
            }
        }
        .padding(.vertical, 6)
    }

    // MARK: - Action Bar

    private var actionBar: some View {
        HStack {
            Button("Deselect All") {
                for rule in filteredRules {
                    if let idx = store.rules.firstIndex(where: { $0.id == rule.id }) {
                        store.rules[idx].isSelectedForRemediation = false
                    }
                }
            }
            .buttonStyle(.bordered)

            Button("Select All") {
                for rule in filteredRules {
                    if let idx = store.rules.firstIndex(where: { $0.id == rule.id }) {
                        store.rules[idx].isSelectedForRemediation = true
                    }
                }
            }
            .buttonStyle(.bordered)

            Spacer()

            Button("Scan Category") {
                Task {
                    store.isScanning = true
                    for rule in filteredRules {
                        if let idx = store.rules.firstIndex(where: { $0.id == rule.id }) {
                            store.rules[idx].status = await ScannerService.check(rule: rule)
                        }
                    }
                    store.isScanning = false
                }
            }
            .buttonStyle(.bordered)
            .disabled(store.isScanning)

            Button("Stage") {
                showingStaging = true
            }
            .buttonStyle(.bordered)

            Button("Apply Now") {
                Task {
                    store.isScanning = true
                    let toApply = store.rules.filter { $0.profiles.contains(profile) && $0.isSelectedForRemediation && $0.status == .nonCompliant }
                    _ = await RemediationService.submit(rules: toApply)
                    var snapshot = store.rules
                    await ScannerService.scan(rules: &snapshot, profile: profile) { done, total in
                        store.scanProgress = Double(done) / Double(total)
                    }
                    store.rules = snapshot
                    store.isScanning = false
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(store.isScanning)
        }
        .padding()
        .background(Color(nsColor: .windowBackgroundColor))
    }

    // MARK: - Helpers

    private func exportReport(_ format: ReportExporter.Format) {
        do {
            let url = try ReportExporter.write(rules: store.rules, profile: profile, format: format)
            exportedURL = url
            showExportSuccess = true
        } catch {
            exportError = error.localizedDescription
        }
    }

    private func generateMobileConfig() {
        do {
            let url = try MobileConfigGenerator.write(rules: store.rules, profile: profile)
            exportedURL = url
            showExportSuccess = true
        } catch {
            exportError = error.localizedDescription
        }
    }

    private func filterChip(label: String, value: RuleSeverity?, color: Color = .accentColor) -> some View {
        let selected = severityFilter == value
        return Button(label) {
            severityFilter = value
        }
        .buttonStyle(.bordered)
        .tint(selected ? color : .secondary)
        .controlSize(.small)
    }

    @ViewBuilder
    private func statusIcon(for status: RuleStatus) -> some View {
        switch status {
        case .compliant:
            Label(status.rawValue, systemImage: "checkmark.circle.fill").foregroundColor(.green)
        case .nonCompliant:
            Label(status.rawValue, systemImage: "xmark.circle.fill").foregroundColor(.red)
        case .unknown:
            Label(status.rawValue, systemImage: "questionmark.circle.fill").foregroundColor(.gray)
        case .error:
            Label(status.rawValue, systemImage: "exclamationmark.triangle.fill").foregroundColor(.orange)
        }
    }

    private func severityBadge(_ severity: RuleSeverity) -> some View {
        let color: Color
        switch severity {
        case .high:   color = .red
        case .medium: color = .orange
        case .low:    color = .blue
        case .na:     color = .gray
        }
        return Text(severity.rawValue.uppercased())
            .font(.system(size: 9, weight: .bold))
            .foregroundColor(.white)
            .padding(.horizontal, 5).padding(.vertical, 2)
            .background(RoundedRectangle(cornerRadius: 3).fill(color))
    }

    private func metaTag(_ label: String, color: Color) -> some View {
        Text(label)
            .font(.system(size: 9, weight: .medium, design: .monospaced))
            .foregroundColor(color)
            .padding(.horizontal, 4).padding(.vertical, 1)
            .overlay(RoundedRectangle(cornerRadius: 3).stroke(color.opacity(0.5)))
    }

    private func categoryIcon(_ category: RuleCategory) -> String {
        switch category {
        case .accessControl:   return "person.badge.key"
        case .authentication:  return "lock.shield"
        case .networkSecurity: return "network.badge.shield.half.filled"
        case .systemConfig:    return "gear.badge.checkmark"
        case .auditingLogging: return "doc.text.magnifyingglass"
        case .dataProtection:  return "externaldrive.badge.lock"
        case .encryptionPki:   return "key.horizontal"
        case .mediaControls:   return "opticaldisc"
        case .passwordPolicy:  return "textformat.123"
        case .misc:            return "wrench.and.screwdriver"
        }
    }

    private func scoreColor(_ score: Double) -> Color {
        if score >= 0.9 { return .green }
        if score >= 0.6 { return .orange }
        return .red
    }
}
