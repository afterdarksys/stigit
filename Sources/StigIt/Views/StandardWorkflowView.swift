import SwiftUI
import StigItCore

struct StandardWorkflowView: View {
    @Environment(RuleStore.self) var store
    let profile: ComplianceProfile

    @State private var selectedCategory: RuleCategory? = nil
    @State private var severityFilter: RuleSeverity? = nil
    @State private var showingStaging = false
    @State private var exportedURL: URL? = nil
    @State private var exportError: String? = nil

    private var filteredRules: [Rule] {
        store.rules.filter {
            $0.profiles.contains(profile)
            && $0.category == selectedCategory
            && (severityFilter == nil || $0.severity == severityFilter)
        }
    }

    var body: some View {
        NavigationSplitView {
            CategorySidebarView(profile: profile, selection: $selectedCategory)
        } detail: {
            VStack(spacing: 0) {
                SeverityFilterBar(selection: $severityFilter)
                Divider()
                ruleList
                Divider()
                actionBar
            }
            .navigationTitle(navigationTitle)
            .toolbar { toolbarContent }
        }
        .sheet(isPresented: $showingStaging) {
            StagingModalView(profile: profile).frame(minWidth: 600, minHeight: 400)
        }
        .alert("Export Error", isPresented: Binding(
            get: { exportError != nil },
            set: { if !$0 { exportError = nil } }
        )) {
            Button("OK") { exportError = nil }
        } message: { Text(exportError ?? "") }
        .alert("Exported", isPresented: Binding(
            get: { exportedURL != nil },
            set: { if !$0 { exportedURL = nil } }
        )) {
            Button("OK") { exportedURL = nil }
        } message: { Text(exportedURL.map { "Saved to:\n\($0.path)" } ?? "") }
        .onAppear {
            if selectedCategory == nil {
                let categories = Set(store.rules.filter { $0.profiles.contains(profile) }.map(\.category))
                selectedCategory = Array(categories).sorted { $0.rawValue < $1.rawValue }.first
            }
        }
    }

    // MARK: - Rule list

    private var ruleList: some View {
        List {
            ForEach(filteredRules) { rule in
                if let index = store.rules.firstIndex(where: { $0.id == rule.id }) {
                    @Bindable var s = store
                    RuleRowView(rule: rule, isSelected: $s.rules[index].isSelectedForRemediation)
                }
            }
        }
    }

    // MARK: - Toolbar

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItem {
            if store.isScanning {
                HStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    Text("Scanning…").font(.caption)
                }
            }
        }
        ToolbarItem {
            Menu {
                Button("Export JSON")    { export(.json) }
                Button("Export CSV")     { export(.csv) }
                Button("Export Summary") { export(.summary) }
                Divider()
                Button("Generate .mobileconfig") { generateProfile() }
            } label: {
                Label("Export", systemImage: "square.and.arrow.up")
            }
        }
    }

    // MARK: - Action bar

    private var actionBar: some View {
        HStack {
            Button("Deselect All") { setSelection(false) }.buttonStyle(.bordered)
            Button("Select All")   { setSelection(true)  }.buttonStyle(.bordered)
            Spacer()
            Button("Scan") {
                Task {
                    store.isScanning = true
                    for rule in filteredRules {
                        if let i = store.rules.firstIndex(where: { $0.id == rule.id }) {
                            store.rules[i].status = await ScannerService.check(rule: rule)
                        }
                    }
                    store.isScanning = false
                }
            }
            .buttonStyle(.bordered)
            .disabled(store.isScanning)

            Button("Stage")      { showingStaging = true }.buttonStyle(.bordered)
            Button("Apply Now")  { applyRemediation()    }.buttonStyle(.borderedProminent).disabled(store.isScanning)
        }
        .padding()
        .background(Color(nsColor: .windowBackgroundColor))
    }

    // MARK: - Helpers

    private var navigationTitle: String {
        selectedCategory.map { "\(profile.rawValue)  ·  \($0.rawValue)" } ?? profile.rawValue
    }

    private func setSelection(_ value: Bool) {
        for rule in filteredRules {
            if let i = store.rules.firstIndex(where: { $0.id == rule.id }) {
                store.rules[i].isSelectedForRemediation = value
            }
        }
    }

    private func applyRemediation() {
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

    private func export(_ format: ReportExporter.Format) {
        do {
            exportedURL = try ReportExporter.write(rules: store.rules, profile: profile, format: format)
        } catch {
            exportError = error.localizedDescription
        }
    }

    private func generateProfile() {
        do {
            exportedURL = try MobileConfigGenerator.write(rules: store.rules, profile: profile)
        } catch {
            exportError = error.localizedDescription
        }
    }
}
