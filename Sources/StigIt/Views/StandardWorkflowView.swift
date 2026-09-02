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
    @State private var annotationStore = FindingAnnotationStore(annotations: [])
    @State private var endpoint = EndpointInfo.current()
    @State private var labelFilter: FindingLabel? = nil
    @State private var editingRule: Rule?
    @State private var waiverRule: Rule?

    private var filteredRules: [Rule] {
        store.rules.filter { rule in
            rule.profiles.contains(profile)
            && rule.category == selectedCategory
            && (severityFilter == nil || rule.severity == severityFilter)
            && (labelFilter.map { annotation(for: rule)?.labels.contains($0) == true } ?? true)
        }
    }

    var body: some View {
        HSplitView {
            CategorySidebarView(profile: profile, selection: $selectedCategory)
                .frame(minWidth: 200, idealWidth: 230, maxWidth: 320)
            VStack(spacing: 0) {
                HStack(spacing: 0) {
                    SeverityFilterBar(selection: $severityFilter)
                    Spacer()
                    Menu {
                        Button("All labels") { labelFilter = nil }
                        Divider()
                        ForEach(FindingLabel.allCases) { label in
                            Button(label.rawValue) { labelFilter = label }
                        }
                    } label: {
                        Label(labelFilter?.rawValue ?? "All labels", systemImage: "tag")
                    }
                    .menuStyle(.borderlessButton)
                    .fixedSize()
                    .padding(.trailing, 12)
                }
                Divider()
                if let framework = profile.frameworkInfo {
                    frameworkBanner(framework)
                    Divider()
                }
                ruleList
                Divider()
                actionBar
            }
            .frame(maxWidth: .infinity)
        }
        .navigationTitle(navigationTitle)
        .toolbar { toolbarContent }
        .sheet(isPresented: $showingStaging) {
            StagingModalView(profile: profile).frame(minWidth: 600, minHeight: 400)
        }
        .sheet(item: $editingRule) { rule in
            FindingAnnotationSheet(
                rule: rule,
                profile: profile,
                endpoint: endpoint,
                existing: annotation(for: rule),
                onSave: saveAnnotation,
                onDelete: { removeAnnotation(for: rule) },
                onCreateWaiver: {
                    editingRule = nil
                    waiverRule = rule
                }
            )
        }
        .sheet(item: $waiverRule) { rule in
            QuickWaiverSheet(rule: rule, onSave: saveWaiver)
        }
        .alert("Operation Error", isPresented: Binding(
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
            loadAnnotations()
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
                    RuleRowView(
                        rule: rule,
                        isSelected: $s.rules[index].isSelectedForRemediation,
                        annotation: annotation(for: rule),
                        onAnnotate: { editingRule = rule }
                    )
                }
            }
        }
    }

    private func frameworkBanner(_ framework: ComplianceFrameworkInfo) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "building.columns.circle.fill")
                .foregroundColor(.accentColor)
            VStack(alignment: .leading, spacing: 2) {
                Text("\(framework.baseline) · \(framework.versionDescription)")
                    .font(.subheadline).bold()
                Text(framework.scopeNote)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 9)
        .background(Color.accentColor.opacity(0.07))
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
            let waivers: WaiverStore
            do {
                waivers = try WaiverStore.load()
            } catch {
                exportError = "Waivers could not be loaded, so remediation was cancelled: \(error.localizedDescription)"
                store.isScanning = false
                return
            }
            let profileRules = store.rules.filter { $0.profiles.contains(profile) }
            let toApply = RemediationService.eligibleRules(from: profileRules, waivers: waivers)
            guard !toApply.isEmpty else {
                store.isScanning = false
                return
            }
            let submitted = await RemediationService.submit(rules: toApply)
            guard submitted else {
                exportError = "Remediation failed or was cancelled. No success was assumed."
                store.isScanning = false
                return
            }
            var snapshot = store.rules
            await ScannerService.scan(rules: &snapshot, profile: profile) { done, total in
                Task { @MainActor in store.scanProgress = Double(done) / Double(total) }
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

    private func annotation(for rule: Rule) -> FindingAnnotation? {
        annotationStore.annotation(for: rule.id, profileKey: profile.key, endpoint: endpoint)
    }

    private func loadAnnotations() {
        do {
            annotationStore = try FindingAnnotationStore.load()
        } catch {
            exportError = "Annotations could not be loaded: \(error.localizedDescription)"
        }
    }

    private func saveAnnotation(_ annotation: FindingAnnotation) {
        annotationStore.upsert(annotation)
        do {
            try annotationStore.save()
        } catch {
            exportError = "Annotation could not be saved: \(error.localizedDescription)"
            loadAnnotations()
        }
    }

    private func removeAnnotation(for rule: Rule) {
        annotationStore.remove(ruleID: rule.id, profileKey: profile.key, endpoint: endpoint)
        do {
            try annotationStore.save()
        } catch {
            exportError = "Annotation could not be removed: \(error.localizedDescription)"
            loadAnnotations()
        }
    }

    private func saveWaiver(_ waiver: Waiver) {
        do {
            var store = try WaiverStore.load()
            store.upsert(waiver)
            try store.save()
        } catch {
            exportError = "Waiver could not be saved: \(error.localizedDescription)"
        }
    }
}
