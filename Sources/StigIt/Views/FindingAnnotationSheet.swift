import SwiftUI
import StigItCore

struct FindingAnnotationSheet: View {
    @Environment(\.dismiss) private var dismiss

    let rule: Rule
    let profile: ComplianceProfile
    let endpoint: EndpointInfo
    let existing: FindingAnnotation?
    let onSave: (FindingAnnotation) -> Void
    let onDelete: () -> Void
    let onCreateWaiver: () -> Void

    @State private var labels: Set<FindingLabel>
    @State private var customTags: String
    @State private var note: String
    @State private var owner: String
    @State private var ticket: String
    @State private var hasDueDate: Bool
    @State private var dueDate: Date
    @State private var updatedBy: String

    init(
        rule: Rule,
        profile: ComplianceProfile,
        endpoint: EndpointInfo,
        existing: FindingAnnotation?,
        onSave: @escaping (FindingAnnotation) -> Void,
        onDelete: @escaping () -> Void,
        onCreateWaiver: @escaping () -> Void
    ) {
        self.rule = rule
        self.profile = profile
        self.endpoint = endpoint
        self.existing = existing
        self.onSave = onSave
        self.onDelete = onDelete
        self.onCreateWaiver = onCreateWaiver
        _labels = State(initialValue: Set(existing?.labels ?? []))
        _customTags = State(initialValue: existing?.customTags.joined(separator: ", ") ?? "")
        _note = State(initialValue: existing?.note ?? "")
        _owner = State(initialValue: existing?.owner ?? "")
        _ticket = State(initialValue: existing?.ticket ?? "")
        _hasDueDate = State(initialValue: existing?.dueDate != nil)
        _dueDate = State(initialValue: existing?.dueDate
            ?? Calendar.current.date(byAdding: .day, value: 30, to: Date())
            ?? Date())
        _updatedBy = State(initialValue: existing?.updatedBy ?? NSFullUserName())
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            Form {
                Section("Workflow labels") {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 190), alignment: .leading)], alignment: .leading) {
                        ForEach(FindingLabel.allCases) { label in
                            Toggle(label.rawValue, isOn: binding(for: label))
                                .toggleStyle(.checkbox)
                        }
                    }
                    TextField("Custom tags", text: $customTags,
                              prompt: Text("Comma-separated, for example Q3, macOS fleet"))
                }

                Section("Analyst context") {
                    TextField("Owner", text: $owner)
                    TextField("Ticket", text: $ticket, prompt: Text("SEC-1234"))
                    Toggle("Due date", isOn: $hasDueDate)
                    if hasDueDate {
                        DatePicker("Target", selection: $dueDate, displayedComponents: .date)
                    }
                    VStack(alignment: .leading, spacing: 5) {
                        Text("Note").font(.caption).foregroundColor(.secondary)
                        TextEditor(text: $note)
                            .font(.body)
                            .frame(minHeight: 82)
                            .overlay(RoundedRectangle(cornerRadius: 5).stroke(Color.secondary.opacity(0.25)))
                    }
                    TextField("Updated by", text: $updatedBy)
                }

                Section("Compliance effect") {
                    Text("Labels preserve the scanner's measured outcome. Use a documented waiver when an accepted risk should be excluded from compliance gating.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Button("Create Approved Waiver…") {
                        let annotation = makeAnnotation()
                        if !annotation.isEmpty { onSave(annotation) }
                        onCreateWaiver()
                        dismiss()
                    }
                }
            }
            .formStyle(.grouped)

            Divider()
            HStack {
                if existing != nil {
                    Button("Remove Annotation", role: .destructive) {
                        onDelete()
                        dismiss()
                    }
                }
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Save") {
                    onSave(makeAnnotation())
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(updatedBy.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            .padding()
        }
        .frame(minWidth: 610, idealWidth: 610, maxWidth: 610, minHeight: 600)
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "tag.square.fill")
                .font(.title2)
                .foregroundColor(.accentColor)
            VStack(alignment: .leading, spacing: 3) {
                Text("Annotate Scan Result").font(.title2).bold()
                Text(rule.title).font(.headline)
                Text("\(profile.rawValue)  ·  \(endpoint.hostname)  ·  \(rule.id)")
                    .font(.caption.monospaced())
                    .foregroundColor(.secondary)
            }
            Spacer()
        }
        .padding()
    }

    private func binding(for label: FindingLabel) -> Binding<Bool> {
        Binding(
            get: { labels.contains(label) },
            set: { enabled in
                if enabled { labels.insert(label) } else { labels.remove(label) }
            }
        )
    }

    private func makeAnnotation() -> FindingAnnotation {
        FindingAnnotation(
            endpointID: FindingAnnotation.endpointID(for: endpoint),
            profileKey: profile.key,
            ruleID: rule.id,
            labels: Array(labels),
            customTags: customTags.split(separator: ",").map(String.init),
            note: note,
            owner: owner,
            ticket: ticket,
            dueDate: hasDueDate ? dueDate : nil,
            createdAt: existing?.createdAt ?? Date(),
            updatedAt: Date(),
            updatedBy: updatedBy
        )
    }
}

struct QuickWaiverSheet: View {
    @Environment(\.dismiss) private var dismiss
    let rule: Rule
    let onSave: (Waiver) -> Void

    @State private var reason = ""
    @State private var approvedBy = NSFullUserName()
    @State private var ticket = ""
    @State private var hasExpiry = true
    @State private var expiry = Calendar.current.date(byAdding: .day, value: 30, to: Date()) ?? Date()

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Create Approved Waiver").font(.title2).bold()
                Text(rule.title).font(.headline)
                Text("A waiver changes compliance gating and must have explicit approval and justification.")
                    .font(.caption).foregroundColor(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding()
            Divider()
            Form {
                TextField("Reason", text: $reason)
                TextField("Approved by", text: $approvedBy)
                TextField("Ticket", text: $ticket)
                Toggle("Expires", isOn: $hasExpiry)
                if hasExpiry { DatePicker("Expiry", selection: $expiry, displayedComponents: .date) }
            }
            .formStyle(.grouped)
            Divider()
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Save Waiver") {
                    onSave(Waiver(
                        ruleID: rule.id,
                        reason: reason.trimmingCharacters(in: .whitespacesAndNewlines),
                        approvedBy: approvedBy.trimmingCharacters(in: .whitespacesAndNewlines),
                        ticket: ticket.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                            ? nil : ticket.trimmingCharacters(in: .whitespacesAndNewlines),
                        expiresAt: hasExpiry ? expiry : nil
                    ))
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(reason.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                          || approvedBy.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            .padding()
        }
        .frame(width: 520, height: 390)
    }
}
