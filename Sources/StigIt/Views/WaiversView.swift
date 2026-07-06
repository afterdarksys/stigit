import SwiftUI
import StigItCore

/// Ops-facing exception management: every waiver carries an approver, a reason,
/// and an expiry, and is shared with the CLI via ~/.stigit/waivers.json.
struct WaiversView: View {
    @Environment(RuleStore.self) var store

    @State private var waiverStore = WaiverStore(waivers: [])
    @State private var showingAdd = false
    @State private var errorMessage: String?
    @State private var selection: Waiver.ID?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if waiverStore.waivers.isEmpty {
                ContentUnavailableView(
                    "No Waivers",
                    systemImage: "doc.badge.clock",
                    description: Text("Waivers document approved exceptions. A waived rule stays visible in reports but no longer counts as a failure.")
                )
            } else {
                waiverTable
            }
        }
        .navigationTitle("Waivers")
        .toolbar {
            ToolbarItem {
                Button {
                    showingAdd = true
                } label: {
                    Label("Add Waiver", systemImage: "plus")
                }
            }
            ToolbarItem {
                Button(role: .destructive) {
                    removeSelected()
                } label: {
                    Label("Remove", systemImage: "trash")
                }
                .disabled(selection == nil)
            }
        }
        .sheet(isPresented: $showingAdd) {
            AddWaiverSheet { waiver in
                waiverStore.upsert(waiver)
                persist()
            }
            .frame(minWidth: 480)
        }
        .alert("Waiver Error", isPresented: Binding(
            get: { errorMessage != nil },
            set: { if !$0 { errorMessage = nil } }
        )) {
            Button("OK") { errorMessage = nil }
        } message: { Text(errorMessage ?? "") }
        .onAppear(perform: load)
    }

    private var waiverTable: some View {
        Table(waiverStore.waivers, selection: $selection) {
            TableColumn("Rule") { waiver in
                VStack(alignment: .leading) {
                    Text(ruleTitle(for: waiver.ruleID))
                    Text(waiver.ruleID).font(.caption).foregroundColor(.secondary)
                }
            }
            TableColumn("Reason", value: \.reason)
            TableColumn("Approved By", value: \.approvedBy)
            TableColumn("Ticket") { waiver in
                Text(waiver.ticket ?? "—")
            }
            TableColumn("Expires") { waiver in
                if let expires = waiver.expiresAt {
                    Text(expires.formatted(date: .abbreviated, time: .omitted))
                        .foregroundColor(waiver.isActive() ? .primary : .red)
                        .bold(!waiver.isActive())
                } else {
                    Text("Never").foregroundColor(.secondary)
                }
            }
        }
    }

    private func ruleTitle(for ruleID: String) -> String {
        store.rules.first { $0.id == ruleID }?.title ?? "Unknown rule"
    }

    private func load() {
        do {
            waiverStore = try WaiverStore.load()
        } catch {
            errorMessage = "Could not read waiver file: \(error.localizedDescription)"
        }
    }

    private func removeSelected() {
        guard let selection else { return }
        waiverStore.remove(ruleID: selection)
        self.selection = nil
        persist()
    }

    private func persist() {
        do {
            try waiverStore.save()
        } catch {
            errorMessage = "Could not save waiver file: \(error.localizedDescription)"
        }
    }
}

// MARK: - Add sheet

private struct AddWaiverSheet: View {
    @Environment(RuleStore.self) var store
    @Environment(\.dismiss) private var dismiss

    let onSave: (Waiver) -> Void

    @State private var ruleID = ""
    @State private var reason = ""
    @State private var approvedBy = ""
    @State private var ticket = ""
    @State private var hasExpiry = true
    @State private var expiresAt = Calendar.current.date(byAdding: .month, value: 6, to: Date()) ?? Date()

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("New Waiver").font(.title2).bold()

            Form {
                Picker("Rule", selection: $ruleID) {
                    Text("Select a rule…").tag("")
                    ForEach(store.rules.sorted { $0.title < $1.title }) { rule in
                        Text("\(rule.title) (\(rule.id))").tag(rule.id)
                    }
                }
                TextField("Reason", text: $reason, prompt: Text("Why is this exception acceptable?"))
                TextField("Approved By", text: $approvedBy, prompt: Text("Name of the approver"))
                TextField("Ticket", text: $ticket, prompt: Text("Optional tracking ID, e.g. SEC-142"))
                Toggle("Expires", isOn: $hasExpiry)
                if hasExpiry {
                    DatePicker("Expiry Date", selection: $expiresAt, displayedComponents: .date)
                }
            }

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Save Waiver") {
                    onSave(Waiver(
                        ruleID: ruleID,
                        reason: reason,
                        approvedBy: approvedBy,
                        ticket: ticket.isEmpty ? nil : ticket,
                        expiresAt: hasExpiry ? expiresAt : nil
                    ))
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
                .disabled(ruleID.isEmpty || reason.isEmpty || approvedBy.isEmpty)
            }
        }
        .padding(24)
    }
}
