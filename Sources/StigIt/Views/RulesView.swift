import SwiftUI
import StigItCore

struct RulesView: View {
    @Environment(RuleStore.self) var store
    
    // We need a binding equivalent for iteration to allow toggles,
    // but in Observation we can just mutate the array if we structure it right.
    // For simplicity with Observation, we'll use a local binding list or just index iteration.
    
    var body: some View {
        @Bindable var bindableStore = store
        
        List($bindableStore.rules) { $rule in
            if rule.profiles.contains(store.activeProfile) {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Toggle(isOn: $rule.isSelectedForRemediation) {
                            Text(rule.title).font(.headline)
                        }
                        Spacer()
                        statusIcon(for: rule.status)
                    }
                    Text(rule.description)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                .padding(.vertical, 4)
            }
        }
        .navigationTitle("Scan & Gaps")
        .toolbar {
            Button("Scan Selected") {
                Task {
                    store.isScanning = true
                    for i in 0..<store.rules.count {
                        if store.rules[i].isSelectedForRemediation {
                            store.rules[i].status = await ScannerService.check(rule: store.rules[i])
                        }
                    }
                    store.isScanning = false
                }
            }
            .disabled(store.isScanning)
        }
    }
    
    @ViewBuilder
    func statusIcon(for status: RuleStatus) -> some View {
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
}
