import SwiftUI
import StigItCore

struct StagingModalView: View {
    @Environment(RuleStore.self) var store
    @Environment(\.dismiss) var dismiss
    
    let profile: ComplianceProfile
    @State private var isSubmitting = false
    @State private var submissionResult: Bool? = nil
    
    var activeRemediations: [Rule] {
        store.rules.filter { $0.profiles.contains(profile) && $0.isSelectedForRemediation && $0.status != .compliant }
    }
    
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("Staging: \(profile.rawValue)")
                .font(.largeTitle)
                .bold()
            
            if let result = submissionResult {
                Text(result ? "Submission successful! You may close this window." : "Submission failed.")
                    .foregroundColor(result ? .green : .red)
                    .font(.headline)
                    
                Button("Close") {
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
            } else {
                Text("The following policy changes will be enforced:")
                    .font(.headline)
                    
                if activeRemediations.isEmpty {
                    Text("No changes staged. All selected policies are either fully compliant or none selected.")
                        .foregroundColor(.secondary)
                } else {
                    List(activeRemediations) { rule in
                        Text("• Will enforce: \(rule.title)")
                            .font(.subheadline)
                            .foregroundColor(.primary)
                    }
                    .frame(maxHeight: 150)
                }
                
                Text("Raw System Commands:")
                    .font(.headline)
                    .padding(.top, 5)
                
                ScrollView {
                    Text(RemediationService.generateStagingScript(for: activeRemediations))
                        .font(.system(.body, design: .monospaced))
                        .padding()
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color(nsColor: .textBackgroundColor))
                        .cornerRadius(8)
                }
                
                HStack {
                    Button("Cancel") {
                        dismiss()
                    }
                    .buttonStyle(.bordered)
                    
                    Spacer()
                    
                    Button("Apply Now") {
                        Task {
                            isSubmitting = true
                            let result = await RemediationService.submit(rules: activeRemediations)
                            submissionResult = result
                            isSubmitting = false
                            
                            // Re-check after submission
                            if result {
                                for i in 0..<store.rules.count {
                                    if store.rules[i].profiles.contains(profile) {
                                        store.rules[i].status = await ScannerService.check(rule: store.rules[i])
                                    }
                                }
                            }
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .disabled(isSubmitting || RemediationService.generateStagingScript(for: activeRemediations).isEmpty)
                }
            }
        }
        .padding()
    }
}
