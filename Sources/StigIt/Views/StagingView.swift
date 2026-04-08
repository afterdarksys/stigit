import SwiftUI
import StigItCore

struct StagingView: View {
    @Environment(RuleStore.self) var store
    @State private var isSubmitting = false
    @State private var submissionResult: Bool? = nil
    
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("Staging & Remediation")
                .font(.largeTitle)
                .bold()
            
            Text("The following policy changes will be enforced:")
                .font(.headline)
                
            let activeRemediations = store.activeRules.filter { $0.isSelectedForRemediation && $0.status != .compliant }
            
            if activeRemediations.isEmpty {
                Text("No changes staged.")
                    .foregroundColor(.secondary)
            } else {
                ForEach(activeRemediations) { rule in
                    Text("• Will enforce: \(rule.title)")
                        .font(.subheadline)
                        .foregroundColor(.primary)
                }
            }
            
            Text("Raw System Commands:")
                .font(.headline)
                .padding(.top, 10)
            
            ScrollView {
                Text(RemediationService.generateStagingScript(for: store.activeRules))
                    .font(.system(.body, design: .monospaced))
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(nsColor: .textBackgroundColor))
                    .cornerRadius(8)
            }
            
            HStack {
                Button("Stage & Apply \(store.activeProfile.rawValue)") {
                    Task {
                        isSubmitting = true
                        let result = await RemediationService.submit(rules: store.activeRules)
                        submissionResult = result
                        isSubmitting = false
                    }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(isSubmitting || RemediationService.generateStagingScript(for: store.activeRules).isEmpty)
                
                if isSubmitting {
                    ProgressView()
                        .padding(.leading)
                }
            }
            
            if let result = submissionResult {
                Text(result ? "Submission successful." : "Submission failed.")
                    .foregroundColor(result ? .green : .red)
                    .font(.headline)
            }
        }
        .padding()
        .navigationTitle("Staging")
    }
}
