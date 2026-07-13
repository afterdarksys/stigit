import SwiftUI
import StigItCore

struct BackupsView: View {
    @State private var backupName: String = "backup_" + ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
    @State private var isBackingUp = false
    @State private var backupURL: URL? = nil
    @State private var operationError: String?
    @State private var operationMessage: String?
    @State private var restoringPath: String?
    @State private var existingBackups: [URL] = []

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("Backup & Restore")
                .font(.largeTitle).bold()

            Text("Create a snapshot of critical system settings before applying remediations.")
                .font(.headline)

            HStack {
                TextField("Backup Name", text: $backupName)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 300)

                Button("Create Backup") {
                    Task {
                        isBackingUp = true
                        operationError = nil
                        operationMessage = nil
                        let result = await BackupRestoreService.createBackup(name: backupName)
                        switch result {
                        case .success(let url):
                            backupURL = url
                            operationMessage = "Backup created successfully."
                        case .failure(let error):
                            operationError = error.localizedDescription
                        }
                        existingBackups = BackupRestoreService.listBackups()
                        isBackingUp = false
                    }
                }
                .disabled(isBackingUp || backupName.isEmpty)

                if isBackingUp { ProgressView() }
            }

            if let url = backupURL {
                Label("Backup saved to: \(url.path)", systemImage: "checkmark.circle.fill")
                    .foregroundColor(.green).font(.subheadline)
            }
            if let operationError {
                Label(operationError, systemImage: "xmark.circle.fill")
                    .foregroundColor(.red).font(.subheadline)
            }
            if let operationMessage {
                Label(operationMessage, systemImage: "checkmark.circle.fill")
                    .foregroundColor(.green).font(.subheadline)
            }

            Divider()

            Text("Existing Backups").font(.headline)
            if existingBackups.isEmpty {
                Text("No backups found in ~/.stigit/backups/")
                    .foregroundColor(.secondary).font(.subheadline)
            } else {
                List(existingBackups, id: \.path) { url in
                    HStack {
                        Image(systemName: "archivebox")
                        Text(url.lastPathComponent)
                        Spacer()
                        Button("Restore") {
                            Task {
                                restoringPath = url.path
                                operationError = nil
                                operationMessage = nil
                                let restored = await BackupRestoreService.restore(from: url)
                                if restored {
                                    operationMessage = "Restored (url.lastPathComponent) successfully."
                                } else {
                                    operationError = "Restore failed for (url.lastPathComponent). No success was assumed."
                                }
                                restoringPath = nil
                            }
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                        .disabled(restoringPath != nil)
                        if restoringPath == url.path { ProgressView().controlSize(.small) }
                    }
                }
                .frame(maxHeight: 200)
            }

            Spacer()
        }
        .padding()
        .navigationTitle("Backups")
        .onAppear {
            existingBackups = BackupRestoreService.listBackups()
        }
    }
}
