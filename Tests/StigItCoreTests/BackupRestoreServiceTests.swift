@testable import StigItCore
import Foundation
import Testing

@Suite("Backup and restore")
struct BackupRestoreServiceTests {
    @Test("Backup names accept only a safe filesystem component")
    func backupNameValidation() {
        #expect(BackupRestoreService.validatedBackupName("before-remediation_1.0") == "before-remediation_1.0")
        #expect(BackupRestoreService.validatedBackupName("../escape") == nil)
        #expect(BackupRestoreService.validatedBackupName("name'; touch /tmp/pwned") == nil)
        #expect(BackupRestoreService.validatedBackupName("") == nil)
    }

    @Test("Restore uses the exact source path recorded in the manifest")
    func restoreUsesExactManifestPath() throws {
        let backupDirectory = URL(fileURLWithPath: "/tmp/safe-backup")
        let manifest = BackupRestoreService.Manifest(
            timestamp: "2026-07-13T00:00:00Z",
            name: "safe-backup",
            entries: [
                .init(sourcePath: "/etc/path_with_under", storedName: "000-path_with_under")
            ]
        )

        let script = try BackupRestoreService.restoreScript(
            manifest: manifest,
            backupDirectory: backupDirectory,
            allowedSourcePaths: ["/etc/path_with_under"]
        )

        #expect(script.contains("'/etc/path_with_under'"))
        #expect(!script.contains("'/etc/path/with/under'"))
        #expect(script.contains("'/tmp/safe-backup/000-path_with_under'"))
    }

    @Test("Restore rejects manifest paths outside the allowlist")
    func restoreRejectsUntrustedDestination() {
        let manifest = BackupRestoreService.Manifest(
            timestamp: "2026-07-13T00:00:00Z",
            name: "safe-backup",
            entries: [.init(sourcePath: "/etc/sudoers", storedName: "000-file")]
        )

        var rejected = false
        do {
            _ = try BackupRestoreService.restoreScript(
                manifest: manifest,
                backupDirectory: URL(fileURLWithPath: "/tmp/safe-backup"),
                allowedSourcePaths: ["/etc/ssh/sshd_config"]
            )
        } catch {
            rejected = true
        }

        #expect(rejected)
    }
}
