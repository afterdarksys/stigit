import Foundation

extension RuleStore {
    static func financialHealthcareRules() -> [Rule] { [
        Rule(
            id: "os_ntp_enabled",
            title: "Network Time Synchronization Enabled",
            description: "The system clock must be synchronized via NTP to ensure accurate timestamps in audit logs, which is required for forensic integrity under SOX, HIPAA, and GLBA.",
            profiles: [.sox, .hipaa, .glba, .nist, .cnssi],
            category: .auditingLogging,
            severity: .medium,
            nistControls: ["AU-8", "AU-8(1)"],
            checkCommand: "/usr/sbin/systemsetup -getusingnetworktime 2>/dev/null | /usr/bin/grep -c 'Network Time: On'",
            expectedResult: .integer(1),
            remediateCommand: "/usr/sbin/systemsetup -setusingnetworktime on"
        ),
        Rule(
            id: "os_sudoers_nopasswd_disable",
            title: "No NOPASSWD Entries in sudoers",
            description: "Passwordless sudo (NOPASSWD) must not be configured. All privileged command execution must require authentication to satisfy access control requirements under SOX, HIPAA, and GLBA.",
            profiles: [.sox, .hipaa, .glba, .nist, .cmmc2, .cnssi],
            category: .authentication,
            severity: .high,
            nistControls: ["IA-2", "AC-6(1)"],
            checkCommand: "/usr/bin/grep -rEc 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | /usr/bin/awk -F: '{sum += $NF} END {print sum+0}'",
            expectedResult: .integer(0),
            remediateCommand: "echo 'NOTE: Remove all NOPASSWD entries from /etc/sudoers and /etc/sudoers.d/ manually'"
        ),
        Rule(
            id: "system_settings_terminal_secure_keyboard_enable",
            title: "Enable Secure Keyboard Entry in Terminal",
            description: "Secure Keyboard Entry must be enabled in Terminal to prevent other applications from reading keystrokes, protecting credentials and sensitive data (ePHI, NPI) entered at the command line.",
            profiles: [.hipaa, .glba, .nist],
            category: .dataProtection,
            severity: .medium,
            nistControls: ["SC-28", "AC-3"],
            checkCommand: "defaults read com.apple.Terminal SecureKeyboardEntry 2>/dev/null || echo '0'",
            expectedResult: .integer(1),
            remediateCommand: "defaults write com.apple.Terminal SecureKeyboardEntry -bool true"
        ),
        Rule(
            id: "os_icloud_drive_disable",
            title: "Disable iCloud Drive",
            description: "iCloud Drive must be disabled to prevent regulated data (ePHI, NPI, financial records) from being stored in or synchronized through consumer cloud infrastructure not covered by BAAs or data processing agreements.",
            profiles: [.hipaa, .glba, .sox],
            category: .dataProtection,
            severity: .high,
            nistControls: ["SC-28", "AC-4", "CM-7"],
            checkCommand: """
                /usr/bin/osascript -l JavaScript << 'EOS'
                $.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowCloudDocumentSync').js
                EOS
                """,
            expectedResult: .string("false"),
            remediateCommand: "defaults write /Library/Preferences/com.apple.applicationaccess.plist allowCloudDocumentSync -bool false",
            mobileconfig: true
        ),
    ] }
}
