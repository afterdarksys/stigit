import Foundation

extension RuleStore {
    static func dataProtectionRules() -> [Rule] { [
        Rule(
            id: "system_settings_filevault_enforce",
            title: "Enforce FileVault Full-Disk Encryption",
            description: "FileVault must be enabled and MDM must prevent users from disabling it.",
            profiles: [.stig, .nist, .cmmc2, .cisL1, .cisL2, .cnssi, .iso27001, .gdpr, .soc2, .nist171, .sox, .hipaa, .glba],
            category: .dataProtection,
            severity: .high,
            stigId: "APPL-26-005020",
            cceId: "CCE-95367-9",
            cciIds: ["CCI-001199", "CCI-002475"],
            nistControls: ["SC-28", "SC-28(1)"],
            checkCommand: """
                dontAllowDisable=$(/usr/bin/osascript -l JavaScript << 'EOS'
                $.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX').objectForKey('dontAllowFDEDisable').js
                EOS
                )
                fileVault=$(/usr/bin/fdesetup status | /usr/bin/grep -c "FileVault is On.")
                [[ "$dontAllowDisable" == "true" ]] && [[ "$fileVault" == "1" ]] && echo "1" || echo "0"
                """,
            expectedResult: .integer(1),
            remediateCommand: "fdesetup enable -user $(stat -f '%Su' /dev/console) 2>/dev/null || true",
            mobileconfig: true
        ),
        Rule(
            id: "os_sip_enable",
            title: "Ensure System Integrity Protection (SIP) is Enabled",
            description: "SIP protects system files and directories from modification even by the root user.",
            profiles: [.stig, .nist, .cmmc1, .cmmc2, .cisL1, .cisL2, .cnssi, .nist171, .sox, .hipaa, .glba],
            category: .dataProtection,
            severity: .high,
            stigId: "APPL-26-005001",
            cceId: "CCE-95298-6",
            cciIds: ["CCI-001493", "CCI-001499"],
            nistControls: ["AC-3", "AU-9", "CM-5(6)", "SI-7"],
            checkCommand: "/usr/bin/csrutil status | /usr/bin/grep -c 'System Integrity Protection status: enabled.'",
            expectedResult: .integer(1),
            remediateCommand: "echo 'NOTE: Boot into Recovery Mode and run: csrutil enable'"
        ),
        Rule(
            id: "os_authenticated_root_enable",
            title: "Enable Authenticated Root Volume",
            description: "The system volume must be cryptographically sealed to detect unauthorized modifications.",
            profiles: [.stig, .nist, .cnssi, .sox, .hipaa, .glba],
            category: .dataProtection,
            severity: .high,
            stigId: "APPL-26-005002",
            cceId: "CCE-95168-1",
            cciIds: ["CCI-001493"],
            nistControls: ["SI-7(6)"],
            checkCommand: "/usr/bin/csrutil authenticated-root status | /usr/bin/grep -c 'enabled'",
            expectedResult: .integer(1),
            remediateCommand: "echo 'NOTE: Boot into Recovery Mode and run: csrutil authenticated-root enable'"
        ),
        Rule(
            id: "os_gatekeeper_enable",
            title: "Enable Gatekeeper",
            description: "Gatekeeper must be enabled to ensure only Apple-signed applications can run.",
            profiles: [.stig, .nist, .cmmc1, .cmmc2, .cisL1, .cisL2, .cnssi, .nist171, .sox, .hipaa, .glba],
            category: .dataProtection,
            severity: .high,
            stigId: "APPL-26-002064",
            cceId: "CCE-95195-4",
            cciIds: ["CCI-001749"],
            nistControls: ["CM-14", "SI-3", "SI-7(1)"],
            checkCommand: """
                /usr/bin/osascript -l JavaScript << 'EOS'
                $.NSUserDefaults.alloc.initWithSuiteName('com.apple.systempolicy.control').objectForKey('EnableAssessment').js
                EOS
                """,
            expectedResult: .string("true"),
            remediateCommand: "spctl --master-enable",
            mobileconfig: true
        ),
        Rule(
            id: "system_settings_gatekeeper_override_disallow",
            title: "Disallow Gatekeeper Override",
            description: "Users must not be permitted to override Gatekeeper and run unsigned applications.",
            profiles: [.stig, .nist, .cnssi, .sox, .hipaa, .glba],
            category: .dataProtection,
            severity: .high,
            stigId: "APPL-26-002065",
            cceId: "CCE-95196-2",
            cciIds: ["CCI-001749"],
            nistControls: ["CM-5(3)"],
            checkCommand: """
                /usr/bin/osascript -l JavaScript << 'EOS'
                $.NSUserDefaults.alloc.initWithSuiteName('com.apple.systempolicy.managed').objectForKey('DisableOverride').js
                EOS
                """,
            expectedResult: .string("true"),
            remediateCommand: "defaults write /Library/Preferences/com.apple.systempolicy.managed DisableOverride -bool true",
            mobileconfig: true
        ),
    ] }
}
