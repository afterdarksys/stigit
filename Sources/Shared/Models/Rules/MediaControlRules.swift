import Foundation

extension RuleStore {
    static func mediaControlRules() -> [Rule] { [
        Rule(
            id: "os_camera_disable",
            title: "Disable Camera",
            description: "The built-in camera must be disabled in high-security environments to prevent unauthorized surveillance.",
            profiles: [.stig, .nist, .cnssi, .hipaa],
            category: .mediaControls,
            severity: .medium,
            stigId: "APPL-26-002080",
            cceId: "CCE-95190-5",
            cciIds: ["CCI-000366"],
            nistControls: ["CM-7"],
            checkCommand: """
                /usr/bin/osascript -l JavaScript << 'EOS'
                $.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowCamera').js
                EOS
                """,
            expectedResult: .string("false"),
            remediateCommand: "defaults write /Library/Preferences/com.apple.applicationaccess.plist allowCamera -bool false",
            mobileconfig: true
        ),
        Rule(
            id: "os_blank_bluray_disable",
            title: "Disable Blank Blu-Ray Media Burning",
            description: "Blank Blu-Ray media must not be available for burning to prevent data exfiltration.",
            profiles: [.stig, .nist, .cnssi, .sox, .hipaa, .glba],
            category: .mediaControls,
            severity: .low,
            stigId: "APPL-26-002081",
            cceId: "CCE-95182-2",
            cciIds: ["CCI-001090"],
            nistControls: ["MP-7"],
            checkCommand: """
                /usr/bin/osascript -l JavaScript << 'EOS'
                $.NSUserDefaults.alloc.initWithSuiteName('com.apple.systempreferences').objectForKey('DisableBlankBluRaySaving').js
                EOS
                """,
            expectedResult: .string("true"),
            remediateCommand: "defaults write /Library/Preferences/com.apple.systempreferences.plist DisableBlankBluRaySaving -bool true",
            mobileconfig: true
        ),
        Rule(
            id: "os_blank_cd_disable",
            title: "Disable Blank CD Media Burning",
            description: "Blank CD media must not be available for burning to prevent data exfiltration.",
            profiles: [.stig, .nist, .cnssi, .sox, .hipaa, .glba],
            category: .mediaControls,
            severity: .low,
            stigId: "APPL-26-002082",
            cceId: "CCE-95183-0",
            cciIds: ["CCI-001090"],
            nistControls: ["MP-7"],
            checkCommand: """
                /usr/bin/osascript -l JavaScript << 'EOS'
                $.NSUserDefaults.alloc.initWithSuiteName('com.apple.systempreferences').objectForKey('DisableBlankCDSaving').js
                EOS
                """,
            expectedResult: .string("true"),
            remediateCommand: "defaults write /Library/Preferences/com.apple.systempreferences.plist DisableBlankCDSaving -bool true",
            mobileconfig: true
        ),
        Rule(
            id: "os_blank_dvd_disable",
            title: "Disable Blank DVD Media Burning",
            description: "Blank DVD media must not be available for burning to prevent data exfiltration.",
            profiles: [.stig, .nist, .cnssi, .sox, .hipaa, .glba],
            category: .mediaControls,
            severity: .low,
            stigId: "APPL-26-002083",
            cceId: "CCE-95185-5",
            cciIds: ["CCI-001090"],
            nistControls: ["MP-7"],
            checkCommand: """
                /usr/bin/osascript -l JavaScript << 'EOS'
                $.NSUserDefaults.alloc.initWithSuiteName('com.apple.systempreferences').objectForKey('DisableBlankDVDSaving').js
                EOS
                """,
            expectedResult: .string("true"),
            remediateCommand: "defaults write /Library/Preferences/com.apple.systempreferences.plist DisableBlankDVDSaving -bool true",
            mobileconfig: true
        ),
        Rule(
            id: "system_settings_diagnostics_reports_disable",
            title: "Disable Sending Diagnostic Reports to Apple",
            description: "Diagnostic and usage data submission must be disabled to prevent data leakage.",
            profiles: [.stig, .nist, .gdpr, .cnssi, .sox, .hipaa, .glba],
            category: .mediaControls,
            severity: .low,
            stigId: "APPL-26-002090",
            cceId: "CCE-95365-3",
            cciIds: ["CCI-000366"],
            nistControls: ["CM-11(2)"],
            checkCommand: """
                /usr/bin/osascript -l JavaScript << 'EOS'
                $.NSUserDefaults.alloc.initWithSuiteName('com.apple.SubmitDiagInfo').objectForKey('AutoSubmit').js
                EOS
                """,
            expectedResult: .string("false"),
            remediateCommand: "defaults write /Library/Application\\ Support/CrashReporter/DiagnosticMessagesHistory.plist AutoSubmit -bool false",
            mobileconfig: true
        ),
    ] }
}
