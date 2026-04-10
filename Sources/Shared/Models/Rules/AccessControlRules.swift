import Foundation

extension RuleStore {
    static func accessControlRules() -> [Rule] { [
        Rule(
            id: "system_settings_screensaver_password_enforce",
            title: "Require Password on Wake",
            description: "A password must be required immediately after the screen saver begins or the display sleeps.",
            profiles: [.stig, .nist, .cisL1, .cisL2, .cmmc2, .cnssi, .iso27001, .gdpr, .soc2, .sox, .hipaa, .glba],
            category: .accessControl,
            severity: .medium,
            stigId: "APPL-26-000008",
            cceId: "CCE-95346-3",
            cciIds: ["CCI-000056"],
            nistControls: ["AC-11(1)"],
            checkCommand: "defaults read com.apple.screensaver askForPassword 2>/dev/null || echo '0'",
            expectedResult: .string("1"),
            remediateCommand: "defaults write com.apple.screensaver askForPassword -int 1"
        ),
        Rule(
            id: "system_settings_screensaver_timeout_enforce",
            title: "Screen Saver Timeout ≤ 15 Minutes",
            description: "Screen saver must activate after no more than 15 minutes (900 seconds) of inactivity.",
            profiles: [.stig, .nist, .cisL1, .cisL2, .cmmc2, .cnssi, .soc2, .sox, .hipaa, .glba],
            category: .accessControl,
            severity: .medium,
            stigId: "APPL-26-000007",
            cceId: "CCE-95347-1",
            cciIds: ["CCI-000057"],
            nistControls: ["AC-11"],
            checkCommand: """
                val=$(/usr/bin/osascript -l JavaScript << 'EOS'
                ObjC.import('Foundation');
                var d = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver');
                var v = d.objectForKey('idleTime');
                v ? v.js : 0
                EOS
                )
                [ "$val" -le 900 ] 2>/dev/null && echo "pass" || echo "fail"
                """,
            expectedResult: .string("pass"),
            remediateCommand: "defaults -currentHost write com.apple.screensaver idleTime -int 900"
        ),
        Rule(
            id: "system_settings_guest_account_disable",
            title: "Disable Guest Account",
            description: "The Guest account must be disabled to prevent unauthorized access.",
            profiles: [.stig, .nist, .cisL1, .cisL2, .cmmc1, .cmmc2, .cnssi, .iso27001, .gdpr, .soc2, .sox, .hipaa, .glba],
            category: .accessControl,
            severity: .high,
            stigId: "APPL-26-001090",
            cceId: "CCE-95230-9",
            cciIds: ["CCI-000366"],
            nistControls: ["AC-2"],
            checkCommand: "defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null || echo '0'",
            expectedResult: .string("0"),
            remediateCommand: "defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false"
        ),
        Rule(
            id: "system_settings_automatic_login_disable",
            title: "Disable Automatic Login",
            description: "Automatic login must be disabled so the system requires authentication on startup.",
            profiles: [.stig, .nist, .cisL1, .cisL2, .cmmc1, .cmmc2, .cnssi, .iso27001, .soc2, .sox, .hipaa, .glba],
            category: .accessControl,
            severity: .high,
            stigId: "APPL-26-001091",
            cceId: "CCE-95355-4",
            cciIds: ["CCI-000366"],
            nistControls: ["AC-3"],
            checkCommand: """
                /usr/bin/osascript -l JavaScript << 'EOS'
                $.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow').objectForKey('autoLoginUser').js
                EOS
                """,
            expectedResult: .string("undefined"),
            remediateCommand: "defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null || true"
        ),
        Rule(
            id: "system_settings_automatic_logout_enforce",
            title: "Enforce Automatic Session Logout",
            description: "The system must log out inactive users after 30 minutes to prevent unauthorized access.",
            profiles: [.stig, .nist, .cisL2, .cnssi, .soc2, .sox, .hipaa, .glba],
            category: .accessControl,
            severity: .medium,
            stigId: "APPL-26-000010",
            cceId: "CCE-95353-9",
            cciIds: ["CCI-000057", "CCI-002361"],
            nistControls: ["AC-11", "AC-12"],
            checkCommand: "defaults read /Library/Preferences/.GlobalPreferences com.apple.autologout.AutoLogOutDelay 2>/dev/null || echo '0'",
            expectedResult: .string("1800"),
            remediateCommand: "defaults write /Library/Preferences/.GlobalPreferences com.apple.autologout.AutoLogOutDelay -int 1800"
        ),
        Rule(
            id: "os_loginwindow_prompt_username_password_enforce",
            title: "Login Window Shows Name and Password Fields",
            description: "The login window must display both the username and password fields to prevent username enumeration.",
            profiles: [.stig, .nist, .cisL1, .cnssi, .sox, .hipaa, .glba],
            category: .accessControl,
            severity: .medium,
            stigId: "APPL-26-000020",
            cceId: "CCE-95237-4",
            cciIds: ["CCI-000366"],
            nistControls: ["CM-6"],
            checkCommand: "defaults read /Library/Preferences/com.apple.loginwindow SHOWFULLNAME 2>/dev/null || echo '0'",
            expectedResult: .string("1"),
            remediateCommand: "defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -int 1"
        ),
    ] }
}
