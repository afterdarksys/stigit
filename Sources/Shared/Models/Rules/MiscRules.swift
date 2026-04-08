import Foundation

extension RuleStore {
    static func miscRules() -> [Rule] { [
        Rule(
            id: "finder_show_hidden",
            title: "Show Hidden Files in Finder",
            description: "Reveals hidden system files and dotfiles globally in the Finder.",
            profiles: [.other],
            category: .misc,
            severity: .low,
            checkCommand: "defaults read com.apple.finder AppleShowAllFiles 2>/dev/null || echo 'NO'",
            expectedResult: .string("YES"),
            remediateCommand: "defaults write com.apple.finder AppleShowAllFiles -bool true && killall Finder"
        ),
        Rule(
            id: "safari_develop_menu",
            title: "Enable Safari Developer Menu",
            description: "Enables the Developer Tools menu in Safari.",
            profiles: [.other],
            category: .misc,
            severity: .low,
            checkCommand: "defaults read com.apple.Safari IncludeDevelopMenu 2>/dev/null || echo '0'",
            expectedResult: .string("1"),
            remediateCommand: "defaults write com.apple.Safari IncludeDevelopMenu -int 1 && defaults write com.apple.Safari WebKitDeveloperExtrasEnabledPreferenceKey -bool true"
        ),
        Rule(
            id: "dock_autohide_fast",
            title: "Fast Dock Autohide",
            description: "Removes the delay before the Dock appears when hovered.",
            profiles: [.other],
            category: .misc,
            severity: .low,
            checkCommand: "defaults read com.apple.dock autohide-delay 2>/dev/null || echo '1'",
            expectedResult: .string("0"),
            remediateCommand: "defaults write com.apple.dock autohide-delay -float 0 && defaults write com.apple.dock autohide-time-modifier -float 0.2 && killall Dock"
        ),
        Rule(
            id: "system_settings_software_update_current",
            title: "macOS is Up to Date",
            description: "The system must have all available security updates installed.",
            profiles: [.stig, .nist, .cmmc1, .cmmc2, .cisL1, .cisL2],
            category: .systemConfig,
            severity: .high,
            stigId: "APPL-26-000006",
            cceId: "CCE-95348-9",
            cciIds: ["CCI-000366"],
            nistControls: ["SI-2"],
            checkCommand: "/usr/bin/softwareupdate -l 2>/dev/null | /usr/bin/grep -c 'No new software available' || echo '0'",
            expectedResult: .integer(1),
            remediateCommand: "softwareupdate --install --all --agree-to-license 2>/dev/null || true"
        ),
        Rule(
            id: "os_mdm_require",
            title: "Enforce MDM Enrollment",
            description: "The system must be enrolled in Mobile Device Management to enforce configuration baselines.",
            profiles: [.stig, .nist, .cmmc2, .cnssi],
            category: .systemConfig,
            severity: .high,
            stigId: "APPL-26-000001",
            cceId: "CCE-95251-5",
            cciIds: ["CCI-000366"],
            nistControls: ["CM-6"],
            checkCommand: "profiles status -type enrollment 2>/dev/null | /usr/bin/grep -c 'MDM enrollment: Yes' || echo '0'",
            expectedResult: .integer(1),
            remediateCommand: "echo 'NOTE: Enroll this device in your MDM solution (e.g., Jamf, Microsoft Intune, Mosyle)'"
        ),
    ] }
}
