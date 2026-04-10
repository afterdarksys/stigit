import Foundation

extension RuleStore {
    static func networkSecurityRules() -> [Rule] { [
        Rule(
            id: "system_settings_bluetooth_disable",
            title: "Disable Bluetooth",
            description: "Bluetooth must be disabled to prevent unauthorized wireless bridging.",
            profiles: [.stig, .nist, .iso27001, .cmmc2, .cnssi, .soc2, .hipaa, .glba],
            category: .networkSecurity,
            severity: .medium,
            stigId: "APPL-26-002040",
            cceId: "CCE-95360-4",
            cciIds: ["CCI-001444"],
            nistControls: ["AC-18", "AC-18(3)"],
            checkCommand: "defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState 2>/dev/null || echo '0'",
            expectedResult: .string("0"),
            remediateCommand: "defaults write /Library/Preferences/com.apple.Bluetooth ControllerPowerState -int 0 && killall -HUP bluetoothd 2>/dev/null || true"
        ),
        Rule(
            id: "os_airdrop_disable",
            title: "Disable AirDrop",
            description: "AirDrop must be disabled to prevent data exfiltration over peer-to-peer wireless connections.",
            profiles: [.stig, .nist, .gdpr, .cmmc2, .cnssi, .sox, .hipaa, .glba],
            category: .networkSecurity,
            severity: .medium,
            stigId: "APPL-26-002060",
            cceId: "CCE-95164-0",
            cciIds: ["CCI-000366"],
            nistControls: ["CM-7", "AC-4"],
            checkCommand: "defaults read com.apple.NetworkBrowser DisableAirDrop 2>/dev/null || echo '0'",
            expectedResult: .string("1"),
            remediateCommand: "defaults write com.apple.NetworkBrowser DisableAirDrop -bool true"
        ),
        Rule(
            id: "system_settings_firewall_enable",
            title: "Enable Application Firewall",
            description: "The macOS Application Firewall must be enabled to block unauthorized inbound connections.",
            profiles: [.stig, .nist, .iso27001, .cmmc1, .cmmc2, .cisL1, .cisL2, .cnssi, .soc2, .sox, .hipaa, .glba],
            category: .networkSecurity,
            severity: .medium,
            stigId: "APPL-26-005050",
            cceId: "CCE-95369-5",
            cciIds: ["CCI-000366"],
            nistControls: ["AC-4", "SC-7", "CM-7"],
            checkCommand: """
                /usr/bin/osascript -l JavaScript << 'EOS'
                $.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.firewall').objectForKey('EnableFirewall').js
                EOS
                """,
            expectedResult: .string("true"),
            remediateCommand: "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
            mobileconfig: true
        ),
        Rule(
            id: "system_settings_firewall_stealth_mode_enable",
            title: "Enable Firewall Stealth Mode",
            description: "The firewall must drop all ICMP probes and unsolicited connection attempts.",
            profiles: [.stig, .nist, .cisL2, .cnssi, .sox, .hipaa, .glba],
            category: .networkSecurity,
            severity: .medium,
            stigId: "APPL-26-005051",
            cceId: "CCE-95370-3",
            cciIds: ["CCI-000366"],
            nistControls: ["SC-7"],
            checkCommand: """
                /usr/bin/osascript -l JavaScript << 'EOS'
                $.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.firewall').objectForKey('EnableStealthMode').js
                EOS
                """,
            expectedResult: .string("true"),
            remediateCommand: "/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on",
            mobileconfig: true
        ),
        Rule(
            id: "os_bonjour_disable",
            title: "Disable Bonjour Multicast Advertising",
            description: "Bonjour multicast advertising must be disabled to prevent unauthorized service discovery.",
            profiles: [.stig, .nist, .cisL2, .cnssi, .hipaa, .glba],
            category: .networkSecurity,
            severity: .medium,
            stigId: "APPL-26-002069",
            cceId: "CCE-95184-8",
            cciIds: ["CCI-000366"],
            nistControls: ["CM-7"],
            checkCommand: "defaults read /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements 2>/dev/null || echo '0'",
            expectedResult: .string("1"),
            remediateCommand: "defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool true",
            mobileconfig: true
        ),
        Rule(
            id: "system_settings_screen_sharing_disable",
            title: "Disable Screen Sharing / Apple Remote Desktop",
            description: "Screen sharing and Apple Remote Desktop must be disabled to prevent unauthorized remote access.",
            profiles: [.stig, .nist, .cisL1, .cisL2, .cnssi, .iso27001, .sox, .hipaa, .glba],
            category: .networkSecurity,
            severity: .high,
            stigId: "APPL-26-002070",
            cceId: "CCE-95341-4",
            cciIds: ["CCI-000366"],
            nistControls: ["CM-7", "AC-17"],
            checkCommand: "launchctl list | grep -c com.apple.screensharing 2>/dev/null && echo '1' || echo '0'",
            expectedResult: .string("0"),
            remediateCommand: "launchctl disable system/com.apple.screensharing && launchctl bootout system/com.apple.screensharing 2>/dev/null || true"
        ),
        Rule(
            id: "system_settings_internet_sharing_disable",
            title: "Disable Internet Sharing",
            description: "Internet sharing must be disabled to prevent the Mac from becoming an unauthorized access point.",
            profiles: [.stig, .nist, .cisL1, .cisL2, .cnssi, .hipaa, .glba],
            category: .networkSecurity,
            severity: .medium,
            stigId: "APPL-26-002071",
            cceId: "CCE-95212-7",
            cciIds: ["CCI-000366"],
            nistControls: ["CM-7"],
            checkCommand: "defaults read /Library/Preferences/SystemConfiguration/com.apple.nat NAT 2>/dev/null | grep -c 'Enabled = 1' || echo '0'",
            expectedResult: .string("0"),
            remediateCommand: "defaults write /Library/Preferences/SystemConfiguration/com.apple.nat NAT -dict Enabled -int 0"
        ),
        Rule(
            id: "system_settings_printer_sharing_disable",
            title: "Disable Printer Sharing",
            description: "Printer sharing must be disabled to reduce attack surface.",
            profiles: [.stig, .nist, .cisL1, .cisL2],
            category: .networkSecurity,
            severity: .low,
            stigId: "APPL-26-002072",
            cceId: "CCE-95322-4",
            cciIds: ["CCI-000366"],
            nistControls: ["CM-7"],
            checkCommand: "cupsctl | grep -c '_share_printers=0' || echo '0'",
            expectedResult: .string("1"),
            remediateCommand: "cupsctl --no-share-printers"
        ),
        Rule(
            id: "system_settings_content_caching_disable",
            title: "Disable Content Caching",
            description: "Content caching must be disabled to prevent the system from caching network content for other devices.",
            profiles: [.stig, .nist, .cisL2, .cnssi, .hipaa, .glba],
            category: .networkSecurity,
            severity: .medium,
            stigId: "APPL-26-002073",
            cceId: "CCE-95364-6",
            cciIds: ["CCI-000366"],
            nistControls: ["CM-7"],
            checkCommand: """
                /usr/bin/osascript -l JavaScript << 'EOS'
                $.NSUserDefaults.alloc.initWithSuiteName('com.apple.AssetCache').objectForKey('Activated').js
                EOS
                """,
            expectedResult: .string("false"),
            remediateCommand: "defaults write /Library/Preferences/com.apple.AssetCache.plist Activated -bool false",
            mobileconfig: true
        ),
        Rule(
            id: "system_settings_airplay_receiver_disable",
            title: "Disable AirPlay Receiver",
            description: "AirPlay receiver must be disabled to prevent unauthorized audio/video streaming to this device.",
            profiles: [.stig, .nist, .cnssi, .hipaa, .glba],
            category: .networkSecurity,
            severity: .medium,
            stigId: "APPL-26-002074",
            cceId: "CCE-95358-8",
            cciIds: ["CCI-000366"],
            nistControls: ["CM-7"],
            checkCommand: """
                /usr/bin/osascript -l JavaScript << 'EOS'
                $.NSUserDefaults.alloc.initWithSuiteName('com.apple.controlcenter').objectForKey('AirplayRecieverEnabled').js
                EOS
                """,
            expectedResult: .string("false"),
            remediateCommand: "defaults write /Library/Preferences/com.apple.AirPlayReceiver.plist AirPlayEnabled -bool false",
            mobileconfig: true
        ),
        Rule(
            id: "system_settings_bluetooth_sharing_disable",
            title: "Disable Bluetooth Sharing",
            description: "Bluetooth file sharing must be disabled to prevent unauthorized file transfers.",
            profiles: [.stig, .nist, .cisL1, .cisL2, .hipaa, .glba],
            category: .networkSecurity,
            severity: .low,
            cciIds: ["CCI-000366"],
            nistControls: ["CM-7"],
            checkCommand: "defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled 2>/dev/null || echo '0'",
            expectedResult: .string("0"),
            remediateCommand: "defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false"
        ),
    ] }
}
