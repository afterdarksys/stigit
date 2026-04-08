import Foundation
import Observation

@Observable
public class RuleStore {
    public var rules: [Rule] = []
    public var activeProfile: ComplianceProfile = .stig
    public var isScanning: Bool = false
    public var scanProgress: Double = 0.0   // 0.0 – 1.0
    public var lastScanDate: Date? = nil

    public init() {
        self.rules = RuleStore.defaultRules()
    }

    // MARK: - Derived

    public var activeRules: [Rule] {
        rules.filter { $0.profiles.contains(activeProfile) }
    }

    public var compliantCount: Int   { activeRules.filter { $0.status == .compliant }.count }
    public var totalCount: Int       { activeRules.count }
    public var complianceScore: Double {
        guard totalCount > 0 else { return 0 }
        return Double(compliantCount) / Double(totalCount)
    }

    public func activeRules(severity: RuleSeverity) -> [Rule] {
        activeRules.filter { $0.severity == severity }
    }

    // MARK: - Default Enterprise Rule Library

    public static func defaultRules() -> [Rule] {
        return accessControlRules()
             + authenticationRules()
             + networkSecurityRules()
             + auditingRules()
             + dataProtectionRules()
             + passwordPolicyRules()
             + mediaControlRules()
             + miscRules()
    }

    // MARK: Access Control

    private static func accessControlRules() -> [Rule] { [
        Rule(
            id: "system_settings_screensaver_password_enforce",
            title: "Require Password on Wake",
            description: "A password must be required immediately after the screen saver begins or the display sleeps.",
            profiles: [.stig, .nist, .cisL1, .cisL2, .cmmc2, .cnssi, .iso27001, .gdpr, .soc2],
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
            profiles: [.stig, .nist, .cisL1, .cisL2, .cmmc2, .cnssi, .soc2],
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
            profiles: [.stig, .nist, .cisL1, .cisL2, .cmmc1, .cmmc2, .cnssi, .iso27001, .gdpr, .soc2],
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
            profiles: [.stig, .nist, .cisL1, .cisL2, .cmmc1, .cmmc2, .cnssi, .iso27001, .soc2],
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
            profiles: [.stig, .nist, .cisL2, .cnssi, .soc2],
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
            profiles: [.stig, .nist, .cisL1, .cnssi],
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

    // MARK: Authentication

    private static func authenticationRules() -> [Rule] { [
        Rule(
            id: "auth_ssh_password_authentication_disable",
            title: "Disable SSH Password Authentication",
            description: "Password-based SSH authentication must be disabled; only key-based or certificate authentication is permitted.",
            profiles: [.stig, .nist, .cisL2, .cmmc1, .cmmc2, .cnssi, .nist171],
            category: .authentication,
            severity: .high,
            stigId: "APPL-26-001150",
            cceId: "CCE-95139-2",
            cciIds: ["CCI-000765", "CCI-000766", "CCI-001948"],
            nistControls: ["IA-2(1)", "IA-2(2)", "IA-5(2)", "MA-4"],
            checkCommand: "/usr/sbin/sshd -G | /usr/bin/grep -Ec '^(passwordauthentication\\s+no|kbdinteractiveauthentication\\s+no)'",
            expectedResult: .integer(2),
            remediateCommand: """
                include_dir=$(/usr/bin/awk '/^Include/ {print $2}' /etc/ssh/sshd_config | /usr/bin/tr -d '*')
                [ -z "$include_dir" ] && { /usr/bin/sed -i.bk "1s/.*/Include \\/etc\\/ssh\\/sshd_config.d\\/*/" /etc/ssh/sshd_config; include_dir="/etc/ssh/sshd_config.d/"; }
                echo "passwordauthentication no" >> "${include_dir}01-mscp-sshd.conf"
                echo "kbdinteractiveauthentication no" >> "${include_dir}01-mscp-sshd.conf"
                """
        ),
        Rule(
            id: "os_sshd_permit_root_login_configure",
            title: "Disable SSH Root Login",
            description: "Direct root login via SSH must be disabled. Administrators must authenticate with individual accounts.",
            profiles: [.stig, .nist, .cisL1, .cisL2, .cmmc2, .cnssi, .nist171],
            category: .authentication,
            severity: .medium,
            stigId: "APPL-26-001100",
            cceId: "CCE-95313-3",
            cciIds: ["CCI-000770", "CCI-001813"],
            nistControls: ["IA-2(5)"],
            checkCommand: "/usr/sbin/sshd -G | /usr/bin/awk '/permitrootlogin/{print $2}'",
            expectedResult: .string("no"),
            remediateCommand: """
                include_dir=$(/usr/bin/awk '/^Include/ {print $2}' /etc/ssh/sshd_config | /usr/bin/tr -d '*')
                [ -z "$include_dir" ] && { /usr/bin/sed -i.bk "1s/.*/Include \\/etc\\/ssh\\/sshd_config.d\\/*/" /etc/ssh/sshd_config; include_dir="/etc/ssh/sshd_config.d/"; }
                /usr/bin/grep -qxF 'permitrootlogin no' "${include_dir}01-mscp-sshd.conf" 2>/dev/null || echo "permitrootlogin no" >> "${include_dir}01-mscp-sshd.conf"
                """
        ),
        Rule(
            id: "os_sshd_client_alive_interval_configure",
            title: "SSH Idle Timeout (ClientAliveInterval = 900)",
            description: "SSHD must be configured to send keep-alive messages every 900 seconds to terminate idle sessions.",
            profiles: [.stig, .nist, .cmmc2, .cnssi, .nist171],
            category: .authentication,
            severity: .medium,
            stigId: "APPL-26-000133",
            cceId: "CCE-95308-1",
            cciIds: ["CCI-001133"],
            nistControls: ["SC-10"],
            checkCommand: "/usr/sbin/sshd -G | /usr/bin/awk '/clientaliveinterval/{print $2}'",
            expectedResult: .string("900"),
            remediateCommand: """
                include_dir=$(/usr/bin/awk '/^Include/ {print $2}' /etc/ssh/sshd_config | /usr/bin/tr -d '*')
                [ -z "$include_dir" ] && { /usr/bin/sed -i.bk "1s/.*/Include \\/etc\\/ssh\\/sshd_config.d\\/*/" /etc/ssh/sshd_config; include_dir="/etc/ssh/sshd_config.d/"; }
                /usr/bin/grep -qi "clientaliveinterval" "${include_dir}01-mscp-sshd.conf" 2>/dev/null \
                  && /usr/bin/sed -i "" "s/clientaliveinterval.*/clientaliveinterval 900/I" "${include_dir}01-mscp-sshd.conf" \
                  || echo "clientaliveinterval 900" >> "${include_dir}01-mscp-sshd.conf"
                """
        ),
        Rule(
            id: "os_sshd_client_alive_count_max_configure",
            title: "SSH ClientAliveCountMax = 0",
            description: "SSHD must terminate the session after the keep-alive threshold (set to 0 retries for immediate termination).",
            profiles: [.stig, .nist, .cmmc2, .cnssi, .nist171],
            category: .authentication,
            severity: .medium,
            stigId: "APPL-26-000134",
            cceId: "CCE-95309-9",
            cciIds: ["CCI-001133"],
            nistControls: ["SC-10"],
            checkCommand: "/usr/sbin/sshd -G | /usr/bin/awk '/clientalivecountmax/{print $2}'",
            expectedResult: .string("0"),
            remediateCommand: """
                include_dir=$(/usr/bin/awk '/^Include/ {print $2}' /etc/ssh/sshd_config | /usr/bin/tr -d '*')
                [ -z "$include_dir" ] && { /usr/bin/sed -i.bk "1s/.*/Include \\/etc\\/ssh\\/sshd_config.d\\/*/" /etc/ssh/sshd_config; include_dir="/etc/ssh/sshd_config.d/"; }
                /usr/bin/grep -qi "clientalivecountmax" "${include_dir}01-mscp-sshd.conf" 2>/dev/null \
                  && /usr/bin/sed -i "" "s/clientalivecountmax.*/clientalivecountmax 0/I" "${include_dir}01-mscp-sshd.conf" \
                  || echo "clientalivecountmax 0" >> "${include_dir}01-mscp-sshd.conf"
                """
        ),
        Rule(
            id: "os_sshd_login_grace_time_configure",
            title: "SSH Login Grace Time = 30s",
            description: "SSHD must be configured to disconnect unauthenticated sessions after 30 seconds.",
            profiles: [.stig, .nist, .cnssi],
            category: .authentication,
            severity: .medium,
            stigId: "APPL-26-000135",
            cceId: "CCE-95310-7",
            cciIds: ["CCI-000366"],
            nistControls: ["CM-6"],
            checkCommand: "/usr/sbin/sshd -G | /usr/bin/awk '/logingracetime/{print $2}'",
            expectedResult: .string("30"),
            remediateCommand: """
                include_dir=$(/usr/bin/awk '/^Include/ {print $2}' /etc/ssh/sshd_config | /usr/bin/tr -d '*')
                [ -z "$include_dir" ] && { /usr/bin/sed -i.bk "1s/.*/Include \\/etc\\/ssh\\/sshd_config.d\\/*/" /etc/ssh/sshd_config; include_dir="/etc/ssh/sshd_config.d/"; }
                /usr/bin/grep -qi "logingracetime" "${include_dir}01-mscp-sshd.conf" 2>/dev/null \
                  && /usr/bin/sed -i "" "s/logingracetime.*/logingracetime 30/I" "${include_dir}01-mscp-sshd.conf" \
                  || echo "logingracetime 30" >> "${include_dir}01-mscp-sshd.conf"
                """
        ),
        Rule(
            id: "os_policy_banner_ssh_configure",
            title: "SSH Login Banner Configured",
            description: "A U.S. Government use-only policy banner must be displayed at remote SSH login.",
            profiles: [.stig, .nist, .cmmc2, .cnssi, .nist171],
            category: .authentication,
            severity: .medium,
            stigId: "APPL-26-000023",
            cceId: "CCE-95258-0",
            cciIds: ["CCI-000048", "CCI-000050"],
            nistControls: ["AC-8"],
            checkCommand: "[ -f /etc/banner ] && echo '1' || echo '0'",
            expectedResult: .string("1"),
            remediateCommand: """
                cat > /etc/banner << 'EOF'
                You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
                By using this IS you consent to monitoring, interception, and search by authorized personnel.
                Unauthorized access or use is prohibited and subject to criminal and civil penalties.
                EOF
                """
        ),
        Rule(
            id: "auth_smartcard_enforce",
            title: "Enforce SmartCard / PIV Authentication",
            description: "SmartCard enforcement must be enabled to require CAC/PIV authentication for all users.",
            profiles: [.stig, .nist, .cmmc2, .cnssi],
            category: .authentication,
            severity: .high,
            stigId: "APPL-26-001160",
            cceId: "CCE-95150-9",
            cciIds: ["CCI-000765", "CCI-000766", "CCI-000767", "CCI-000768"],
            nistControls: ["IA-2(1)", "IA-2(2)", "IA-2(3)"],
            checkCommand: """
                /usr/bin/osascript -l JavaScript << 'EOS'
                $.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.smartcard').objectForKey('enforceSmartCard').js
                EOS
                """,
            expectedResult: .string("true"),
            remediateCommand: "defaults write /Library/Preferences/com.apple.security.smartcard enforceSmartCard -bool true",
            mobileconfig: true
        ),
        Rule(
            id: "os_pam_sudo_smartcard_enforce",
            title: "Require SmartCard for sudo",
            description: "PAM must be configured to require SmartCard authentication for sudo operations.",
            profiles: [.stig, .nist, .cnssi],
            category: .authentication,
            severity: .high,
            stigId: "APPL-26-001170",
            cceId: "CCE-95282-0",
            cciIds: ["CCI-000765", "CCI-000766"],
            nistControls: ["IA-2(1)", "IA-2(2)"],
            checkCommand: "/usr/bin/grep -c 'pam_smartcard.so' /etc/pam.d/sudo 2>/dev/null || echo '0'",
            expectedResult: .integer(1),
            remediateCommand: """
                /usr/bin/sed -i.bk 's/^#auth.*pam_smartcard/auth       sufficient     pam_smartcard/' /etc/pam.d/sudo 2>/dev/null || true
                """
        ),
    ] }

    // MARK: Network Security

    private static func networkSecurityRules() -> [Rule] { [
        Rule(
            id: "system_settings_bluetooth_disable",
            title: "Disable Bluetooth",
            description: "Bluetooth must be disabled to prevent unauthorized wireless bridging.",
            profiles: [.stig, .nist, .iso27001, .cmmc2, .cnssi, .soc2],
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
            profiles: [.stig, .nist, .gdpr, .cmmc2, .cnssi],
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
            profiles: [.stig, .nist, .iso27001, .cmmc1, .cmmc2, .cisL1, .cisL2, .cnssi, .soc2],
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
            description: "The firewall must be configured to drop all ICMP probes and unsolicited connection attempts (stealth mode).",
            profiles: [.stig, .nist, .cisL2, .cnssi],
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
            description: "Bonjour multicast advertising must be disabled to prevent service discovery by unauthorized parties.",
            profiles: [.stig, .nist, .cisL2, .cnssi],
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
            profiles: [.stig, .nist, .cisL1, .cisL2, .cnssi, .iso27001],
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
            profiles: [.stig, .nist, .cisL1, .cisL2, .cnssi],
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
            description: "Printer sharing must be disabled to reduce the attack surface.",
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
            description: "Content caching must be disabled to prevent the system from caching network content from other devices.",
            profiles: [.stig, .nist, .cisL2, .cnssi],
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
            description: "AirPlay receiver must be disabled to prevent audio and video from being streamed to this device.",
            profiles: [.stig, .nist, .cnssi],
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
            profiles: [.stig, .nist, .cisL1, .cisL2],
            category: .networkSecurity,
            severity: .low,
            cciIds: ["CCI-000366"],
            nistControls: ["CM-7"],
            checkCommand: "defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled 2>/dev/null || echo '0'",
            expectedResult: .string("0"),
            remediateCommand: "defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false"
        ),
    ] }

    // MARK: Auditing & Logging

    private static func auditingRules() -> [Rule] { [
        Rule(
            id: "audit_auditd_enabled",
            title: "Enable Security Auditing (auditd)",
            description: "The auditd daemon must be running to capture security-relevant events.",
            profiles: [.stig, .nist, .cmmc2, .cisL1, .cisL2, .cnssi, .nist171, .soc2],
            category: .auditingLogging,
            severity: .medium,
            stigId: "APPL-26-001003",
            cceId: "CCE-95104-6",
            cciIds: ["CCI-000130", "CCI-000131", "CCI-000159"],
            nistControls: ["AU-3", "AU-8", "AU-12"],
            checkCommand: """
                LAUNCHD_RUNNING=$(/bin/launchctl print system | /usr/bin/grep -c -E '\\tcom.apple.auditd')
                AUDITD_RUNNING=$(/usr/sbin/audit -c 2>/dev/null | /usr/bin/grep -c 'AUC_AUDITING')
                if [[ "$LAUNCHD_RUNNING" == "1" ]] && [[ -e /etc/security/audit_control ]] && [[ "$AUDITD_RUNNING" == "1" ]]; then
                  echo "pass"
                else
                  echo "fail"
                fi
                """,
            expectedResult: .string("pass"),
            remediateCommand: """
                if [[ ! -e /etc/security/audit_control ]] && [[ -e /etc/security/audit_control.example ]]; then
                  /bin/cp /etc/security/audit_control.example /etc/security/audit_control
                fi
                /bin/launchctl enable system/com.apple.auditd
                /bin/launchctl bootstrap system /System/Library/LaunchDaemons/com.apple.auditd.plist 2>/dev/null || true
                /usr/sbin/audit -i
                """
        ),
        Rule(
            id: "audit_flags_lo_configure",
            title: "Audit Login/Logout Events (lo flag)",
            description: "The audit system must be configured to record login and logout events.",
            profiles: [.stig, .nist, .cmmc2, .cnssi],
            category: .auditingLogging,
            severity: .medium,
            stigId: "APPL-26-001020",
            cceId: "CCE-95116-0",
            cciIds: ["CCI-000067", "CCI-000172"],
            nistControls: ["AU-2", "AU-12"],
            checkCommand: "/usr/bin/awk -F: '/^flags/{print $2}' /etc/security/audit_control 2>/dev/null | /usr/bin/grep -c 'lo'",
            expectedResult: .integer(1),
            remediateCommand: """
                /usr/bin/grep -qE '^flags:.*lo' /etc/security/audit_control \
                  || /usr/bin/sed -i.bk 's/^flags:/flags:lo,/' /etc/security/audit_control
                /usr/sbin/audit -s
                """
        ),
        Rule(
            id: "audit_flags_aa_configure",
            title: "Audit Authentication Events (aa flag)",
            description: "The audit system must record authentication and authorization events.",
            profiles: [.stig, .nist, .cmmc2, .cnssi],
            category: .auditingLogging,
            severity: .medium,
            stigId: "APPL-26-001021",
            cceId: "CCE-95105-3",
            cciIds: ["CCI-000172"],
            nistControls: ["AU-2", "AU-12"],
            checkCommand: "/usr/bin/awk -F: '/^flags/{print $2}' /etc/security/audit_control 2>/dev/null | /usr/bin/grep -c 'aa'",
            expectedResult: .integer(1),
            remediateCommand: """
                /usr/bin/grep -qE '^flags:.*aa' /etc/security/audit_control \
                  || /usr/bin/sed -i.bk 's/^flags:/flags:aa,/' /etc/security/audit_control
                /usr/sbin/audit -s
                """
        ),
        Rule(
            id: "audit_flags_ad_configure",
            title: "Audit Administrative Actions (ad flag)",
            description: "The audit system must record administrative-level actions such as system setting changes.",
            profiles: [.stig, .nist, .cmmc2, .cnssi],
            category: .auditingLogging,
            severity: .medium,
            stigId: "APPL-26-001022",
            cceId: "CCE-95106-1",
            cciIds: ["CCI-000172"],
            nistControls: ["AU-2", "AU-12"],
            checkCommand: "/usr/bin/awk -F: '/^flags/{print $2}' /etc/security/audit_control 2>/dev/null | /usr/bin/grep -c 'ad'",
            expectedResult: .integer(1),
            remediateCommand: """
                /usr/bin/grep -qE '^flags:.*ad' /etc/security/audit_control \
                  || /usr/bin/sed -i.bk 's/^flags:/flags:ad,/' /etc/security/audit_control
                /usr/sbin/audit -s
                """
        ),
        Rule(
            id: "audit_flags_fd_configure",
            title: "Audit File Deletion Events (fd flag)",
            description: "The audit system must record all file deletion attempts (successful and failed).",
            profiles: [.stig, .nist, .cmmc2, .cnssi],
            category: .auditingLogging,
            severity: .medium,
            stigId: "APPL-26-001023",
            cceId: "CCE-95109-5",
            cciIds: ["CCI-000172"],
            nistControls: ["AU-2", "AU-12"],
            checkCommand: "/usr/bin/awk -F: '/^flags/{print $2}' /etc/security/audit_control 2>/dev/null | /usr/bin/grep -c 'fd'",
            expectedResult: .integer(1),
            remediateCommand: """
                /usr/bin/grep -qE '^flags:.*fd' /etc/security/audit_control \
                  || /usr/bin/sed -i.bk 's/^flags:/flags:-fd,/' /etc/security/audit_control
                /usr/sbin/audit -s
                """
        ),
        Rule(
            id: "audit_flags_fm_configure",
            title: "Audit File Attribute Modification Events (fm flag)",
            description: "The audit system must record attribute changes to files (e.g., chmod, chown).",
            profiles: [.stig, .nist, .cmmc2, .cnssi],
            category: .auditingLogging,
            severity: .medium,
            stigId: "APPL-26-001024",
            cceId: "CCE-95110-3",
            cciIds: ["CCI-000172"],
            nistControls: ["AU-2", "AU-12"],
            checkCommand: "/usr/bin/awk -F: '/^flags/{print $2}' /etc/security/audit_control 2>/dev/null | /usr/bin/grep -c 'fm'",
            expectedResult: .integer(1),
            remediateCommand: """
                /usr/bin/grep -qE '^flags:.*fm' /etc/security/audit_control \
                  || /usr/bin/sed -i.bk 's/^flags:/flags:-fm,/' /etc/security/audit_control
                /usr/sbin/audit -s
                """
        ),
        Rule(
            id: "audit_flags_ex_configure",
            title: "Audit Program Execution Events (ex flag)",
            description: "The audit system must record all program execution events.",
            profiles: [.nist, .cnssi],
            category: .auditingLogging,
            severity: .medium,
            cceId: "CCE-95108-7",
            cciIds: ["CCI-000172"],
            nistControls: ["AU-2", "AU-12"],
            checkCommand: "/usr/bin/awk -F: '/^flags/{print $2}' /etc/security/audit_control 2>/dev/null | /usr/bin/grep -c 'ex'",
            expectedResult: .integer(1),
            remediateCommand: """
                /usr/bin/grep -qE '^flags:.*ex' /etc/security/audit_control \
                  || /usr/bin/sed -i.bk 's/^flags:/flags:ex,/' /etc/security/audit_control
                /usr/sbin/audit -s
                """
        ),
        Rule(
            id: "audit_retention_configure",
            title: "Audit Log Retention ≥ 7 Days",
            description: "Audit logs must be retained for a minimum of 7 days to support incident response.",
            profiles: [.stig, .nist, .cmmc2, .cnssi, .soc2],
            category: .auditingLogging,
            severity: .medium,
            stigId: "APPL-26-001040",
            cceId: "CCE-95127-7",
            cciIds: ["CCI-001849"],
            nistControls: ["AU-11"],
            checkCommand: "/usr/bin/awk -F: '/^expire-after/{print $2}' /etc/security/audit_control 2>/dev/null | /usr/bin/grep -c '7d'",
            expectedResult: .integer(1),
            remediateCommand: """
                /usr/bin/grep -q '^expire-after' /etc/security/audit_control \
                  && /usr/bin/sed -i.bk 's/^expire-after:.*/expire-after:7d/' /etc/security/audit_control \
                  || echo 'expire-after:7d' >> /etc/security/audit_control
                /usr/sbin/audit -s
                """
        ),
        Rule(
            id: "audit_configure_capacity_notify",
            title: "Audit Storage Capacity Warning Configured",
            description: "The system must notify administrators when audit storage capacity reaches 25%.",
            profiles: [.nist, .cnssi],
            category: .auditingLogging,
            severity: .low,
            cceId: "CCE-95126-9",
            cciIds: ["CCI-001855"],
            nistControls: ["AU-5(1)"],
            checkCommand: "/usr/bin/awk -F: '/^minfree/{print $2}' /etc/security/audit_control 2>/dev/null | /usr/bin/grep -c '25'",
            expectedResult: .integer(1),
            remediateCommand: """
                /usr/bin/grep -q '^minfree' /etc/security/audit_control \
                  && /usr/bin/sed -i.bk 's/^minfree:.*/minfree:25/' /etc/security/audit_control \
                  || echo 'minfree:25' >> /etc/security/audit_control
                /usr/sbin/audit -s
                """
        ),
        Rule(
            id: "audit_control_mode_configure",
            title: "Audit Control File Permissions (0440)",
            description: "The audit_control file must have permissions 0440 to prevent unauthorized modification.",
            profiles: [.stig, .nist, .cnssi],
            category: .auditingLogging,
            severity: .medium,
            stigId: "APPL-26-001060",
            cceId: "CCE-95130-1",
            cciIds: ["CCI-001493", "CCI-001494"],
            nistControls: ["AU-9"],
            checkCommand: "/bin/ls -le /etc/security/audit_control 2>/dev/null | /usr/bin/awk '{print $1}' | /usr/bin/grep -c '^-r--r-----'",
            expectedResult: .integer(1),
            remediateCommand: "chmod 0440 /etc/security/audit_control"
        ),
    ] }

    // MARK: Data Protection

    private static func dataProtectionRules() -> [Rule] { [
        Rule(
            id: "system_settings_filevault_enforce",
            title: "Enforce FileVault Full-Disk Encryption",
            description: "FileVault must be enabled and the MDM must prevent users from disabling it.",
            profiles: [.stig, .nist, .cmmc2, .cisL1, .cisL2, .cnssi, .iso27001, .gdpr, .soc2, .nist171],
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
                if [[ "$dontAllowDisable" == "true" ]] && [[ "$fileVault" == "1" ]]; then echo "1"; else echo "0"; fi
                """,
            expectedResult: .integer(1),
            remediateCommand: "fdesetup enable -user $(stat -f '%Su' /dev/console) 2>/dev/null || true",
            mobileconfig: true
        ),
        Rule(
            id: "os_sip_enable",
            title: "Ensure System Integrity Protection (SIP) is Enabled",
            description: "SIP protects system files and directories from unauthorized modification, even by the root user.",
            profiles: [.stig, .nist, .cmmc1, .cmmc2, .cisL1, .cisL2, .cnssi, .nist171],
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
            profiles: [.stig, .nist, .cnssi],
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
            profiles: [.stig, .nist, .cmmc1, .cmmc2, .cisL1, .cisL2, .cnssi, .nist171],
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
            profiles: [.stig, .nist, .cnssi],
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

    // MARK: Password Policy

    private static func passwordPolicyRules() -> [Rule] { [
        Rule(
            id: "pwpolicy_minimum_length_enforce",
            title: "Minimum Password Length ≥ 15 Characters",
            description: "Passwords must be at least 15 characters long to meet STIG requirements.",
            profiles: [.stig, .nist, .cmmc1, .cmmc2, .cnssi, .nist171],
            category: .passwordPolicy,
            severity: .medium,
            stigId: "APPL-26-003001",
            cceId: "CCE-95330-7",
            cciIds: ["CCI-000205"],
            nistControls: ["IA-5(1)"],
            checkCommand: """
                /usr/bin/pwpolicy -getaccountpolicies 2>/dev/null | /usr/bin/grep -c 'policyAttributePassword matches.*{15,}'  || \
                /usr/bin/pwpolicy -getglobalpolicies 2>/dev/null | /usr/bin/grep -c 'minChars = 1[5-9]\\|minChars = [2-9][0-9]' || echo '0'
                """,
            expectedResult: .integer(1),
            remediateCommand: """
                /usr/bin/pwpolicy -setglobalpolicies "minChars=15" 2>/dev/null || true
                """
        ),
        Rule(
            id: "pwpolicy_alpha_numeric_enforce",
            title: "Require Numeric Character in Passwords",
            description: "Passwords must contain at least one numeric character.",
            profiles: [.stig, .nist, .cmmc2, .cnssi],
            category: .passwordPolicy,
            severity: .medium,
            stigId: "APPL-26-003002",
            cceId: "CCE-95316-6",
            cciIds: ["CCI-000194"],
            nistControls: ["IA-5(1)"],
            checkCommand: "/usr/bin/pwpolicy -getaccountpolicies 2>/dev/null | /usr/bin/grep -c 'requiresNumeric' || echo '0'",
            expectedResult: .integer(1),
            remediateCommand: "/usr/bin/pwpolicy -setglobalpolicies 'requiresNumeric=1' 2>/dev/null || true"
        ),
        Rule(
            id: "pwpolicy_special_character_enforce",
            title: "Require Special Character in Passwords",
            description: "Passwords must contain at least one special character.",
            profiles: [.stig, .nist, .cmmc2, .cnssi],
            category: .passwordPolicy,
            severity: .medium,
            stigId: "APPL-26-003003",
            cceId: "CCE-95336-4",
            cciIds: ["CCI-001619"],
            nistControls: ["IA-5(1)"],
            checkCommand: "/usr/bin/pwpolicy -getaccountpolicies 2>/dev/null | /usr/bin/grep -c 'requiresSymbol' || echo '0'",
            expectedResult: .integer(1),
            remediateCommand: "/usr/bin/pwpolicy -setglobalpolicies 'requiresSymbol=1' 2>/dev/null || true"
        ),
        Rule(
            id: "pwpolicy_history_enforce",
            title: "Password History ≥ 5 Previous Passwords",
            description: "The system must prohibit password reuse for a minimum of 5 generations.",
            profiles: [.stig, .nist, .cmmc2, .cnssi],
            category: .passwordPolicy,
            severity: .medium,
            stigId: "APPL-26-003004",
            cceId: "CCE-95332-3",
            cciIds: ["CCI-000200"],
            nistControls: ["IA-5(1)"],
            checkCommand: "/usr/bin/pwpolicy -getaccountpolicies 2>/dev/null | /usr/bin/grep -c 'policyAttributePasswordHistoryDepth.*[5-9]\\|policyAttributePasswordHistoryDepth.*[0-9][0-9]' || echo '0'",
            expectedResult: .integer(1),
            remediateCommand: "/usr/bin/pwpolicy -setglobalpolicies 'usingHistory=5' 2>/dev/null || true"
        ),
        Rule(
            id: "pwpolicy_max_lifetime_enforce",
            title: "Maximum Password Age ≤ 60 Days",
            description: "Passwords must be changed every 60 days or less.",
            profiles: [.stig, .nist, .cmmc2, .cnssi],
            category: .passwordPolicy,
            severity: .medium,
            stigId: "APPL-26-003005",
            cceId: "CCE-95329-9",
            cciIds: ["CCI-000199"],
            nistControls: ["IA-5(1)"],
            checkCommand: "/usr/bin/pwpolicy -getaccountpolicies 2>/dev/null | /usr/bin/grep -c 'policyAttributeExpiresEveryNDays.*[1-5][0-9]\\|policyAttributeExpiresEveryNDays.*60' || echo '0'",
            expectedResult: .integer(1),
            remediateCommand: "/usr/bin/pwpolicy -setglobalpolicies 'maxMinutesUntilChangePassword=86400' 2>/dev/null || true"
        ),
        Rule(
            id: "pwpolicy_account_lockout_enforce",
            title: "Account Lockout after 3 Failed Attempts",
            description: "The system must lock accounts after 3 consecutive failed login attempts.",
            profiles: [.stig, .nist, .cmmc2, .cisL1, .cisL2, .cnssi, .nist171],
            category: .passwordPolicy,
            severity: .medium,
            stigId: "APPL-26-003006",
            cceId: "CCE-95318-2",
            cciIds: ["CCI-000044"],
            nistControls: ["AC-7"],
            checkCommand: "/usr/bin/pwpolicy -getaccountpolicies 2>/dev/null | /usr/bin/grep -c 'policyAttributeMaximumFailedAuthentications.*[1-3]' || echo '0'",
            expectedResult: .integer(1),
            remediateCommand: "/usr/bin/pwpolicy -setglobalpolicies 'maxFailedLoginAttempts=3' 2>/dev/null || true"
        ),
        Rule(
            id: "pwpolicy_account_lockout_timeout_enforce",
            title: "Account Lockout Duration ≥ 15 Minutes",
            description: "Locked accounts must remain locked for at least 15 minutes.",
            profiles: [.stig, .nist, .cmmc2, .cnssi],
            category: .passwordPolicy,
            severity: .medium,
            stigId: "APPL-26-003007",
            cceId: "CCE-95319-0",
            cciIds: ["CCI-002238"],
            nistControls: ["AC-7(2)"],
            checkCommand: "/usr/bin/pwpolicy -getaccountpolicies 2>/dev/null | /usr/bin/grep -c 'autoEnableInSeconds.*900\\|autoEnableInSeconds.*[1-9][0-9][0-9][0-9]' || echo '0'",
            expectedResult: .integer(1),
            remediateCommand: "/usr/bin/pwpolicy -setglobalpolicies 'minutesUntilFailedLoginReset=15' 2>/dev/null || true"
        ),
    ] }

    // MARK: Media Controls

    private static func mediaControlRules() -> [Rule] { [
        Rule(
            id: "os_camera_disable",
            title: "Disable Camera",
            description: "The built-in camera must be disabled in high-security environments to prevent unauthorized surveillance.",
            profiles: [.stig, .nist, .cnssi],
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
            profiles: [.stig, .nist, .cnssi],
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
            profiles: [.stig, .nist, .cnssi],
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
            profiles: [.stig, .nist, .cnssi],
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
            profiles: [.stig, .nist, .gdpr, .cnssi],
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

    // MARK: Misc

    private static func miscRules() -> [Rule] { [
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
