import Foundation

extension RuleStore {
    static func authenticationRules() -> [Rule] { [
        Rule(
            id: "auth_ssh_password_authentication_disable",
            title: "Disable SSH Password Authentication",
            description: "Password-based SSH authentication must be disabled; only key-based or certificate authentication is permitted.",
            profiles: [.stig, .nist, .cisL2, .cmmc1, .cmmc2, .cnssi, .nist171, .hipaa, .glba],
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
            profiles: [.stig, .nist, .cisL1, .cisL2, .cmmc2, .cnssi, .nist171, .sox, .hipaa, .glba],
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
            description: "SSHD must send keep-alive messages every 900 seconds to terminate idle sessions.",
            profiles: [.stig, .nist, .cmmc2, .cnssi, .nist171, .sox, .hipaa, .glba],
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
            description: "SSHD must terminate sessions immediately after the keep-alive threshold (0 retries).",
            profiles: [.stig, .nist, .cmmc2, .cnssi, .nist171, .sox, .hipaa, .glba],
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
            description: "SSHD must disconnect unauthenticated sessions after 30 seconds.",
            profiles: [.stig, .nist, .cnssi, .sox, .hipaa, .glba],
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
            profiles: [.stig, .nist, .cmmc2, .cnssi, .nist171, .sox, .hipaa, .glba],
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
            profiles: [.stig, .nist, .cmmc2, .cnssi, .sox],
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
            profiles: [.stig, .nist, .cnssi, .sox],
            category: .authentication,
            severity: .high,
            stigId: "APPL-26-001170",
            cceId: "CCE-95282-0",
            cciIds: ["CCI-000765", "CCI-000766"],
            nistControls: ["IA-2(1)", "IA-2(2)"],
            checkCommand: "/usr/bin/grep -c 'pam_smartcard.so' /etc/pam.d/sudo 2>/dev/null || echo '0'",
            expectedResult: .integer(1),
            remediateCommand: "/usr/bin/sed -i.bk 's/^#auth.*pam_smartcard/auth       sufficient     pam_smartcard/' /etc/pam.d/sudo 2>/dev/null || true"
        ),
    ] }
}
