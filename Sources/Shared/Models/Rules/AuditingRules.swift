import Foundation

extension RuleStore {
    static func auditingRules() -> [Rule] { [
        Rule(
            id: "audit_auditd_enabled",
            title: "Enable Security Auditing (auditd)",
            description: "The auditd daemon must be running to capture security-relevant events.",
            profiles: [.stig, .nist, .cmmc2, .cisL1, .cisL2, .cnssi, .nist171, .soc2, .sox, .hipaa, .glba],
            category: .auditingLogging,
            severity: .medium,
            stigId: "APPL-26-001003",
            cceId: "CCE-95104-6",
            cciIds: ["CCI-000130", "CCI-000131", "CCI-000159"],
            nistControls: ["AU-3", "AU-8", "AU-12"],
            checkCommand: """
                LAUNCHD=$(/bin/launchctl print system | /usr/bin/grep -c -E '\\tcom.apple.auditd')
                RUNNING=$(/usr/sbin/audit -c 2>/dev/null | /usr/bin/grep -c 'AUC_AUDITING')
                [[ "$LAUNCHD" == "1" ]] && [[ -e /etc/security/audit_control ]] && [[ "$RUNNING" == "1" ]] && echo "pass" || echo "fail"
                """,
            expectedResult: .string("pass"),
            remediateCommand: """
                [[ ! -e /etc/security/audit_control ]] && [[ -e /etc/security/audit_control.example ]] && /bin/cp /etc/security/audit_control.example /etc/security/audit_control
                /bin/launchctl enable system/com.apple.auditd
                /bin/launchctl bootstrap system /System/Library/LaunchDaemons/com.apple.auditd.plist 2>/dev/null || true
                /usr/sbin/audit -i
                """
        ),
        Rule(
            id: "audit_flags_lo_configure",
            title: "Audit Login/Logout Events (lo flag)",
            description: "The audit system must record login and logout events.",
            profiles: [.stig, .nist, .cmmc2, .cnssi, .sox, .hipaa, .glba],
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
            profiles: [.stig, .nist, .cmmc2, .cnssi, .sox, .hipaa, .glba],
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
            profiles: [.stig, .nist, .cmmc2, .cnssi, .sox, .hipaa, .glba],
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
            description: "The audit system must record all file deletion attempts, both successful and failed.",
            profiles: [.stig, .nist, .cmmc2, .cnssi, .sox, .hipaa, .glba],
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
            description: "The audit system must record attribute changes to files such as chmod and chown.",
            profiles: [.stig, .nist, .cmmc2, .cnssi, .sox, .hipaa, .glba],
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
            profiles: [.nist, .cnssi, .sox, .hipaa],
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
            profiles: [.stig, .nist, .cmmc2, .cnssi, .soc2, .sox, .hipaa, .glba],
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
            title: "Audit Storage Capacity Warning at 25%",
            description: "The system must notify administrators when audit storage capacity reaches 25%.",
            profiles: [.nist, .cnssi, .sox, .hipaa, .glba],
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
            profiles: [.stig, .nist, .cnssi, .sox, .hipaa, .glba],
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
}
