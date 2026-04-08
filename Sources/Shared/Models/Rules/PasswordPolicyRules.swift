import Foundation

extension RuleStore {
    static func passwordPolicyRules() -> [Rule] { [
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
                /usr/bin/pwpolicy -getaccountpolicies 2>/dev/null | /usr/bin/grep -c 'policyAttributePassword matches.*{15,}' || \
                /usr/bin/pwpolicy -getglobalpolicies 2>/dev/null | /usr/bin/grep -c 'minChars = 1[5-9]\\|minChars = [2-9][0-9]' || echo '0'
                """,
            expectedResult: .integer(1),
            remediateCommand: "/usr/bin/pwpolicy -setglobalpolicies 'minChars=15' 2>/dev/null || true"
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
}
