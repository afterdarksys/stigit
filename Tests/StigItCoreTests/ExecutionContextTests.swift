@testable import StigItCore
import Testing

@Suite("Rule execution context")
struct ExecutionContextTests {
    @Test("Root wraps console-user rules with a user-scoped shell")
    func rootUsesConsoleUser() {
        let rule = TestFixtures.rule(executionContext: .consoleUser)

        let command = ExecutionContextService.command(
            for: rule,
            runningAsRoot: true,
            consoleUsername: "contractor"
        )

        #expect(command == "/usr/bin/sudo -u 'contractor' -H /bin/sh -c 'printf remediate'")
    }

    @Test("System rules remain root-scoped")
    func systemRuleIsUnchanged() {
        let rule = TestFixtures.rule(executionContext: .system)

        let command = ExecutionContextService.command(
            for: rule,
            runningAsRoot: true,
            consoleUsername: "contractor"
        )

        #expect(command == "printf remediate")
    }

    @Test("A root console-user rule fails closed when nobody is logged in")
    func missingConsoleUserFailsClosed() {
        let rule = TestFixtures.rule(executionContext: .consoleUser)

        let command = ExecutionContextService.command(
            for: rule,
            runningAsRoot: true,
            consoleUsername: nil
        )

        #expect(command == nil)
    }

    @Test("Built-in user preference rules run in the console user's context")
    @MainActor
    func builtInUserPreferenceRulesAreScoped() {
        let userScopedIDs = Set(
            RuleStore.defaultRules()
                .filter { $0.executionContext == .consoleUser }
                .map(\.id)
        )

        #expect(userScopedIDs == [
            "system_settings_screensaver_password_enforce",
            "system_settings_screensaver_timeout_enforce",
            "os_airdrop_disable",
            "system_settings_bluetooth_sharing_disable",
            "system_settings_terminal_secure_keyboard_enable",
            "finder_show_hidden",
            "safari_develop_menu",
            "dock_autohide_fast",
        ])
    }
}
