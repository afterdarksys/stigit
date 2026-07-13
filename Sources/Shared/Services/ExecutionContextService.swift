import Foundation

enum ExecutionContextService {
    static func command(
        for rule: Rule,
        command: String? = nil,
        runningAsRoot: Bool,
        consoleUsername: String?
    ) -> String? {
        let rawCommand = command ?? rule.remediateCommand
        guard rule.executionContext == .consoleUser, runningAsRoot else {
            return rawCommand
        }
        guard let username = validatedUsername(consoleUsername) else { return nil }
        return "/usr/bin/sudo -u \(shellQuote(username)) -H /bin/sh -c \(shellQuote(rawCommand))"
    }

    static func currentConsoleUsername() -> String? {
        if geteuid() != 0 {
            return validatedUsername(NSUserName())
        }
        let attributes = try? FileManager.default.attributesOfItem(atPath: "/dev/console")
        return validatedUsername(attributes?[.ownerAccountName] as? String)
    }

    private static func validatedUsername(_ username: String?) -> String? {
        guard let username,
              !username.isEmpty,
              username != "root",
              username != "loginwindow",
              username != "_mbsetupuser" else { return nil }
        let allowed = CharacterSet.alphanumerics
            .union(CharacterSet(charactersIn: "._-"))
        guard username.rangeOfCharacter(from: allowed.inverted) == nil else { return nil }
        return username
    }

    private static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
