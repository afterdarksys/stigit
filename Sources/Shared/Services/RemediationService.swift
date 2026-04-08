import Foundation

public class RemediationService {
    
    /// Generates a single bash script string that concatenates all remediations
    public static func generateStagingScript(for rules: [Rule]) -> String {
        let commands = rules
            .filter { $0.isSelectedForRemediation && $0.status != .compliant }
            .map { $0.remediateCommand }
        
        return commands.joined(separator: "\n")
    }
    
    /// Executes the staged commands using an AppleScript prompt to gain administrator privileges
    public static func submit(rules: [Rule]) async -> Bool {
        let scriptContent = generateStagingScript(for: rules)
        
        guard !scriptContent.isEmpty else {
            return true
        }
        
        // Escape quotes and backslashes for AppleScript
        let escapedScript = scriptContent
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        
        let appleScript = """
        do shell script "\(escapedScript)" with administrator privileges
        """
        
        return await runAppleScript(appleScript)
    }
    
    private static func runAppleScript(_ script: String) async -> Bool {
        let task = Process()
        let pipe = Pipe()
        
        task.standardOutput = pipe
        task.standardError = pipe
        task.arguments = ["-e", script]
        task.launchPath = "/usr/bin/osascript"
        
        do {
            try task.run()
            task.waitUntilExit()
            return task.terminationStatus == 0
        } catch {
            return false
        }
    }
}
