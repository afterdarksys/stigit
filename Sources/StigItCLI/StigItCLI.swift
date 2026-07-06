import Foundation
import StigItCore

@MainActor
@main
struct StigItCLI {

    static let version = "2.0.0"

    static func main() async {
        let arguments = Array(CommandLine.arguments.dropFirst())

        guard let first = arguments.first else {
            printUsage()
            exit(ExitCode.success)
        }

        // Legacy flat-flag invocation (`stigit-cli --profile stig --remediate`) still
        // works so existing MDM scripts don't break on upgrade.
        if first.hasPrefix("-") && first != "-h" && first != "--help" {
            exit(await runLegacy(ArgScanner(arguments)))
        }

        let rest = ArgScanner(Array(arguments.dropFirst()))
        switch first {
        case "scan":
            exit(await ScanCommand.run(rest))
        case "remediate":
            exit(await RemediateCommand.run(rest))
        case "waiver", "waivers":
            exit(WaiverCommand.run(rest))
        case "fleet":
            exit(FleetCommand.run(rest))
        case "schedule":
            exit(ScheduleCommand.run(rest))
        case "mobileconfig":
            exit(MobileConfigCommand.run(rest))
        case "rules":
            exit(RulesCommand.run(rest))
        case "version", "--version":
            print("stigit-cli \(version)")
            exit(ExitCode.success)
        case "help", "-h", "--help":
            printUsage()
            exit(ExitCode.success)
        default:
            Console.error("Unknown command '\(first)'. Run 'stigit-cli help' for usage.")
            exit(ExitCode.error)
        }
    }

    // MARK: - Legacy shim

    private static func runLegacy(_ args: ArgScanner) async -> Int32 {
        Console.error("Note: flat-flag usage is deprecated; see 'stigit-cli help' for the subcommand interface.")

        // The old interface never gated exit codes — preserve that with --fail-on none
        // unless the caller opted in explicitly.
        var tokens = args.tokens
        if !args.has("--fail-on") { tokens += ["--fail-on", "none"] }
        if args.has("--generate-mobileconfig") {
            let status = MobileConfigCommand.run(args)
            if !args.has("--remediate") && args.value(for: "--export") == nil
                && !args.has("--backup") && args.value(for: "--profile") == nil {
                return status
            }
        }
        let scanner = ArgScanner(tokens)
        if args.has("--remediate") {
            return await RemediateCommand.run(scanner)
        }
        return await ScanCommand.run(scanner)
    }

    // MARK: - Usage

    private static func printUsage() {
        print("""
        stigit-cli \(version) – macOS Security Compliance Scanner
        ==========================================================

        USAGE: stigit-cli <command> [options]

        COMMANDS:
          scan          Scan this machine against a compliance profile
          remediate     Scan, then apply fixes for unwaived failing rules
          waiver        Manage documented exceptions (list | add | remove)
          fleet         Aggregate endpoint reports (summarize <dir>)
          schedule      Manage the recurring launchd scan (install | uninstall | status)
          mobileconfig  Generate an MDM .mobileconfig profile
          rules         List the rule library (rules list)
          version       Print the version

        SCAN / REMEDIATE OPTIONS:
          --profile <key>       \(StigItCore.ComplianceProfile.allCases.map(\.key).joined(separator: " | "))
                                (default: stig)
          --severity <level>    high | medium | low
          --rules-dir <path>    Load extra YAML rules (macos_security schema)
          --waivers <file>      Waiver file (default: ~/.stigit/waivers.json)
          --format <fmt>        text | json | ndjson | junit   (stdout format)
          --quiet, -q           Suppress per-rule output and progress
          --export <fmt>        Also write a report file: json | csv | summary | ndjson | junit
          --output <dir>        Report directory (default: ~/.stigit/reports/)
          --fleet-dir <dir>     Publish this endpoint's report into a fleet drop directory
          --history             Save this scan to ~/.stigit/history/
          --compare             Include drift vs. the previous saved scan
          --fail-on <level>     Exit 1 when unwaived findings exist at/above:
                                high (default) | medium | low | any | none

        REMEDIATE-ONLY OPTIONS:
          --dry-run             Print the staged remediation script without executing
          --backup              Snapshot config to ~/.stigit/backups/ first
          --non-interactive     No GUI prompt; requires root (sudo / MDM)

        EXIT CODES:
          0  compliant (or findings below --fail-on)
          1  unwaived findings at/above --fail-on
          2  usage or runtime error

        EXAMPLES:
          stigit-cli scan --profile cis1 --format json --history --compare
          stigit-cli scan --profile stig --fleet-dir /Volumes/Compliance/fleet --quiet
          sudo stigit-cli remediate --profile stig --backup --non-interactive
          stigit-cli waiver add os_ssh_root_login --reason "break-glass account" \\
                     --approved-by "J. Doe" --ticket SEC-142 --expires 2026-12-31
          stigit-cli fleet summarize /Volumes/Compliance/fleet --format csv
          sudo stigit-cli schedule install --interval daily --profile stig \\
                     --fleet-dir /Volumes/Compliance/fleet
        """)
    }
}
