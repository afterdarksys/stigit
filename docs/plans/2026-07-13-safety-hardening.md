# StigIt Safety Hardening Implementation Plan

> **For Codex:** Use `${SUPERPOWERS_SKILLS_ROOT}/skills/collaboration/executing-plans/SKILL.md` to implement this plan task-by-task.

**Goal:** Make StigIt fail closed, prevent unsafe remediation and restore behavior, and make its automation/reporting contracts testable and reliable.

**Architecture:** Add a Swift Testing target around `StigItCore`, move behavior that must be tested out of CLI/UI-only code where necessary, and represent command execution as a structured result rather than an untyped string. Preserve the existing CLI and SwiftUI surfaces while making invalid input and incomplete evaluations explicit errors.

**Tech Stack:** Swift 6, Swift Package Manager, Swift Testing, Foundation, SwiftUI, Yams, macOS `plutil` smoke validation.

---

### Task 1: Establish the test harness

**Files:**
- Modify: `Package.swift`
- Create: `Tests/StigItCoreTests/TestFixtures.swift`

1. Add a `StigItCoreTests` test target depending on `StigItCore`.
2. Add reusable rule/report fixtures.
3. Run `swift test` and verify the empty harness compiles.

### Task 2: Fail-closed scan outcomes

**Files:**
- Modify: `Sources/Shared/Services/ScannerService.swift`
- Modify: `Sources/Shared/Models/ScanReport.swift`
- Test: `Tests/StigItCoreTests/ScannerServiceTests.swift`
- Test: `Tests/StigItCoreTests/ScanReportTests.swift`

1. Write failing tests proving nonzero/launch failures become `.error`, string results require exact trimmed equality, errored high controls fail the automation gate, and an entirely unevaluated report cannot score 100%.
2. Run the focused tests and confirm the expected failures.
3. Introduce a structured shell result carrying stdout, stderr, and termination status; update evaluation and gating.
4. Run focused and full tests.

### Task 3: Validate CLI options and explicit rule directories

**Files:**
- Modify: `Sources/StigItCLI/CLISupport.swift`
- Modify: `Sources/StigItCLI/ScanCommands.swift`
- Test: `Tests/StigItCoreTests/ArgumentValidationTests.swift` if parsing is moved into core; otherwise add CLI contract smoke assertions to the verification script.

1. Add value-aware option parsing that distinguishes absent flags from missing values and rejects unknown options.
2. Make an explicitly unreadable/empty rule directory a runtime error rather than a built-in fallback.
3. Verify `scan --profile` and a nonexistent `--rules-dir` both exit 2 without scanning.

### Task 4: Stabilize JSON and fleet artifacts

**Files:**
- Modify: `Sources/Shared/Models/ScanReport.swift`
- Modify: `Sources/Shared/Services/FleetService.swift`
- Test: `Tests/StigItCoreTests/ReportEncodingTests.swift`

1. Write failing round-trip tests requiring encoded summary counts and rejecting unsupported schema versions.
2. Add explicit Codable handling for the stable schema.
3. Escape fleet CSV fields and test commas, quotes, newlines, and formula-leading values.

### Task 5: Make GUI remediation waiver- and state-aware

**Files:**
- Add: `Sources/Shared/Services/RemediationPlanner.swift`
- Modify: `Sources/StigIt/Views/StandardWorkflowView.swift`
- Modify: `Sources/StigIt/Views/StagingModalView.swift`
- Test: `Tests/StigItCoreTests/RemediationPlannerTests.swift`

1. Write failing tests proving only selected, non-compliant, unwaived rules are eligible.
2. Implement the shared planner and use it in both GUI paths and the CLI.
3. Surface cancelled/failed remediation instead of silently rescanning.

### Task 6: Replace unsafe backup mapping

**Files:**
- Modify: `Sources/Shared/Services/BackupRestoreService.swift`
- Test: `Tests/StigItCoreTests/BackupRestoreServiceTests.swift`

1. Write failing tests for safe backup-name validation and lossless source/destination manifest mapping.
2. Store structured manifest entries rather than reconstructing paths from underscores.
3. Stop reporting success when required copy operations fail; restore individual contents to exact paths.

### Task 7: Correct rule loading and applicability

**Files:**
- Modify: `Sources/Shared/Models/Rule.swift`
- Modify: `Sources/Shared/Services/YAMLRuleLoader.swift`
- Modify: `Sources/StigItCLI/CLISupport.swift`
- Add: `.gitmodules`
- Test: `Tests/StigItCoreTests/YAMLRuleLoaderTests.swift`

1. Write failing fixtures for numeric/string ODV selection, macOS applicability, parse diagnostics, and updated duplicate replacement.
2. Make ODV selection profile-aware and preserve supported macOS versions.
3. Let explicitly loaded rules replace built-ins with matching IDs.
4. Restore valid submodule metadata for `reference/macos_security`.

### Task 8: Generate valid MobileConfig artifacts

**Files:**
- Modify: `Sources/Shared/Services/MobileConfigGenerator.swift`
- Modify: `Sources/StigItCLI/ManagementCommands.swift`
- Test: `Tests/StigItCoreTests/MobileConfigGeneratorTests.swift`

1. Write failing tests for XML metacharacters, slash-containing profile names, stable payload structure, and empty payload sets.
2. XML-escape all interpolated values and use filesystem-safe output names.
3. Model payload metadata rather than relying on a hardcoded rule-ID switch.
4. Validate generated fixtures with `plutil -lint`.

### Task 9: Final verification and documentation

**Files:**
- Modify: `README.md`

1. Run `swift test` and require zero failures.
2. Run debug and release builds.
3. Run CLI contract smoke checks for help, invalid arguments, scan JSON, waivers, fleet summaries, and MobileConfig generation.
4. Run `plutil -lint` on generated profiles and `git diff --check`.
5. Document evaluation-error semantics, trusted rule-directory requirements, root/console-user behavior, supported packaging state, and accessibility verification still required for distribution.
