import StigItCore
import Testing

@Suite("Scanner service")
struct ScannerServiceTests {
    @Test("A nonzero check exit is an evaluation error even when stdout matches")
    func nonzeroExitIsError() async {
        let rule = TestFixtures.rule(checkCommand: "printf pass; exit 7")

        let status = await ScannerService.check(rule: rule)

        #expect(status == .error)
    }

    @Test("String expectations require exact trimmed output")
    func stringExpectationIsExact() async {
        let rule = TestFixtures.rule(checkCommand: "printf not-pass")

        let status = await ScannerService.check(rule: rule)

        #expect(status == .nonCompliant)
    }

    @Test("Whitespace around an exact string result is ignored")
    func stringExpectationTrimsWhitespace() async {
        let rule = TestFixtures.rule(checkCommand: "printf '  pass\\n'")

        let status = await ScannerService.check(rule: rule)

        #expect(status == .compliant)
    }
}
