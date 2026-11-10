import XCTest
@testable import ArgentDefender

/// Verifies the Swift models against JSON envelopes captured from the real
/// `argent-engine` binary (see Fixtures/), so app ↔ engine contract drift is caught.
final class EngineContractTests: XCTestCase {
    func fixture(_ name: String) throws -> JSON {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Fixtures/\(name).json")
        return try JSONDecoder().decode(JSON.self, from: Data(contentsOf: url))
    }

    func testURLEnvelopeDecodesFindingsAndRisk() throws {
        let env = try fixture("url_envelope")
        XCTAssertEqual(env["ok"].bool, true)
        let outcome = ScanOutcome(raw: env["data"])
        XCTAssertFalse(outcome.findings.isEmpty)
        XCTAssertTrue(outcome.findings.contains { $0.category == "phishing" })
        XCTAssertNotNil(outcome.risk)
        XCTAssertLessThan(outcome.risk!.score, 100)
        XCTAssertNotNil(outcome.scanID)
        XCTAssertEqual(env["data"]["results"][0]["verdict"].string, "HIGH_RISK")
    }

    func testAPKEnvelope() throws {
        let env = try fixture("apk_envelope")
        let d = env["data"]
        XCTAssertEqual(d["apk"]["manifest"]["package"].string, "com.emanuelef.remote_capture")
        XCTAssertEqual(d["apk"]["signing"]["v2"].bool, true)
        XCTAssertEqual(d["apk"]["signing"]["certificates_sha256"][0].string, "ac701125e653189b2bbaa78fba60c1136b88b8780078db0dc4257f019c81c9fe")
        let f = ScanOutcome(raw: d).findings
        XCTAssertTrue(f.allSatisfy { $0.severity <= .INFORMATIONAL }, "benign open-source APK must not raise alerts")
    }

    func testHistoryDecodes() throws {
        let env = try fixture("history_envelope")
        let h = env["data"].decode([ScanSummary].self)
        XCTAssertNotNil(h)
        XCTAssertFalse(h!.isEmpty)
    }

    func testErrorEnvelope() throws {
        let env = try fixture("error_envelope")
        XCTAssertEqual(env["ok"].bool, false)
        XCTAssertTrue(env["data"].isNull)
        XCTAssertNotNil(env["error"].string)
    }

    func testSeverityOrderingAndLimitations() {
        XCTAssertTrue(Severity.CRITICAL > .HIGH && Severity.LOW > .INFORMATIONAL && Severity.INFORMATIONAL > .NOT_ACCESSIBLE)
        let lim = Finding(id: "1", title: "x", category: "limitation", severity: .NOT_ACCESSIBLE, confidence: .CONFIRMED, engine: "e", rule: "r",
                          subject: Subject(kind: "device", name: "d"), evidence: [], recommendation: "")
        XCTAssertTrue([lim].actionable.isEmpty)
        XCTAssertEqual([lim].limitations.count, 1)
    }

    func testScoreColors() {
        XCTAssertEqual(Theme.scoreColor(95), Theme.secure)
        XCTAssertEqual(Theme.scoreColor(10), Theme.critical)
    }

    func testEngineLocatesBinaryInDevelopment() async throws {
        let engine = Engine()
        try XCTSkipUnless(engine.isAvailable, "build the Rust engine first (cargo build --release)")
        let env = try await engine.run(["env"])
        XCTAssertNotNil(env["host"]["arch"].string)
    }
}
