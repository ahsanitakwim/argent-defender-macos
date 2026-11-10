import Foundation
import SwiftUI

enum Severity: String, Codable, CaseIterable, Comparable {
    case NOT_ACCESSIBLE, INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL

    var rank: Int { Severity.allCases.firstIndex(of: self) ?? 0 }
    static func < (a: Severity, b: Severity) -> Bool { a.rank < b.rank }

    var label: String {
        switch self {
        case .NOT_ACCESSIBLE: return "Not accessible"
        case .INFORMATIONAL: return "Info"
        default: return rawValue.capitalized
        }
    }
    var color: Color {
        switch self {
        case .CRITICAL: return Theme.critical
        case .HIGH: return Theme.amber
        case .MEDIUM: return Theme.electric
        case .LOW: return Theme.cyan
        case .INFORMATIONAL: return Theme.secure
        case .NOT_ACCESSIBLE: return .gray
        }
    }
}

enum Confidence: String, Codable, CaseIterable {
    case LOW, MEDIUM, HIGH, CONFIRMED
}

struct Subject: Codable, Hashable {
    var kind: String
    var name: String
    var path: String?
    var sha256: String?
}

struct Finding: Codable, Identifiable, Hashable {
    var id: String
    var title: String
    var category: String
    var severity: Severity
    var confidence: Confidence
    var engine: String
    var rule: String
    var subject: Subject
    var evidence: [String]
    var recommendation: String

    var isLimitation: Bool { category == "limitation" }
    var uniqueKey: String { id + evidence.joined(separator: "|") }

    static let threatCategories: Set<String> = ["malware", "spyware", "stalkerware", "ransomware", "banking_trojan", "rat", "adware", "pua"]
}

struct RiskScore: Codable, Hashable {
    var score: Int
    var rating: String
    var by_severity: [String: Int]
}

struct ScanSummary: Codable, Identifiable, Hashable {
    var scan_id: String
    var kind: String
    var target: String
    var device_id: String?
    var started_at: String
    var finished_at: String?
    var score: Int?
    var findings: Int
    var id: String { scan_id }
}

/// A generic result of a scan-like command, as returned by the engine.
struct ScanOutcome: Identifiable {
    let id = UUID()
    let raw: JSON
    var findings: [Finding] { raw["findings"].decode([Finding].self) ?? [] }
    var risk: RiskScore? { raw["risk"].decode(RiskScore.self) }
    var scanID: String? { raw["scan_id"].string }
    var gambling: String? { raw["gambling_classification"].string }
}

extension Array where Element == Finding {
    var actionable: [Finding] { filter { !$0.isLimitation } }
    var limitations: [Finding] { filter { $0.isLimitation } }
    func count(_ cats: Set<String>) -> Int { filter { cats.contains($0.category) && $0.severity >= .LOW }.count }
}
