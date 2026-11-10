import Foundation
import SwiftUI
import AppKit

enum NavSection: String, CaseIterable, Identifiable, Hashable {
    case overview = "Overview"
    case devices = "Device Center"
    case quickScan = "Quick Scan"
    case fullScan = "Full Scan"
    case deepScan = "Deep Scan"
    case android = "Android Scanner"
    case iphone = "iPhone Scanner"
    case malware = "Malware Analysis"
    case gaming = "Gaming Watch"
    case network = "Network Security"
    case forensics = "Digital Forensics"
    case intel = "Threat Intelligence"
    case ai = "AI Intelligence"
    case reports = "Security Reports"
    case history = "History"
    case settings = "Settings"

    var id: String { rawValue }
    var icon: String {
        switch self {
        case .overview: return "gauge.with.dots.needle.67percent"
        case .devices: return "iphone.and.arrow.forward"
        case .quickScan: return "bolt.shield"
        case .fullScan: return "shield.lefthalf.filled"
        case .deepScan: return "scope"
        case .android: return "candybarphone"
        case .iphone: return "iphone"
        case .malware: return "ladybug"
        case .gaming: return "suit.spade"
        case .network: return "network.badge.shield.half.filled"
        case .forensics: return "magnifyingglass.circle"
        case .intel: return "globe.asia.australia"
        case .ai: return "brain"
        case .reports: return "doc.richtext"
        case .history: return "clock.arrow.circlepath"
        case .settings: return "gearshape"
        }
    }
    static let groups: [SidebarGroup] = [
        SidebarGroup(title: "Command", items: [.overview, .devices]),
        SidebarGroup(title: "Scan", items: [.quickScan, .fullScan, .deepScan]),
        SidebarGroup(title: "Devices", items: [.android, .iphone]),
        SidebarGroup(title: "Analysis", items: [.malware, .gaming, .network, .forensics]),
        SidebarGroup(title: "Intelligence", items: [.intel, .ai]),
        SidebarGroup(title: "Records", items: [.reports, .history, .settings]),
    ]
}

struct SidebarGroup: Identifiable {
    let title: String
    let items: [NavSection]
    var id: String { title }
}


struct AppNotification: Identifiable, Hashable {
    let id = UUID()
    let date = Date()
    let title: String
    let detail: String
    let severity: Severity
}

@MainActor
final class AppState: ObservableObject {
    let engine = Engine()

    @Published var selection: NavSection? = .overview
    @Published var env: JSON = .null
    @Published var devices: JSON = .null
    @Published var deviceHistory: [JSON] = []
    @Published var history: [ScanSummary] = []
    @Published var recentFindings: [Finding] = []
    @Published var lastBench: JSON = .null
    @Published var intelStats: JSON = .null
    @Published var notifications: [AppNotification] = []
    @Published var busy: Set<String> = []
    @Published var errorMessage: String?
    @Published var lastOutcome: [NavSection: ScanOutcome] = [:]

    @AppStorage("analystName") var analystName: String = NSFullUserName()
    @AppStorage("minIOSMajor") var minIOSMajor: Int = 17
    @AppStorage("signReports") var signReports: Bool = true

    var connectedCount: Int {
        devices["android"]["devices"].array.filter { $0["state"].string == "device" }.count + devices["ios"]["devices"].array.count
    }

    func isBusy(_ key: String) -> Bool { busy.contains(key) }

    /// Run an engine command with busy tracking and error surfacing.
    @discardableResult
    func run(_ key: String, _ args: [String], stdin: String? = nil) async -> JSON? {
        busy.insert(key)
        defer { busy.remove(key) }
        do {
            return try await engine.run(args, stdin: stdin)
        } catch {
            errorMessage = error.localizedDescription
            return nil
        }
    }

    /// Run a scan-type command, store the outcome for a section, notify, refresh history.
    func runScan(_ section: NavSection, _ args: [String], stdin: String? = nil, title: String) async {
        guard let data = await run(section.rawValue, args, stdin: stdin) else { return }
        let outcome = ScanOutcome(raw: data)
        lastOutcome[section] = outcome
        let f = outcome.findings.actionable
        let worst = f.map(\.severity).max() ?? .INFORMATIONAL
        let score = outcome.risk.map { "score \($0.score)/100 · " } ?? ""
        notify(title, "\(score)\(f.count) finding(s)", worst)
        if !data["bench"].isNull { lastBench = data["bench"] }
        await refreshHistory()
    }

    func notify(_ title: String, _ detail: String, _ sev: Severity) {
        notifications.insert(AppNotification(title: title, detail: detail, severity: sev), at: 0)
        if notifications.count > 100 { notifications.removeLast() }
    }

    func bootstrap() async {
        if let e = await run("env", ["env"]) { env = e; intelStats = e["intel"] }
        await refreshDevices()
        await refreshHistory()
    }

    func refreshDevices() async {
        if let d = await run("devices", ["devices"]) { devices = d }
        if let h = await run("devhist", ["device-history"]) { deviceHistory = h.array }
    }

    func refreshIntel() async {
        if let s = await run("intelstats", ["intel", "stats"]) { intelStats = s }
    }

    func refreshHistory() async {
        guard let h = await run("history", ["history", "--limit", "200"]) else { return }
        history = h.decode([ScanSummary].self) ?? []
        // Aggregate findings of the most recent scans for overview metrics.
        var agg: [Finding] = []
        var seen = Set<String>()
        for s in history.prefix(8) {
            if let r = try? await engine.run(["scan-get", s.scan_id]) {
                for f in r["result"]["findings"].decode([Finding].self) ?? [] where seen.insert(f.uniqueKey).inserted {
                    agg.append(f)
                }
                if lastBench.isNull, !r["bench"].isNull { lastBench = r["bench"] }
            }
        }
        recentFindings = agg
    }
}
