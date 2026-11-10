import SwiftUI
import AppKit

@MainActor
struct OverviewView: View {
    @EnvironmentObject var state: AppState

    private var f: [Finding] { state.recentFindings.actionable }
    private var deviceScore: Int? { state.history.first { ["android_audit", "ios_audit", "ios_backup"].contains($0.kind) }?.score }
    private let cols = [GridItem(.adaptive(minimum: 210), spacing: 14)]

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            PageHeader(section: .overview, subtitle: "Security posture across connected devices, scans and intelligence")
            LazyVGrid(columns: cols, spacing: 14) {
                MetricCard(title: "Connected Devices", value: "\(state.connectedCount)", detail: deviceDetail, icon: "iphone.and.arrow.forward", tint: Theme.cyan)
                MetricCard(title: "Device Security Score", value: deviceScore.map { "\($0)" } ?? "—", detail: deviceScore == nil ? "Run an Android or iPhone scan" : "latest device assessment", icon: "gauge.with.dots.needle.67percent", tint: Theme.scoreColor(deviceScore))
                MetricCard(title: "Malware Findings", value: "\(f.count(Finding.threatCategories))", detail: "malware · spyware · ransomware · trojans", icon: "ladybug.fill", tint: Theme.critical)
                MetricCard(title: "Suspicious Applications", value: "\(Set(f.filter { $0.subject.kind == "package" && $0.severity >= .MEDIUM }.map(\.subject.name)).count)", detail: "medium severity or above", icon: "app.badge.checkmark", tint: Theme.amber)
                MetricCard(title: "Judol Indicators", value: "\(f.count(["gambling"]))", detail: "Gaming Watch", icon: "suit.spade.fill", tint: Theme.amber)
                MetricCard(title: "Phishing Indicators", value: "\(f.count(["phishing"]))", detail: "URL & domain analysis", icon: "link.badge.plus", tint: Theme.electric)
                MetricCard(title: "Network Threats", value: "\(f.count(["network_threat"]))", detail: "C2, proxies, redirects", icon: "network.badge.shield.half.filled", tint: Theme.electric)
                MetricCard(title: "Last Scan", value: lastScanText, detail: state.history.first?.kind.replacingOccurrences(of: "_", with: " ") ?? "", icon: "clock", tint: Theme.titanium)
                MetricCard(title: "Threat Database", value: "\(state.intelStats["total"].int ?? 0)", detail: intelDetail, icon: "externaldrive.badge.checkmark", tint: Theme.secure)
                MetricCard(title: "Scan Performance", value: perfValue, detail: perfDetail, icon: "speedometer", tint: Theme.cyan)
            }
            HStack(alignment: .top, spacing: 14) {
                Panel(title: "Findings by severity (recent scans)", systemImage: "chart.bar") {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(Severity.allCases.reversed().filter { $0 != .NOT_ACCESSIBLE }, id: \.self) { severity in
                            let count = f.filter { $0.severity == severity }.count
                            HStack {
                                Text(severity.label).font(.caption).frame(width: 88, alignment: .leading)
                                ProgressView(value: Double(count), total: Double(max(1, f.count)))
                                    .accentColor(severity.color)
                                Text("\(count)").font(.caption.monospacedDigit()).frame(width: 28, alignment: .trailing)
                            }
                        }
                    }
                    .frame(height: 200)
                }
                Panel(title: "Security score trend", systemImage: "chart.xyaxis.line") {
                    let pts: [ScorePoint] = state.history.filter { $0.score != nil }.prefix(30).reversed().enumerated().map { ScorePoint(index: $0.offset, score: $0.element.score ?? 0) }
                    if pts.isEmpty {
                        Text("No scans yet.").foregroundStyle(.secondary).frame(height: 200)
                    } else {
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach(pts) { item in
                                HStack {
                                    Text("Scan \(item.index + 1)").font(.caption).frame(width: 58, alignment: .leading)
                                    ProgressView(value: Double(item.score), total: 100)
                                        .accentColor(Theme.scoreColor(item.score))
                                    Text("\(item.score)").font(.caption.monospacedDigit()).frame(width: 30, alignment: .trailing)
                                }
                            }
                        }
                        .frame(height: 200)
                    }
                }
            }
            FindingsPanel(findings: state.recentFindings, title: "Latest findings")
        }
    }

    private var deviceDetail: String {
        let a = state.devices["android"]["devices"].array.count, i = state.devices["ios"]["devices"].array.count
        return "Android \(a) · iPhone \(i)"
    }
    private var lastScanText: String {
        guard let s = state.history.first?.started_at, let d = ISO8601DateFormatter().date(from: s) else { return "—" }
        return RelativeDateTimeFormatter().localizedString(for: d, relativeTo: Date())
    }
    private var intelDetail: String {
        let feeds = state.intelStats["feeds"].array
        let last = feeds.compactMap { $0["last_update"].string }.max() ?? "never"
        return "\(feeds.count) source(s) · updated \(last.prefix(10))"
    }
    private var perfValue: String {
        guard let t = state.lastBench["throughput_mib_s"].double, t > 0 else { return "—" }
        return String(format: "%.0f MiB/s", t)
    }
    private var perfDetail: String {
        guard let n = state.lastBench["files_scanned"].int, let ms = state.lastBench["duration_ms"].int else { return "measured on last file scan" }
        return "\(n) files in \(String(format: "%.1f", Double(ms) / 1000)) s · \(state.lastBench["threads"].int ?? 0) threads"
    }
}

struct ScorePoint: Identifiable {
    let index: Int
    let score: Int
    var id: Int { index }
}
