import SwiftUI
import AppKit

/// ARGENT AI — on-device anomaly results, evidence-grounded summary, optional LLM narrative.
@MainActor
struct AIView: View {
    @EnvironmentObject var state: AppState
    @AppStorage("ai.endpoint") private var endpoint = "http://127.0.0.1:8080"
    @AppStorage("ai.model") private var model = "local"
    @AppStorage("ai.cloudEnabled") private var cloudEnabled = false
    @AppStorage("ai.cloudEndpoint") private var cloudEndpoint = ""
    @State private var question = "Jelaskan temuan paling penting dan langkah yang harus saya lakukan."
    @State private var answer = ""
    @State private var useCloud = false

    var findings: [Finding] { state.recentFindings }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            PageHeader(section: .ai, subtitle: "Local-first AI: anomaly detection, correlation and evidence-grounded explanations")
            Panel(title: "How ARGENT AI is used", systemImage: "info.circle") {
                Text("• Detection is performed by signatures, heuristics, intelligence and an on-device Isolation-Forest anomaly model — never by an LLM alone.\n• Every statement below cites the finding IDs it is based on.\n• The narrative assistant runs on a LOCAL llama.cpp server by default. Cloud AI is off unless you enable it, and only finding titles/evidence are sent — never files, APKs or backups.")
                    .font(.callout).fixedSize(horizontal: false, vertical: true)
            }
            Panel(title: "Correlation across recent scans", systemImage: "point.3.connected.trianglepath.dotted") {
                let groups = Correlation.build(findings)
                if groups.isEmpty {
                    Text("No subject is flagged by two or more independent engines.").foregroundStyle(.secondary)
                }
                ForEach(groups.prefix(20)) { item in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(item.subject).font(.callout.bold().monospaced())
                        Text("Corroborated by \(item.engines.joined(separator: ", ")) — " + item.findings.map { "[\($0.id)] \($0.title)" }.joined(separator: "; "))
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            Panel(title: "Ask ARGENT AI", systemImage: "bubble.left.and.text.bubble.right") {
                TextField("Question", text: $question).textFieldStyle(.roundedBorder)
                HStack {
                    Toggle("Use cloud AI (opt-in)", isOn: $useCloud).disabled(!cloudEnabled)
                    Spacer()
                    Text(useCloud ? "Endpoint: \(cloudEndpoint)" : "Endpoint: \(endpoint) (local)").font(.caption).foregroundStyle(.secondary)
                    Button("Explain") { Task { await ask() } }.buttonStyle(.borderedProminent).disabled(findings.isEmpty || state.isBusy("ai"))
                }
                if state.isBusy("ai") { BusyOverlay(text: "Generating explanation…") }
                if !answer.isEmpty {
                    Text(answer).textSelection(.enabled).padding(10).frame(maxWidth: .infinity, alignment: .leading)
                        .background(RoundedRectangle(cornerRadius: 8).fill(Theme.navy.opacity(0.08)))
                }
                if findings.isEmpty { Text("Run a scan first — the assistant only explains existing evidence.").font(.caption).foregroundStyle(.secondary) }
            }
        }
    }

    func ask() async {
        state.busy.insert("ai")
        defer { state.busy.remove("ai") }
        let cfg: AIAssistant.Config
        if useCloud && cloudEnabled, let u = URL(string: cloudEndpoint) {
            cfg = .init(endpoint: u, model: model, apiKey: Keychain.get("ai.cloud.key"), isCloud: true)
        } else if let u = URL(string: endpoint) {
            cfg = .init(endpoint: u, model: model, apiKey: nil, isCloud: false)
        } else { return }
        do { answer = try await AIAssistant.explain(findings: findings.actionable, question: question, config: cfg) }
        catch { state.errorMessage = error.localizedDescription }
    }
}

/// ARGENT REPORT — export any stored scan as signed PDF / HTML / JSON.
@MainActor
struct ReportsView: View {
    @EnvironmentObject var state: AppState
    @State private var selected: String?
    @State private var format: ReportExporter.Format = .pdf

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            PageHeader(section: .reports, subtitle: "Branded, evidence-based reports with hybrid post-quantum signatures (Ed25519 + ML-DSA-65)")
            Panel(title: "Export", systemImage: "square.and.arrow.up") {
                HStack {
                    Picker("Format", selection: $format) { ForEach(ReportExporter.Format.allCases) { Text($0.rawValue).tag($0) } }.pickerStyle(.segmented).frame(width: 260)
                    Toggle("Sign report (quantum-ready)", isOn: $state.signReports)
                    Spacer()
                    Button("Export selected…") {
                        guard let id = selected else { return }
                        Task {
                            do {
                                if let u = try await ReportExporter.export(scanID: id, format: format, sign: state.signReports, engine: state.engine) {
                                    state.notify("Report exported", u.lastPathComponent, .INFORMATIONAL)
                                    NSWorkspace.shared.activateFileViewerSelecting([u])
                                }
                            } catch { state.errorMessage = error.localizedDescription }
                        }
                    }.buttonStyle(.borderedProminent).disabled(selected == nil)
                }
                Text("Signed exports produce a .sig.json file next to the report. Verify with: argent-engine pqc verify --file <report> --sig <report>.sig.json --pubkey <public key>").font(.caption).foregroundStyle(.secondary)
            }
            Table(state.history, selection: $selected) {
                TableColumn("Started") { s in Text(s.started_at.replacingOccurrences(of: "T", with: " ").prefix(19)) }
                TableColumn("Type") { s in Text(s.kind.replacingOccurrences(of: "_", with: " ")) }
                TableColumn("Target") { s in Text(s.target).lineLimit(1).truncationMode(.middle) }
                TableColumn("Findings") { s in Text("\(s.findings)") }
                TableColumn("Score") { s in Text(s.score.map(String.init) ?? "—").foregroundStyle(Theme.scoreColor(s.score)) }
            }
            .frame(minHeight: 420)
        }
    }
}

@MainActor
struct HistoryView: View {
    @EnvironmentObject var state: AppState
    @State private var query = ""
    @State private var opened: JSON = .null

    var rows: [ScanSummary] {
        state.history.filter { query.isEmpty || $0.target.localizedCaseInsensitiveContains(query) || $0.kind.localizedCaseInsensitiveContains(query) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            PageHeader(section: .history, subtitle: "Every scan is stored locally with its findings, score and benchmark")
            HStack {
                TextField("Search history", text: $query).textFieldStyle(.roundedBorder)
                Button { Task { await state.refreshHistory() } } label: { Image(systemName: "arrow.clockwise") }
            }
            ForEach(rows) { s in
                HStack {
                    Text(s.started_at.replacingOccurrences(of: "T", with: " ").prefix(19)).font(.caption.monospaced()).frame(width: 150, alignment: .leading)
                    Text(s.kind.replacingOccurrences(of: "_", with: " ")).font(.callout.bold()).frame(width: 120, alignment: .leading)
                    Text(s.target).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    Text("\(s.findings) findings").font(.caption).foregroundStyle(.secondary)
                    Text(s.score.map(String.init) ?? "—").font(.callout.bold().monospacedDigit()).foregroundStyle(Theme.scoreColor(s.score)).frame(width: 40)
                    Button("Open") { Task { if let r = await state.run("open", ["scan-get", s.scan_id]) { opened = r } } }
                }
                Divider()
            }
            if !opened.isNull {
                let o = ScanOutcome(raw: opened["result"])
                OutcomeHeader(outcome: ScanOutcome(raw: mergeID(opened)))
                FindingsPanel(findings: o.findings)
            }
        }
    }

    func mergeID(_ j: JSON) -> JSON {
        var o = j["result"].object
        o["scan_id"] = j["scan_id"]
        return .object(o)
    }
}

/// Groups findings by subject and keeps those corroborated by ≥2 independent engines.
struct Correlation: Identifiable {
    let subject: String
    let engines: [String]
    let findings: [Finding]
    var id: String { subject }

    static func build(_ all: [Finding]) -> [Correlation] {
        let grouped = Dictionary(grouping: all.actionable.filter { $0.severity >= .LOW }, by: { $0.subject.name })
        return grouped.compactMap { key, value -> Correlation? in
            let engines = Array(Set(value.map(\.engine))).sorted()
            return engines.count >= 2 ? Correlation(subject: key, engines: engines, findings: value) : nil
        }
        .sorted { $0.findings.count > $1.findings.count }
    }
}
