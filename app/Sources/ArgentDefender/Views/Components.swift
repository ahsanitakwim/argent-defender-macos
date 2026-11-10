import SwiftUI
import AppKit
import UniformTypeIdentifiers

@MainActor
struct PageHeader: View {
    let section: NavSection
    var subtitle: String
    var body: some View {
        HStack(alignment: .center, spacing: 14) {
            Image(systemName: section.icon)
                .font(.system(size: 22, weight: .semibold))
                .foregroundStyle(Theme.cyan)
                .frame(width: 44, height: 44)
                .background(RoundedRectangle(cornerRadius: 10).fill(Theme.navy))
            VStack(alignment: .leading, spacing: 2) {
                Text(section.rawValue.uppercased()).font(.system(size: 20, weight: .bold)).tracking(1.5)
                Text(subtitle).font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
        }
    }
}

@MainActor
struct MetricCard: View {
    let title: String
    let value: String
    var detail: String = ""
    var icon: String
    var tint: Color = Theme.electric
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Image(systemName: icon).foregroundStyle(tint)
                Text(title.uppercased()).font(.system(size: 10, weight: .semibold)).tracking(1).foregroundStyle(.secondary)
            }
            Text(value).font(.system(size: 28, weight: .bold, design: .rounded)).foregroundStyle(tint).lineLimit(1).minimumScaleFactor(0.5)
            if !detail.isEmpty { Text(detail).font(.caption).foregroundStyle(.secondary).lineLimit(2) }
        }
        .padding(14)
        .frame(maxWidth: .infinity, minHeight: 104, alignment: .topLeading)
        .background(RoundedRectangle(cornerRadius: 14).fill(Theme.panelBackground))
        .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(tint.opacity(0.25)))
    }
}

@MainActor
struct SeverityBadge: View {
    let severity: Severity
    var body: some View {
        Text(severity.label.uppercased())
            .font(.system(size: 9, weight: .bold)).tracking(0.6)
            .padding(.horizontal, 7).padding(.vertical, 3)
            .background(Capsule().fill(severity.color))
            .foregroundStyle(.white)
    }
}

@MainActor
struct ConfidenceBadge: View {
    let confidence: Confidence
    var body: some View {
        Text("CONF \(confidence.rawValue)")
            .font(.system(size: 9, weight: .semibold, design: .monospaced))
            .padding(.horizontal, 6).padding(.vertical, 3)
            .overlay(Capsule().strokeBorder(Theme.titanium.opacity(0.6)))
            .foregroundStyle(.secondary)
    }
}

@MainActor
struct ScoreRing: View {
    let score: Int?
    var size: CGFloat = 120
    var body: some View {
        ZStack {
            Circle().stroke(Theme.titanium.opacity(0.2), lineWidth: 10)
            Circle()
                .trim(from: 0, to: CGFloat(score ?? 0) / 100)
                .stroke(Theme.scoreColor(score), style: StrokeStyle(lineWidth: 10, lineCap: .round))
                .rotationEffect(.degrees(-90))
            VStack(spacing: 0) {
                Text(score.map(String.init) ?? "—").font(.system(size: size * 0.3, weight: .bold, design: .rounded))
                Text("SECURITY").font(.system(size: 9, weight: .semibold)).tracking(1.5).foregroundStyle(.secondary)
            }
        }
        .frame(width: size, height: size)
    }
}

@MainActor
struct FindingRow: View {
    let finding: Finding
    @State private var expanded = false
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                SeverityBadge(severity: finding.severity)
                ConfidenceBadge(confidence: finding.confidence)
                Text(finding.title).font(.system(size: 13, weight: .semibold))
                Spacer()
                Text(finding.subject.name).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle).frame(maxWidth: 260, alignment: .trailing)
                Image(systemName: expanded ? "chevron.up" : "chevron.down").foregroundStyle(.secondary)
            }
            .contentShape(Rectangle())
            .onTapGesture { withAnimation(.easeOut(duration: 0.15)) { expanded.toggle() } }
            if expanded {
                VStack(alignment: .leading, spacing: 4) {
                    Text("\(finding.engine) · \(finding.rule) · \(finding.category) · ID \(finding.id)")
                        .font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary).textSelection(.enabled)
                    ForEach(finding.evidence.filter { !$0.isEmpty }, id: \.self) { e in
                        Label(e, systemImage: "doc.text.magnifyingglass").font(.callout).textSelection(.enabled)
                    }
                    if let p = finding.subject.path { Text(p).font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled) }
                    if let h = finding.subject.sha256 { Text("SHA-256 \(h)").font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled) }
                    if !finding.recommendation.isEmpty {
                        Label(finding.recommendation, systemImage: "arrow.turn.down.right").font(.callout).foregroundStyle(Theme.electric)
                    }
                }
                .padding(.leading, 4)
            }
        }
        .padding(.vertical, 6)
    }
}

/// Searchable, filterable list of findings with a separate "limitations" box.
@MainActor
struct FindingsPanel: View {
    let findings: [Finding]
    var title = "Findings"
    @State private var query = ""
    @State private var minSeverity: Severity = .INFORMATIONAL

    var filtered: [Finding] {
        findings.actionable
            .filter { $0.severity >= minSeverity }
            .filter { query.isEmpty || $0.title.localizedCaseInsensitiveContains(query) || $0.subject.name.localizedCaseInsensitiveContains(query) || $0.rule.localizedCaseInsensitiveContains(query) }
            .sorted { ($0.severity, $0.confidence.rawValue) > ($1.severity, $1.confidence.rawValue) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Panel(title: "\(title) (\(filtered.count))", systemImage: "exclamationmark.shield") {
                HStack {
                    TextField("Search findings, packages, rules…", text: $query).textFieldStyle(.roundedBorder)
                    Picker("Minimum severity", selection: $minSeverity) {
                        ForEach(Severity.allCases.filter { $0 != .NOT_ACCESSIBLE }, id: \.self) { Text($0.label).tag($0) }
                    }.frame(width: 220)
                }
                if filtered.isEmpty {
                    Label(findings.actionable.isEmpty ? "No findings produced by the available checks." : "No findings match the filter.", systemImage: "checkmark.shield")
                        .foregroundStyle(Theme.secure).padding(.vertical, 6)
                } else {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(filtered, id: \.uniqueKey) { f in
                            FindingRow(finding: f)
                            Divider()
                        }
                    }
                }
            }
            if !findings.limitations.isEmpty {
                Panel(title: "Transparency — not examined", systemImage: "eye.slash") {
                    ForEach(findings.limitations, id: \.uniqueKey) { l in
                        Label(l.title, systemImage: "info.circle").font(.callout).foregroundStyle(.secondary)
                    }
                }
            }
        }
    }
}

@MainActor
struct OutcomeHeader: View {
    let outcome: ScanOutcome
    @EnvironmentObject var state: AppState
    @State private var exporting = false
    var body: some View {
        Panel(title: "Result", systemImage: "checkmark.seal") {
            HStack(spacing: 24) {
                ScoreRing(score: outcome.risk?.score, size: 96)
                VStack(alignment: .leading, spacing: 6) {
                    Text(outcome.risk?.rating ?? "—").font(.title2.bold()).foregroundStyle(Theme.scoreColor(outcome.risk?.score))
                    if let g = outcome.gambling { Text("Gaming Watch: \(g.replacingOccurrences(of: "_", with: " "))").font(.callout) }
                    Text(outcome.risk?.by_severity.sorted { $0.key < $1.key }.map { "\($0.key) \($0.value)" }.joined(separator: " · ") ?? "")
                        .font(.caption).foregroundStyle(.secondary)
                    if let id = outcome.scanID { Text(id).font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled) }
                }
                Spacer()
                if let id = outcome.scanID {
                    Menu {
                        ForEach(ReportExporter.Format.allCases) { fmt in
                            Button("Export \(fmt.rawValue)…") {
                                Task {
                                    do {
                                        if let url = try await ReportExporter.export(scanID: id, format: fmt, sign: state.signReports, engine: state.engine) {
                                            NSWorkspace.shared.activateFileViewerSelecting([url])
                                        }
                                    } catch { state.errorMessage = error.localizedDescription }
                                }
                            }
                        }
                    } label: { Label("Export Report", systemImage: "square.and.arrow.up") }
                    .menuStyle(.button).frame(width: 170)
                }
            }
        }
    }
}

@MainActor
struct BusyOverlay: View {
    let text: String
    var body: some View {
        HStack(spacing: 10) {
            ProgressView().controlSize(.small)
            Text(text).font(.callout)
        }
        .padding(10)
        .background(Capsule().fill(.ultraThinMaterial))
    }
}

/// Explicit owner-consent gate required before any device is accessed.
@MainActor
struct ConsentSheet: View {
    let deviceLabel: String
    var onConfirm: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var owner = false
    @State private var informed = false
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Device examination consent", systemImage: "hand.raised.fill").font(.title3.bold())
            Text("ARGENT DEFENDER will read information from \(deviceLabel) using only mechanisms authorised by the operating system. No root/jailbreak, no protection bypass, no configuration changes and nothing is uploaded.")
                .fixedSize(horizontal: false, vertical: true)
            Toggle("I am the owner of this device, or I have the owner's explicit permission / lawful authority.", isOn: $owner)
            Toggle("The person using this device knows it is being examined.", isOn: $informed)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Start examination") { dismiss(); onConfirm() }
                    .keyboardShortcut(.defaultAction).disabled(!(owner && informed))
            }
        }
        .padding(24).frame(width: 520)
    }
}

enum FilePicker {
    @MainActor
    static func pick(files: Bool = true, directories: Bool = false, types: [UTType] = []) -> URL? {
        let p = NSOpenPanel()
        p.canChooseFiles = files
        p.canChooseDirectories = directories
        p.allowsMultipleSelection = false
        if !types.isEmpty { p.allowedContentTypes = types }
        return p.runModal() == .OK ? p.url : nil
    }
}

@MainActor
struct EngineOutputView: View {
    let json: JSON
    var body: some View {
        DisclosureGroup("Technical details (JSON)") {
            ScrollView(.horizontal) {
                Text(json.pretty).font(.system(size: 11, design: .monospaced)).textSelection(.enabled).padding(8)
            }.frame(maxHeight: 320)
        }
    }
}
