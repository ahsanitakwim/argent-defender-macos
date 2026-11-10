import SwiftUI
import AppKit
import UniformTypeIdentifiers

/// ARGENT MALWARE ENGINE — single-file analysis (APK static analysis or any file).
@MainActor
struct MalwareAnalysisView: View {
    @EnvironmentObject var state: AppState
    @State private var dropTargeted = false

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            PageHeader(section: .malware, subtitle: "Signature (YARA-X), heuristic, static, certificate, hash-intelligence and Gaming Watch analysis of APK, IPA, DEX or any file")
            Panel(title: "Sample", systemImage: "doc.viewfinder") {
                VStack(spacing: 10) {
                    Image(systemName: "tray.and.arrow.down").font(.system(size: 34)).foregroundStyle(Theme.cyan)
                    Text("Drop an APK / IPA / file here, or choose one").foregroundStyle(.secondary)
                    Button("Choose file…") { if let u = FilePicker.pick() { Task { await analyse(u) } } }.buttonStyle(.borderedProminent)
                    if state.isBusy(NavSection.malware.rawValue) { BusyOverlay(text: "Analysing…") }
                }
                .frame(maxWidth: .infinity, minHeight: 150)
                .background(RoundedRectangle(cornerRadius: 12).strokeBorder(style: StrokeStyle(lineWidth: 1.5, dash: [6])).foregroundStyle(dropTargeted ? Theme.cyan : Theme.titanium.opacity(0.5)))
                .onDrop(of: [.fileURL], isTargeted: $dropTargeted) { providers in
                    guard let p = providers.first else { return false }
                    _ = p.loadObject(ofClass: URL.self) { url, _ in
                        if let url { Task { @MainActor in await analyse(url) } }
                    }
                    return true
                }
                Text("Files are analysed locally and are never uploaded. Use test samples only inside an isolated lab — never detonate live malware on a personal device.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if let o = state.lastOutcome[.malware] {
                OutcomeHeader(outcome: o)
                if !o.raw["apk"].isNull { apkPanel(o.raw) }
                FindingsPanel(findings: o.findings)
                EngineOutputView(json: o.raw["apk"].isNull ? o.raw["bench"] : o.raw["apk"])
            }
        }
    }

    func analyse(_ url: URL) async {
        if url.pathExtension.lowercased() == "apk" {
            await state.runScan(.malware, ["apk", url.path], title: "APK analysed: \(url.lastPathComponent)")
        } else {
            await state.runScan(.malware, ["scan", url.path, "--mode", "deep"], title: "File analysed: \(url.lastPathComponent)")
        }
    }

    func apkPanel(_ r: JSON) -> some View {
        let a = r["apk"], m = a["manifest"], s = a["signing"]
        return Panel(title: "APK identity", systemImage: "shippingbox") {
            Grid(alignment: .leading, horizontalSpacing: 24, verticalSpacing: 4) {
                GridRow { Text("Package").foregroundStyle(.secondary); Text(m["package"].string ?? "").font(.body.monospaced()).textSelection(.enabled) }
                GridRow { Text("Version").foregroundStyle(.secondary); Text("\(m["version_name"].string ?? "?") (code \(m["version_code"].string ?? "?")) · minSdk \(m["min_sdk"].string ?? "?") · targetSdk \(m["target_sdk"].string ?? "?")") }
                GridRow { Text("SHA-256").foregroundStyle(.secondary); Text(a["hashes"]["sha256"].string ?? "").font(.caption.monospaced()).textSelection(.enabled) }
                GridRow { Text("Signature schemes").foregroundStyle(.secondary); Text("v1 \(yn(s["v1_jar_signature"])) · v2 \(yn(s["v2"])) · v3 \(yn(s["v3"])) · v3.1 \(yn(s["v31"]))") }
                GridRow { Text("Certificate SHA-256").foregroundStyle(.secondary); Text(s["certificates_sha256"].array.compactMap(\.string).joined(separator: "\n")).font(.caption.monospaced()).textSelection(.enabled) }
                GridRow { Text("Cryptographic verification").foregroundStyle(.secondary); Text(s["apksigner_verified"].isNull ? "apksigner not installed (Android SDK build-tools) — structure only" : (s["apksigner_verified"].bool == true ? "VERIFIED by apksigner" : "FAILED apksigner verification")) }
                GridRow { Text("Contents").foregroundStyle(.secondary); Text("\(a["dex_files"].array.count) DEX · \(a["native_libs"].array.count) native libs · \(m["components"].array.count) components · \(m["permissions"].array.count) permissions") }
            }
        }
    }
    func yn(_ j: JSON) -> String { j.bool == true ? "✓" : "–" }
}

/// ARGENT GAMING WATCH — Indonesia gambling threat intelligence + admin.
@MainActor
struct GamingWatchView: View {
    @EnvironmentObject var state: AppState
    @State private var query = ""
    @State private var result: JSON = .null
    @State private var indicators: [JSON] = []
    @State private var filter = ""
    @State private var showAdd = false

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            PageHeader(section: .gaming, subtitle: "INDONESIA GAMBLING THREAT INTELLIGENCE — domains, URLs, packages, APK hashes, mirrors")
            Panel(title: "Check indicator", systemImage: "magnifyingglass") {
                HStack {
                    TextField("Domain, URL, package name or APK SHA-256", text: $query).textFieldStyle(.roundedBorder).onSubmit { Task { await check() } }
                    Button("Check") { Task { await check() } }.buttonStyle(.borderedProminent).disabled(query.isEmpty)
                }
                if !result.isNull {
                    let cls = result["classification"].string ?? "UNKNOWN"
                    HStack {
                        Text(cls.replacingOccurrences(of: "_", with: " ")).font(.title3.bold()).foregroundStyle(color(cls))
                        Spacer()
                    }
                    ForEach((result["findings"].decode([Finding].self) ?? []), id: \.uniqueKey) { FindingRow(finding: $0) }
                }
                Text("Classifications: CONFIRMED INDICATOR (verified database match) · HIGH RISK · SUSPECTED (heuristic) · UNKNOWN (not examinable) · NO KNOWN INDICATOR. Ordinary games are never classified as gambling without evidence.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Panel(title: "Indicator database (\(indicators.count))", systemImage: "cylinder.split.1x2") {
                HStack {
                    TextField("Filter", text: $filter).textFieldStyle(.roundedBorder).onSubmit { Task { await load() } }
                    Button("Add indicator…") { showAdd = true }
                    Button("Import CSV…") {
                        guard let u = FilePicker.pick(types: [.commaSeparatedText, .plainText]) else { return }
                        Task { if let r = await state.run("judol", ["judol", "import", "--file", u.path]) { state.notify("Gaming Watch import", "\(r["imported"].int ?? 0) indicators", .INFORMATIONAL); await load() } }
                    }
                }
                Text("CSV columns: domain,url,package_name,apk_hash,brand_alias,indicator_type,classification,evidence,source,confidence").font(.caption2.monospaced()).foregroundStyle(.secondary)
                if indicators.isEmpty {
                    Text("The database ships empty: ARGENT DEFENDER does not invent indicators. Import verified lists (e.g. government blocking lists you are entitled to use, threat-intel feeds, your own investigations).").font(.callout).foregroundStyle(.secondary)
                }
                ForEach(indicators, id: \.self) { i in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(i["domain"].string ?? i["package_name"].string ?? i["url"].string ?? i["apk_hash"].string ?? "").font(.callout.monospaced()).textSelection(.enabled)
                            Text("\(i["indicator_id"].string ?? "") · \(i["brand_alias"].string ?? "") · \(i["source"].string ?? "") · conf \(i["confidence"].int ?? 0)%").font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text((i["classification"].string ?? "").replacingOccurrences(of: "_", with: " ")).font(.caption.bold()).foregroundStyle(color(i["classification"].string ?? ""))
                        if i["verified"].bool == true {
                            Label("Verified", systemImage: "checkmark.seal.fill").font(.caption).foregroundStyle(Theme.secure)
                        } else {
                            Button("Verify") { Task { await state.run("judol", ["judol", "verify", "--id", i["indicator_id"].string ?? "", "--analyst", state.analystName]); await load() } }
                        }
                        Button(role: .destructive) { Task { await state.run("judol", ["judol", "delete", "--id", i["indicator_id"].string ?? "", "--analyst", state.analystName]); await load() } } label: { Image(systemName: "trash") }
                    }
                    Divider()
                }
            }
        }
        .task { await load() }
        .sheet(isPresented: $showAdd) { AddIndicatorSheet { await load() } }
    }

    func color(_ c: String) -> Color {
        switch c { case "CONFIRMED_INDICATOR": return Theme.critical; case "HIGH_RISK": return Theme.amber; case "SUSPECTED": return Theme.electric; case "NO_KNOWN_INDICATOR": return Theme.secure; default: return .secondary }
    }
    func check() async { if let r = await state.run("judolcheck", ["judol", "check", query.trimmingCharacters(in: .whitespaces)]) { result = r } }
    func load() async {
        var args = ["judol", "list"]
        if !filter.isEmpty { args += ["--q", filter] }
        if let r = await state.run("judollist", args) { indicators = r.array }
    }
}

@MainActor
struct AddIndicatorSheet: View {
    @EnvironmentObject var state: AppState
    @Environment(\.dismiss) private var dismiss
    var onSaved: () async -> Void
    @State private var type = "domain"
    @State private var value = ""
    @State private var brand = ""
    @State private var classification = "SUSPECTED"
    @State private var evidence = ""
    @State private var source = ""
    @State private var confidence = 60.0

    var body: some View {
        Form {
            Picker("Type", selection: $type) { ForEach(["domain", "url", "package", "apk_hash", "brand"], id: \.self) { Text($0) } }
            TextField("Value", text: $value)
            TextField("Brand / alias", text: $brand)
            Picker("Classification", selection: $classification) {
                Text("CONFIRMED INDICATOR").tag("CONFIRMED_INDICATOR"); Text("HIGH RISK").tag("HIGH_RISK"); Text("SUSPECTED").tag("SUSPECTED")
            }
            TextField("Evidence (required for CONFIRMED)", text: $evidence, axis: .vertical).lineLimit(2...5)
            TextField("Source (e.g. official list reference, report URL)", text: $source)
            Slider(value: $confidence, in: 0...100, step: 5) { Text("Confidence \(Int(confidence))%") }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Save") { Task { await save() } }.keyboardShortcut(.defaultAction)
                    .disabled(value.isEmpty || source.isEmpty || (classification == "CONFIRMED_INDICATOR" && evidence.isEmpty))
            }
        }
        .padding(20).frame(width: 520)
    }

    func save() async {
        let v = value.trimmingCharacters(in: .whitespaces)
        let obj: [String: JSON] = [
            "indicator_id": .string(""),
            "domain": type == "domain" ? .string(v.lowercased()) : .null,
            "url": type == "url" ? .string(v) : .null,
            "package_name": type == "package" ? .string(v) : .null,
            "apk_hash": type == "apk_hash" ? .string(v.lowercased()) : .null,
            "brand_alias": brand.isEmpty ? (type == "brand" ? .string(v) : .null) : .string(brand),
            "indicator_type": .string(type),
            "classification": .string(classification),
            "evidence": evidence.isEmpty ? .null : .string(evidence),
            "source": .string(source),
            "confidence": .number(confidence),
            "verified": .bool(false),
            "verified_by": .null, "verification_date": .null, "last_updated": .null,
        ]
        let json = String(decoding: (try? JSONEncoder().encode(JSON.object(obj))) ?? Data(), as: UTF8.self)
        if await state.run("judoladd", ["judol", "add"], stdin: json) != nil {
            await onSaved()
            dismiss()
        }
    }
}

/// ARGENT NETWORK — URL/domain reputation, phishing, typosquatting, homographs, redirects.
@MainActor
struct NetworkSecurityView: View {
    @EnvironmentObject var state: AppState
    @State private var input = ""
    @State private var follow = false

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            PageHeader(section: .network, subtitle: "Domain & URL reputation, phishing, typosquatting, IDN homographs, C2 indicators, redirects")
            Panel(title: "Analyse URLs / domains", systemImage: "link") {
                TextEditor(text: $input).font(.body.monospaced()).frame(height: 90)
                    .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(Theme.titanium.opacity(0.4)))
                Text("One per line. Paste suspicious links from SMS, WhatsApp, e-mail or QR codes.").font(.caption).foregroundStyle(.secondary)
                Toggle("Trace redirects online (contacts the site — use only when you accept that)", isOn: $follow)
                HStack {
                    Button("Analyse") { Task { await analyse() } }.buttonStyle(.borderedProminent).disabled(input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    if state.isBusy(NavSection.network.rawValue) { BusyOverlay(text: "Analysing…") }
                }
            }
            if let o = state.lastOutcome[.network] {
                OutcomeHeader(outcome: o)
                Panel(title: "Verdicts", systemImage: "list.bullet.rectangle") {
                    ForEach(o.raw["results"].array, id: \.self) { r in
                        HStack {
                            Text(r["verdict"].string?.replacingOccurrences(of: "_", with: " ") ?? "").font(.caption.bold()).frame(width: 160, alignment: .leading)
                                .foregroundStyle(verdictColor(r["verdict"].string ?? ""))
                            VStack(alignment: .leading) {
                                Text(r["url"].string ?? "").font(.callout.monospaced()).textSelection(.enabled)
                                if let u = r["unicode_host"].string { Text("renders as: \(u)").font(.caption).foregroundStyle(Theme.amber) }
                                if !r["redirects"].array.isEmpty { Text(r["redirects"].array.compactMap(\.string).joined(separator: " → ")).font(.caption2).foregroundStyle(.secondary) }
                            }
                            Spacer()
                            Text("risk \(r["score"].int ?? 0)").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                        }
                    }
                }
                FindingsPanel(findings: o.findings)
            }
            Panel(title: "Traffic capture (authorised)", systemImage: "waveform.path.ecg") {
                Text("For live network evidence, capture traffic with PCAPdroid on the Android device (user-consented VPN, no root) or Wireshark/Zeek on a network you control, then add the PCAP as evidence in Digital Forensics. ARGENT DEFENDER never intercepts traffic silently.")
                    .font(.callout).fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    func verdictColor(_ v: String) -> Color {
        switch v { case "MALICIOUS": return Theme.critical; case "HIGH_RISK": return Theme.amber; case "SUSPICIOUS": return Theme.electric; default: return Theme.secure }
    }

    func analyse() async {
        let urls = input.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        await state.runScan(.network, ["url"] + urls + (follow ? ["--follow-redirects"] : []), title: "URL analysis finished")
    }
}
