import SwiftUI
import AppKit
import UniformTypeIdentifiers

/// ARGENT FORENSIC — cases, evidence integrity, chain of custody, notes, timeline.
@MainActor
struct ForensicsView: View {
    @EnvironmentObject var state: AppState
    @State private var cases: [JSON] = []
    @State private var selected = ""
    @State private var detail: JSON = .null
    @State private var timeline: [JSON] = []
    @State private var newTitle = ""
    @State private var note = ""
    @State private var device = ""
    @State private var method = "logical_copy"

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            PageHeader(section: .forensics, subtitle: "Evidence integrity · chain of custody · SHA-256 verification · read-only working copies · audit logging")
            Panel(title: "Cases", systemImage: "folder.badge.person.crop") {
                HStack {
                    TextField("New case title", text: $newTitle).textFieldStyle(.roundedBorder)
                    Button("Create case") {
                        Task {
                            if let r = await state.run("case", ["case", "create", "--title", newTitle, "--examiner", state.analystName]) {
                                newTitle = ""; await load(); selected = r["case_id"].string ?? ""; await open()
                            }
                        }
                    }.disabled(newTitle.isEmpty)
                }
                Picker("Open case", selection: $selected) {
                    Text("Select…").tag("")
                    ForEach(cases, id: \.self) { c in Text("\(c["case_id"].string ?? "") — \(c["title"].string ?? "") (\(c["evidence_count"].int ?? 0) items)").tag(c["case_id"].string ?? "") }
                }
                .onChange(of: selected) { _ in Task { await open() } }
            }
            if !selected.isEmpty && !detail.isNull {
                Panel(title: "Acquire evidence", systemImage: "tray.and.arrow.down") {
                    HStack {
                        TextField("Source device (e.g. model / serial)", text: $device).textFieldStyle(.roundedBorder)
                        Picker("Method", selection: $method) {
                            Text("Logical copy").tag("logical_copy"); Text("iPhone backup (idevicebackup2/Finder)").tag("ios_backup")
                            Text("ADB pull (user APKs)").tag("adb_pull"); Text("PCAP capture").tag("pcap"); Text("Received file").tag("received_file")
                        }.frame(width: 300)
                        Button("Add file or folder…") {
                            guard let u = FilePicker.pick(files: true, directories: true) else { return }
                            Task {
                                var args = ["evidence", "add", "--case", selected, "--path", u.path, "--method", method, "--examiner", state.analystName]
                                if !device.isEmpty { args += ["--device", device] }
                                if let r = await state.run("evidence", args) { state.notify("Evidence acquired", "\(r["evidence_id"].string ?? "") SHA-256 \(r["sha256"].string?.prefix(16) ?? "")…", .INFORMATIONAL) }
                                await open()
                            }
                        }.buttonStyle(.borderedProminent)
                    }
                    Text("The original is hashed, copied to a read-only working copy, re-hashed and compared. The original is never modified.").font(.caption).foregroundStyle(.secondary)
                }
                Panel(title: "Evidence", systemImage: "archivebox") {
                    ForEach(detail["evidence"].array, id: \.self) { e in
                        let id = e["evidence_id"].string ?? ""
                        HStack(alignment: .top) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(id).font(.callout.bold().monospaced())
                                Text("\(e["acquisition_method"].string ?? "") · \(e["source_device"].string ?? "—") · \(e["acquired_at"].string ?? "")").font(.caption).foregroundStyle(.secondary)
                                Text("SHA-256 \(e["sha256"].string ?? "")").font(.caption2.monospaced()).textSelection(.enabled)
                                Text("\(e["item_count"].int ?? 0) item(s) · \(ByteCountFormatter.string(fromByteCount: Int64(e["size"].double ?? 0), countStyle: .file)) · \(e["original_path"].string ?? "")").font(.caption2).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("Verify integrity") {
                                Task {
                                    if let r = await state.run("verify", ["evidence", "verify", "--id", id, "--examiner", state.analystName]) {
                                        let ok = r["working_copy_intact"].bool == true && r["custody_chain"]["intact"].bool == true
                                        state.notify(ok ? "Evidence intact" : "INTEGRITY FAILURE", id, ok ? .INFORMATIONAL : .CRITICAL)
                                        if !ok { state.errorMessage = "Integrity check failed for \(id): \(r.pretty)" }
                                    }
                                    await open()
                                }
                            }
                            Button("Analyse") {
                                Task { await state.runScan(.forensics, ["evidence", "analyze", "--id", id, "--examiner", state.analystName], title: "Evidence \(id) analysed"); await open() }
                            }.buttonStyle(.borderedProminent)
                        }
                        Divider()
                    }
                }
                if let o = state.lastOutcome[.forensics] {
                    OutcomeHeader(outcome: o)
                    FindingsPanel(findings: o.findings)
                }
                Panel(title: "Investigation notes", systemImage: "note.text") {
                    ForEach(detail["notes"].array, id: \.self) { n in
                        VStack(alignment: .leading) {
                            Text("\(n["at"].string ?? "") · \(n["author"].string ?? "")\(n["evidence_id"].string.map { " · \($0)" } ?? "")").font(.caption).foregroundStyle(.secondary)
                            Text(n["body"].string ?? "").textSelection(.enabled)
                        }
                    }
                    HStack {
                        TextField("Add note…", text: $note, axis: .vertical).textFieldStyle(.roundedBorder)
                        Button("Add") { Task { await state.run("note", ["case", "note", "--case", selected, "--author", state.analystName, "--body", note]); note = ""; await open() } }.disabled(note.isEmpty)
                    }
                }
                Panel(title: "Chain of custody (hash-chained)", systemImage: "link") {
                    ForEach(detail["custody"].array, id: \.self) { l in
                        HStack(alignment: .top) {
                            Text("#\(l["seq"].int ?? 0)").font(.caption.monospaced()).frame(width: 40, alignment: .leading)
                            Text(l["at"].string ?? "").font(.caption.monospaced()).frame(width: 170, alignment: .leading)
                            Text("\(l["evidence_id"].string ?? "") \(l["action"].string ?? "") by \(l["actor"].string ?? "")").font(.caption.bold())
                            Text(l["detail"].string ?? "").font(.caption).foregroundStyle(.secondary).lineLimit(2).textSelection(.enabled)
                            Spacer()
                            Text(l["entry_hash"].string?.prefix(12).description ?? "").font(.caption2.monospaced()).foregroundStyle(.secondary)
                        }
                    }
                }
                if !timeline.isEmpty { TimelinePanel(events: timeline) }
                HStack {
                    Button("Export case file (JSON)…") { exportCase() }
                    Spacer()
                }
            }
        }
        .task { await load() }
    }

    func load() async { if let r = await state.run("cases", ["case", "list"]) { cases = r.array } }
    func open() async {
        guard !selected.isEmpty else { detail = .null; return }
        if let r = await state.run("caseshow", ["case", "show", selected]) { detail = r }
        if let t = await state.run("timeline", ["case", "timeline", selected]) { timeline = t.array }
    }
    func exportCase() {
        let p = NSSavePanel()
        p.nameFieldStringValue = "\(selected).json"
        guard p.runModal() == .OK, let u = p.url else { return }
        try? Data(detail.pretty.utf8).write(to: u)
        state.notify("Case exported", u.lastPathComponent, .INFORMATIONAL)
    }
}

/// ARGENT INTEL — threat intelligence management.
@MainActor
struct ThreatIntelView: View {
    @EnvironmentObject var state: AppState
    @State private var lookup = ""
    @State private var lookupResult: JSON = .null
    @State private var importFormat = "list"
    @State private var importSource = ""
    @State private var importLicense = ""
    @State private var reliability = 70.0
    @State private var iocs: [JSON] = []
    @State private var iocFilter = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            PageHeader(section: .intel, subtitle: "Offline IOC database · URLhaus · ThreatFox · MalwareBazaar · STIX 2.1 / MVT · MISP event JSON")
            HStack(alignment: .top, spacing: 14) {
                MetricCard(title: "Indicators", value: "\(state.intelStats["total"].int ?? 0)", icon: "number", tint: Theme.cyan)
                ForEach(state.intelStats["by_type"].array.prefix(4), id: \.self) { t in
                    MetricCard(title: t[0].string ?? "", value: "\(t[1].int ?? 0)", icon: "tag", tint: Theme.electric)
                }
            }
            Panel(title: "Online updates (with integrity record)", systemImage: "arrow.down.circle") {
                HStack {
                    ForEach(["urlhaus", "threatfox", "bazaar"], id: \.self) { feed in
                        Button("Update \(feed)") {
                            Task {
                                let key = Keychain.get("abusech.authkey")
                                if let r = await state.run("update-\(feed)", ["intel", "update", "--feed", feed] + (key == nil ? [] : ["--auth-key-stdin"]), stdin: key) {
                                    state.notify("Intel updated: \(feed)", "\(r["records"].int ?? 0) records · sha256 \(r["payload_sha256"].string?.prefix(12) ?? "")", .INFORMATIONAL)
                                    await state.refreshIntel()
                                }
                            }
                        }.disabled(state.isBusy("update-\(feed)"))
                    }
                    if state.busy.contains(where: { $0.hasPrefix("update-") }) { BusyOverlay(text: "Downloading…") }
                }
                Text("abuse.ch may require a free Auth-Key — store it in Settings › Integrations (kept in the Keychain).").font(.caption).foregroundStyle(.secondary)
            }
            Panel(title: "Import dataset (offline)", systemImage: "square.and.arrow.down") {
                HStack {
                    Picker("Format", selection: $importFormat) {
                        Text("Plain list").tag("list"); Text("URLhaus CSV").tag("urlhaus"); Text("ThreatFox CSV").tag("threatfox")
                        Text("MalwareBazaar CSV").tag("bazaar"); Text("STIX 2.x (MVT)").tag("stix2"); Text("MISP event JSON").tag("misp")
                    }.frame(width: 260)
                    TextField("Source name", text: $importSource).frame(width: 160)
                    TextField("Licence", text: $importLicense).frame(width: 140)
                    Slider(value: $reliability, in: 0...100, step: 5) { Text("Reliability \(Int(reliability))") }.frame(width: 220)
                    Button("Choose file…") {
                        guard let u = FilePicker.pick() else { return }
                        Task {
                            var args = ["intel", "import", "--format", importFormat, "--file", u.path, "--source", importSource.isEmpty ? u.deletingPathExtension().lastPathComponent : importSource, "--reliability", "\(Int(reliability))"]
                            if !importLicense.isEmpty { args += ["--license", importLicense] }
                            if let r = await state.run("import", args) { state.notify("Imported \(r["records"].int ?? 0) indicators", r["source"].string ?? "", .INFORMATIONAL); await state.refreshIntel() }
                        }
                    }.buttonStyle(.borderedProminent)
                }
                Text("Tip: Amnesty International's mobile spyware indicators (Pegasus, Predator…) are published as STIX2 files for MVT — import them here to correlate iPhone backups.").font(.caption).foregroundStyle(.secondary)
            }
            Panel(title: "Lookup", systemImage: "magnifyingglass") {
                HStack {
                    TextField("Hash, domain, URL, IP, package or process name", text: $lookup).textFieldStyle(.roundedBorder).onSubmit { Task { await doLookup() } }
                    Button("Lookup") { Task { await doLookup() } }.disabled(lookup.isEmpty)
                }
                if !lookupResult.isNull {
                    Text("Detected type: \(lookupResult["type"].string ?? "")").font(.caption).foregroundStyle(.secondary)
                    if lookupResult["hits"].array.isEmpty { Text("No match in the local intelligence database.").foregroundStyle(Theme.secure) }
                    ForEach(lookupResult["hits"].array, id: \.self) { h in
                        Text("\(h["source"].string ?? "") · \(h["threat"].string ?? "?") · \(h["category"].string ?? "") · confidence \(h["confidence"].int ?? 0)% · source reliability \(h["reliability"].int ?? 0)%").font(.callout)
                    }
                }
            }
            Panel(title: "Sources & licences", systemImage: "checkmark.shield") {
                ForEach(state.intelStats["feeds"].array, id: \.self) { f in
                    HStack {
                        Text(f["source"].string ?? "").bold().frame(width: 140, alignment: .leading)
                        Text("\(f["records"].int ?? 0) rec").frame(width: 90, alignment: .leading)
                        Text("reliability \(f["reliability"].int ?? 0)").frame(width: 110, alignment: .leading)
                        Text(f["license"].string ?? "licence not recorded").foregroundStyle(.secondary)
                        Spacer()
                        Text("\(f["last_update"].string ?? "") · sha256 \(f["payload_sha256"].string?.prefix(12) ?? "")").font(.caption.monospaced()).foregroundStyle(.secondary)
                    }
                }
            }
            Panel(title: "Indicator administration", systemImage: "slider.horizontal.3") {
                HStack {
                    TextField("Filter", text: $iocFilter).textFieldStyle(.roundedBorder).onSubmit { Task { await loadIocs() } }
                    Button("Load") { Task { await loadIocs() } }
                }
                ForEach(iocs, id: \.self) { i in
                    HStack {
                        Text(i["type"].string ?? "").font(.caption.bold()).frame(width: 70, alignment: .leading)
                        Text(i["value"].string ?? "").font(.caption.monospaced()).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                        Spacer()
                        Text("\(i["threat"].string ?? "") · \(i["source"].string ?? "")").font(.caption).foregroundStyle(.secondary)
                        Button(role: .destructive) { Task { await state.run("iocdel", ["intel", "delete", "--id", "\(i["id"].int ?? -1)"]); await loadIocs(); await state.refreshIntel() } } label: { Image(systemName: "trash") }
                    }
                }
            }
        }
        .task { await state.refreshIntel() }
    }

    func doLookup() async { if let r = await state.run("lookup", ["intel", "lookup", lookup.trimmingCharacters(in: .whitespaces)]) { lookupResult = r } }
    func loadIocs() async {
        var a = ["intel", "list", "--limit", "300"]
        if !iocFilter.isEmpty { a += ["--q", iocFilter] }
        if let r = await state.run("ioclist", a) { iocs = r.array }
    }
}
