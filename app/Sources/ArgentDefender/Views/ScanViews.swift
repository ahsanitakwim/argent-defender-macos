import SwiftUI
import AppKit
import UniformTypeIdentifiers

/// Quick / Full / Deep / Custom / Incremental file scanning (ARGENT SCAN).
@MainActor
struct ScanView: View {
    enum Mode: String { case quick, full, deep }
    let mode: Mode
    @EnvironmentObject var state: AppState
    @State private var target: URL?
    @State private var incremental = false
    @State private var clamav = false
    @State private var customExt = ""

    var section: NavSection { mode == .quick ? .quickScan : mode == .full ? .fullScan : .deepScan }
    var description: String {
        switch mode {
        case .quick: return "High-risk file types only (APK, IPA, DEX, SO, scripts, archives, profiles), ≤64 MiB, archive descent 1 level."
        case .full: return "Every file ≤512 MiB, APK/IPA analysis, archive descent 1 level. Enable Incremental to skip unchanged files."
        case .deep: return "Every file ≤2 GiB, content-based APK detection, nested archives (2 levels). Optional ClamAV second engine."
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            PageHeader(section: section, subtitle: description)
            Panel(title: "Target", systemImage: "folder") {
                HStack {
                    Text(target?.path ?? "Choose a file or folder — e.g. pulled APKs, an iPhone backup folder, Downloads, or extracted evidence.")
                        .foregroundStyle(target == nil ? .secondary : .primary).lineLimit(2).truncationMode(.middle)
                    Spacer()
                    Button("Choose…") { target = FilePicker.pick(files: true, directories: true) }
                }
                HStack(spacing: 18) {
                    if mode != .deep { Toggle("Incremental (skip unchanged files)", isOn: $incremental) }
                    if mode != .quick {
                        Toggle("ClamAV second engine", isOn: $clamav)
                            .disabled(!toolInstalled("clamscan"))
                            .help(toolInstalled("clamscan") ? "Uses clamscan from Homebrew" : "Install with: brew install clamav")
                    }
                    if mode == .full {
                        TextField("Custom extensions (e.g. apk,dex,so)", text: $customExt).frame(width: 260)
                    }
                }
                HStack {
                    Button {
                        Task { await start() }
                    } label: { Label("Start \(mode.rawValue.capitalized) Scan", systemImage: "play.fill") }
                    .buttonStyle(.borderedProminent).disabled(target == nil || state.isBusy(section.rawValue))
                    if state.isBusy(section.rawValue) { BusyOverlay(text: "Scanning with YARA-X, hash intelligence and Gaming Watch…") }
                }
            }
            if let o = state.lastOutcome[section] {
                OutcomeHeader(outcome: o)
                BenchPanel(bench: o.raw["bench"])
                if !o.raw["rule_errors"].array.isEmpty {
                    Panel(title: "Rule files skipped", systemImage: "exclamationmark.triangle") {
                        ForEach(o.raw["rule_errors"].array, id: \.self) { Text($0.string ?? "").font(.caption.monospaced()) }
                    }
                }
                FindingsPanel(findings: o.findings)
            }
        }
    }

    func toolInstalled(_ n: String) -> Bool {
        state.env["tools"].array.first { $0["name"].string == n }.map { !$0["path"].isNull } ?? false
    }

    func start() async {
        guard let t = target else { return }
        var m = mode.rawValue
        var extra: [String] = []
        if incremental && mode != .deep { m = "incremental" }
        if mode == .full && !customExt.trimmingCharacters(in: .whitespaces).isEmpty { m = "custom"; extra += ["--ext", customExt.replacingOccurrences(of: " ", with: "")] }
        if clamav { extra.append("--clamav") }
        await state.runScan(section, ["scan", t.path, "--mode", m] + extra, title: "\(mode.rawValue.capitalized) scan finished")
    }
}

@MainActor
struct BenchPanel: View {
    let bench: JSON
    var body: some View {
        if !bench.isNull {
            Panel(title: "Performance benchmark (measured)", systemImage: "speedometer") {
                Grid(alignment: .leading, horizontalSpacing: 24, verticalSpacing: 4) {
                    GridRow { k("Files scanned"); v("\(bench["files_scanned"].int ?? 0) / \(bench["files_discovered"].int ?? 0)"); k("Cached (incremental)"); v("\(bench["files_skipped_cached"].int ?? 0)") }
                    GridRow { k("Applications inspected"); v("\(bench["applications_inspected"].int ?? 0)"); k("Archive entries"); v("\(bench["archive_entries_scanned"].int ?? 0)") }
                    GridRow { k("Data scanned"); v(ByteCountFormatter.string(fromByteCount: Int64(bench["bytes_scanned"].double ?? 0), countStyle: .file)); k("Duration"); v(String(format: "%.2f s", (bench["duration_ms"].double ?? 0) / 1000)) }
                    GridRow { k("Throughput"); v(String(format: "%.1f MiB/s", bench["throughput_mib_s"].double ?? 0)); k("Threads"); v("\(bench["threads"].int ?? 0)") }
                    GridRow { k("CPU utilisation"); v(String(format: "%.0f %%", bench["cpu_utilization_pct"].double ?? 0)); k("Peak RAM"); v(String(format: "%.1f MiB", bench["peak_rss_mib"].double ?? 0)) }
                    GridRow { k("Rules loaded"); v("\(bench["rules_loaded"].int ?? 0) (compiled in \(bench["rule_compile_ms"].int ?? 0) ms)"); k("Mode"); v(bench["mode"].string ?? "") }
                }
            }
        }
    }
    func k(_ s: String) -> some View { Text(s).foregroundStyle(.secondary) }
    func v(_ s: String) -> some View { Text(s).font(.body.monospacedDigit()) }
}

/// ARGENT ANDROID SCANNER — Standard (non-root ADB) & Advanced Forensic modes.
@MainActor
struct AndroidScannerView: View {
    @EnvironmentObject var state: AppState
    @State private var serial = ""
    @State private var advanced = false
    @State private var thirdPartyOnly = true
    @State private var consent = false
    @State private var appQuery = ""

    var devices: [JSON] { state.devices["android"]["devices"].array.filter { $0["state"].string == "device" } }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            PageHeader(section: .android, subtitle: "Application inventory, permission audit, accessibility/overlay/device-admin abuse, configuration & patch assessment over ADB")
            Panel(title: "Device & mode", systemImage: "candybarphone") {
                if devices.isEmpty {
                    Label("No authorised Android device. Connect via USB with USB debugging enabled, then press Refresh.", systemImage: "exclamationmark.triangle").foregroundStyle(Theme.amber)
                }
                Picker("Device", selection: $serial) {
                    Text("Select…").tag("")
                    ForEach(devices, id: \.self) { d in Text("\(d["model"].string ?? "Android") — \(d["serial"].string ?? "")").tag(d["serial"].string ?? "") }
                }.frame(maxWidth: 480)
                Picker("Mode", selection: $advanced) {
                    Text("Standard — USB/ADB, non-root, read-only").tag(false)
                    Text("Advanced Forensic — also copy user-installed APKs for static & signature analysis").tag(true)
                }.pickerStyle(.radioGroup)
                Toggle("User-installed apps only (faster)", isOn: $thirdPartyOnly)
                Text("ARGENT DEFENDER never roots the device or bypasses Android protections. Private app data and system partitions are reported as not accessible.")
                    .font(.caption).foregroundStyle(.secondary)
                HStack {
                    Button { consent = true } label: { Label("Start Android Scan", systemImage: "play.fill") }
                        .buttonStyle(.borderedProminent).disabled(serial.isEmpty || state.isBusy(NavSection.android.rawValue))
                    if state.isBusy(NavSection.android.rawValue) { BusyOverlay(text: "Inspecting packages over ADB… this can take a few minutes") }
                }
            }
            if let o = state.lastOutcome[.android] {
                OutcomeHeader(outcome: o)
                deviceInfo(o.raw["info"])
                anomalies(o.raw["anomalies"].array)
                FindingsPanel(findings: o.findings)
                appInventory(o.raw["apps"].array)
            }
        }
        .onAppear { if serial.isEmpty { serial = devices.first?["serial"].string ?? "" } }
        .sheet(isPresented: $consent) {
            ConsentSheet(deviceLabel: "Android device \(serial)") { Task { await run() } }
        }
    }

    func run() async {
        var args = ["android", "audit", "--serial", serial]
        if thirdPartyOnly { args.append("--third-party-only") }
        if advanced {
            let dir = state.engine.supportDirectory.appendingPathComponent("acquired/android/\(serial)/\(Int(Date().timeIntervalSince1970))")
            args += ["--pull-apks", dir.path]
        }
        await state.runScan(.android, args, title: "Android scan finished")
    }

    func deviceInfo(_ i: JSON) -> some View {
        Panel(title: "Device", systemImage: "info.circle") {
            Grid(alignment: .leading, horizontalSpacing: 24, verticalSpacing: 4) {
                GridRow { Text("Manufacturer / model").foregroundStyle(.secondary); Text("\(i["manufacturer"].string ?? "") \(i["model"].string ?? "")") }
                GridRow { Text("Android").foregroundStyle(.secondary); Text("\(i["android_version"].string ?? "?") (SDK \(i["sdk"].string ?? "?"))") }
                GridRow { Text("Security patch").foregroundStyle(.secondary); Text(i["security_patch"].string ?? "unknown") }
                GridRow { Text("Verified boot / bootloader").foregroundStyle(.secondary); Text("\(i["verified_boot_state"].string ?? "?") / locked=\(i["bootloader_locked"].string ?? "?")") }
                GridRow { Text("Encryption").foregroundStyle(.secondary); Text(i["encryption_state"].string ?? "?") }
            }
        }
    }

    @ViewBuilder func anomalies(_ a: [JSON]) -> some View {
        let flagged = a.filter { $0["anomalous"].bool == true }
        if !a.isEmpty {
            Panel(title: "ARGENT AI — anomaly detection (Isolation Forest, on-device)", systemImage: "brain") {
                if flagged.isEmpty { Text("No statistically anomalous app profiles among \(a.count) user apps.").foregroundStyle(.secondary) }
                ForEach(flagged, id: \.self) { x in
                    HStack {
                        Text(x["package"].string ?? "").font(.callout.monospaced())
                        Spacer()
                        Text(x["drivers"].array.map { "\($0[0].string ?? "") z=\(String(format: "%.1f", $0[1].double ?? 0))" }.joined(separator: ", ")).font(.caption).foregroundStyle(.secondary)
                        Text(String(format: "%.3f", x["score"].double ?? 0)).font(.callout.monospacedDigit()).foregroundStyle(Theme.amber)
                    }
                }
            }
        }
    }

    func appInventory(_ apps: [JSON]) -> some View {
        Panel(title: "Application inventory (\(apps.count))", systemImage: "square.grid.3x3") {
            TextField("Filter packages…", text: $appQuery).textFieldStyle(.roundedBorder)
            let shown = apps.filter { appQuery.isEmpty || ($0["package"].string ?? "").localizedCaseInsensitiveContains(appQuery) }
            ForEach(shown.prefix(400), id: \.self) { a in
                HStack {
                    Image(systemName: a["system_app"].bool == true ? "gearshape" : "app").foregroundStyle(.secondary)
                    Text(a["package"].string ?? "").font(.callout.monospaced()).textSelection(.enabled)
                    if a["accessibility_enabled"].bool == true { Text("ACCESSIBILITY").font(.caption2.bold()).foregroundStyle(Theme.amber) }
                    if a["device_admin_active"].bool == true { Text("DEVICE ADMIN").font(.caption2.bold()).foregroundStyle(Theme.amber) }
                    Spacer()
                    Text(a["version"].string ?? "").font(.caption).foregroundStyle(.secondary)
                    Text(a["installer"].string ?? "—").font(.caption).foregroundStyle(.secondary).frame(width: 200, alignment: .trailing)
                    Text("\(a["permissions"].array.count) perms").font(.caption).foregroundStyle(.secondary).frame(width: 70, alignment: .trailing)
                }
            }
        }
    }
}

/// ARGENT IPHONE SCANNER — Device Audit, Backup Forensics, Application (IPA) Analysis.
@MainActor
struct IPhoneScannerView: View {
    enum Mode: String, CaseIterable, Identifiable { case audit = "A. Device Audit", backup = "B. Backup Forensics", ipa = "C. Application Analysis"; var id: String { rawValue } }
    @EnvironmentObject var state: AppState
    @State private var mode: Mode = .backup
    @State private var udid = ""
    @State private var backups: [JSON] = []
    @State private var backupRootNote = ""
    @State private var selectedBackup = ""
    @State private var password = ""
    @State private var includeMessages = false
    @State private var consent = false
    @State private var pendingAction: (() async -> Void)?

    var devices: [JSON] { state.devices["ios"]["devices"].array }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            PageHeader(section: .iphone, subtitle: "Pairing-based audit, local / encrypted backup forensics and IPA analysis — within Apple's sandbox")
            Picker("", selection: $mode) { ForEach(Mode.allCases) { Text($0.rawValue).tag($0) } }.pickerStyle(.segmented).labelsHidden()
            Panel(title: "Limitations (always applies)", systemImage: "lock.shield") {
                Text("iOS isolates apps in sandboxes. Pairing and backups do NOT expose the full filesystem, every app, running processes or all network traffic. ARGENT DEFENDER never jailbreaks or bypasses the sandbox, and a backup without indicators does not prove the device is malware-free.")
                    .font(.callout).fixedSize(horizontal: false, vertical: true)
            }
            switch mode {
            case .audit: auditPanel
            case .backup: backupPanel
            case .ipa: ipaPanel
            }
            if let o = state.lastOutcome[.iphone] {
                OutcomeHeader(outcome: o)
                if !o.raw["summary"].isNull { backupSummary(o.raw) }
                FindingsPanel(findings: o.findings)
                if !o.raw["timeline"].array.isEmpty { TimelinePanel(events: o.raw["timeline"].array) }
            }
        }
        .task { await loadBackups() }
        .onAppear { if udid.isEmpty { udid = devices.first?["udid"].string ?? "" } }
        .sheet(isPresented: $consent) {
            ConsentSheet(deviceLabel: "this iPhone / backup") { if let a = pendingAction { Task { await a() } } }
        }
    }

    var auditPanel: some View {
        Panel(title: "iPhone Device Audit", systemImage: "iphone") {
            Picker("Device", selection: $udid) {
                Text("Select…").tag("")
                ForEach(devices, id: \.self) { d in Text("\(d["name"].string ?? "iPhone") — iOS \(d["ios_version"].string ?? "?")").tag(d["udid"].string ?? "") }
            }.frame(maxWidth: 480)
            HStack {
                Button("Run Device Audit") {
                    pendingAction = { await state.runScan(.iphone, ["ios", "audit", "--udid", udid, "--min-ios", "\(state.minIOSMajor)"], title: "iPhone audit finished") }
                    consent = true
                }.buttonStyle(.borderedProminent).disabled(udid.isEmpty)
                Button("Create Local Backup…") {
                    guard let dir = FilePicker.pick(files: false, directories: true) else { return }
                    pendingAction = {
                        if let r = await state.run("backup", ["ios", "backup-create", "--udid", udid, "--out", dir.path]) {
                            state.notify("Backup finished", r["path"].string ?? "", .INFORMATIONAL)
                            await loadBackups()
                        }
                    }
                    consent = true
                }.disabled(udid.isEmpty)
                if state.isBusy("backup") { BusyOverlay(text: "Creating backup — keep the iPhone unlocked and connected") }
            }
            Text("Backup guidance: for the most complete analysis enable ‘Encrypt local backup’ in Finder (keychain, Health and network-usage records are only included in encrypted backups). Remember the password — Apple cannot recover it.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    var backupPanel: some View {
        Panel(title: "iPhone Backup Forensics", systemImage: "externaldrive") {
            HStack {
                Picker("Backup", selection: $selectedBackup) {
                    Text("Select…").tag("")
                    ForEach(backups, id: \.self) { b in
                        Text("\(b["device_name"].string ?? "iPhone") · iOS \(b["ios_version"].string ?? "?") · \(b["last_backup"].string?.prefix(10).description ?? "") \(b["encrypted"].bool == true ? "🔒" : "")").tag(b["path"].string ?? "")
                    }
                }.frame(maxWidth: 560)
                Button("Other folder…") { if let u = FilePicker.pick(files: false, directories: true) { selectedBackup = u.path } }
                Button { Task { await loadBackups() } } label: { Image(systemName: "arrow.clockwise") }
            }
            if !backupRootNote.isEmpty { Text(backupRootNote).font(.caption).foregroundStyle(Theme.amber) }
            if isEncrypted {
                SecureField("Backup password (used once, never stored)", text: $password).frame(maxWidth: 360)
            }
            Toggle("Also analyse links found in SMS/iMessage (only URLs are kept; message text is never stored)", isOn: $includeMessages)
            HStack {
                Button("Analyse Backup") {
                    pendingAction = { await analyse() }
                    consent = true
                }.buttonStyle(.borderedProminent).disabled(selectedBackup.isEmpty || (isEncrypted && password.isEmpty) || state.isBusy(NavSection.iphone.rawValue))
                if state.isBusy(NavSection.iphone.rawValue) { BusyOverlay(text: "Decrypting & analysing (read-only)…") }
            }
        }
    }

    var ipaPanel: some View {
        Panel(title: "iPhone Application Analysis", systemImage: "app.badge") {
            Text("Analyse an IPA you obtained lawfully (e.g. your own build or an exported archive). YARA-X rules, hash & bundle-ID intelligence and Gaming Watch are applied.").font(.callout)
            Button("Choose IPA…") {
                guard let u = FilePicker.pick(types: [UTType(filenameExtension: "ipa") ?? .zip]) else { return }
                Task { await state.runScan(.iphone, ["scan", u.path, "--mode", "deep"], title: "IPA analysis finished") }
            }.buttonStyle(.borderedProminent)
        }
    }

    var isEncrypted: Bool { backups.first { $0["path"].string == selectedBackup }?["encrypted"].bool ?? false }

    func loadBackups() async {
        if let r = await state.run("backups", ["ios", "backups"]) {
            backups = r["backups"].array
            backupRootNote = r["readable"].bool == false ? (r["note"].string ?? "") : ""
        }
    }

    func analyse() async {
        var args = ["ios", "analyze", "--backup", selectedBackup, "--min-ios", "\(state.minIOSMajor)"]
        if includeMessages { args.append("--include-messages") }
        var stdin: String?
        if isEncrypted { args.append("--password-stdin"); stdin = password }
        await state.runScan(.iphone, args, stdin: stdin, title: "iPhone backup analysed")
        password = ""
    }

    func backupSummary(_ r: JSON) -> some View {
        Panel(title: "Backup", systemImage: "externaldrive.badge.checkmark") {
            Grid(alignment: .leading, horizontalSpacing: 24, verticalSpacing: 4) {
                GridRow { Text("Device").foregroundStyle(.secondary); Text("\(r["summary"]["device_name"].string ?? "") · \(r["summary"]["product_type"].string ?? "") · iOS \(r["summary"]["ios_version"].string ?? "")") }
                GridRow { Text("Encrypted").foregroundStyle(.secondary); Text(r["encrypted"].bool == true ? "Yes (decrypted in a private temporary area, deleted after analysis)" : "No") }
                GridRow { Text("Indexed").foregroundStyle(.secondary); Text("\(r["files_indexed"].int ?? 0) files in \(r["domains"].int ?? 0) domains") }
                GridRow { Text("Examined").foregroundStyle(.secondary); Text("\(r["installed_apps"].array.count) apps · \(r["urls_examined"].int ?? 0) URLs · \(r["processes_examined"].int ?? 0) process records · \(r["configuration_profiles"].int ?? 0) profile files") }
            }
        }
    }
}

@MainActor
struct TimelinePanel: View {
    let events: [JSON]
    var body: some View {
        Panel(title: "Timeline (UTC)", systemImage: "calendar.day.timeline.left") {
            ForEach(events, id: \.self) { e in
                HStack(alignment: .top) {
                    Text(e["at"].string?.replacingOccurrences(of: "T", with: " ").prefix(19).description ?? "").font(.caption.monospaced()).frame(width: 150, alignment: .leading)
                    Text(e["kind"].string ?? "").font(.caption.bold()).frame(width: 140, alignment: .leading)
                    Text(e["description"].string ?? "").font(.caption).textSelection(.enabled)
                    Spacer()
                    Text(e["source"].string ?? "").font(.caption2).foregroundStyle(.secondary)
                }
            }
        }
    }
}
