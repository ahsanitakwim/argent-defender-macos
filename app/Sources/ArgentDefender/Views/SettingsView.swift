import SwiftUI
import AppKit

/// Settings & ARGENT ADMIN workspace: tools, rules, integrations, keys, audit log.
@MainActor
struct SettingsView: View {
    @EnvironmentObject var state: AppState
    @AppStorage("appearance") private var appearance = "system"
    @AppStorage("ai.endpoint") private var aiEndpoint = "http://127.0.0.1:8080"
    @AppStorage("ai.model") private var aiModel = "local"
    @AppStorage("ai.cloudEnabled") private var cloudEnabled = false
    @AppStorage("ai.cloudEndpoint") private var cloudEndpoint = ""
    @State private var abuseKey = ""
    @State private var cloudKey = ""
    @State private var rules: JSON = .null
    @State private var audit: [JSON] = []
    @State private var auditStatus: JSON = .null
    @State private var pubkey: JSON = .null

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                PageHeader(section: .settings, subtitle: "Preferences · ARGENT ADMIN · integrations · keys · audit")
                Panel(title: "General", systemImage: "gearshape") {
                    Picker("Appearance", selection: $appearance) { Text("System").tag("system"); Text("Dark").tag("dark"); Text("Light").tag("light") }.pickerStyle(.segmented).frame(width: 300)
                    TextField("Analyst / examiner name", text: $state.analystName).frame(width: 360)
                    Stepper("Minimum supported iOS major version: \(state.minIOSMajor)", value: $state.minIOSMajor, in: 12...40)
                    Text("Data folder: \(state.engine.supportDirectory.path)").font(.caption.monospaced()).textSelection(.enabled)
                    Button("Show data folder in Finder") { NSWorkspace.shared.activateFileViewerSelecting([state.engine.databaseURL]) }
                }
                Panel(title: "Environment & tools (adaptive compatibility)", systemImage: "cpu") {
                    let h = state.env["host"]
                    Text("\(h["os"].string ?? "") \(h["os_version"].string ?? "") · \(h["arch"].string ?? "") \(h["apple_silicon"].bool == true ? "(Apple Silicon)" : "") · \(h["logical_cpus"].int ?? 0) CPUs · \(ByteCountFormatter.string(fromByteCount: Int64(h["memory_bytes"].double ?? 0), countStyle: .memory)) RAM · engine \(h["engine_version"].string ?? "?")")
                        .font(.callout)
                    if !state.engine.isAvailable { Label("Engine binary missing", systemImage: "xmark.octagon").foregroundStyle(Theme.critical) }
                    ForEach(state.env["tools"].array, id: \.self) { t in
                        HStack {
                            Image(systemName: t["path"].isNull ? "circle.dashed" : "checkmark.circle.fill").foregroundStyle(t["path"].isNull ? Color.secondary : Theme.secure)
                            Text(t["name"].string ?? "").font(.callout.monospaced()).frame(width: 120, alignment: .leading)
                            Text(t["purpose"].string ?? "").font(.caption)
                            Spacer()
                            Text(t["path"].isNull ? (t["install_hint"].string ?? "") : (t["version"].string ?? t["path"].string ?? "")).font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1)
                        }
                    }
                    Text("Missing optional tools only disable the related feature; the rest of ARGENT DEFENDER keeps working.").font(.caption).foregroundStyle(.secondary)
                    Button("Re-detect") { Task { await state.bootstrap() } }
                }
                Panel(title: "YARA rules (admin)", systemImage: "list.bullet.rectangle.portrait") {
                    Text("Bundled rules plus any .yar/.yara in the rules folder are compiled with YARA-X. Invalid files are skipped and reported.").font(.caption).foregroundStyle(.secondary)
                    HStack {
                        Button("Open rules folder") { NSWorkspace.shared.open(state.engine.rulesDirectory) }
                        Button("Add rule file…") {
                            guard let u = FilePicker.pick() else { return }
                            try? FileManager.default.copyItem(at: u, to: state.engine.rulesDirectory.appendingPathComponent(u.lastPathComponent))
                            Task { await loadRules() }
                        }
                        Button("Reload & validate") { Task { await loadRules() } }
                    }
                    if !rules.isNull {
                        Text("\(rules["count"].int ?? 0) rules from \(rules["files"].array.count) file(s)").font(.callout)
                        ForEach(rules["errors"].array, id: \.self) { Text($0.string ?? "").font(.caption.monospaced()).foregroundStyle(Theme.critical) }
                        DisclosureGroup("Rule list") { ForEach(rules["rules"].array, id: \.self) { Text($0.string ?? "").font(.caption.monospaced()) } }
                    }
                }
                Panel(title: "Integrations (secrets stored in the macOS Keychain)", systemImage: "key") {
                    HStack {
                        SecureField(Keychain.get("abusech.authkey") == nil ? "abuse.ch Auth-Key (optional)" : "abuse.ch Auth-Key ••• stored", text: $abuseKey).frame(width: 360)
                        Button("Save") { try? Keychain.set(abuseKey, for: "abusech.authkey"); abuseKey = "" }.disabled(abuseKey.isEmpty)
                        Button("Remove") { Keychain.delete("abusech.authkey") }
                    }
                    TextField("Local AI endpoint (llama.cpp llama-server)", text: $aiEndpoint).frame(width: 420)
                    TextField("Model name", text: $aiModel).frame(width: 240)
                    Toggle("Allow cloud AI for explanations (opt-in; sends finding titles/evidence only)", isOn: $cloudEnabled)
                    if cloudEnabled {
                        TextField("Cloud endpoint (OpenAI-compatible base URL)", text: $cloudEndpoint).frame(width: 420)
                        HStack {
                            SecureField("Cloud API key", text: $cloudKey).frame(width: 360)
                            Button("Save") { try? Keychain.set(cloudKey, for: "ai.cloud.key"); cloudKey = "" }.disabled(cloudKey.isEmpty)
                        }
                    }
                }
                Panel(title: "Quantum-ready security", systemImage: "lock.rotation") {
                    Text("Reports and evidence exports are signed with Ed25519 + ML-DSA-65 (FIPS 204) and can be encrypted with X25519 + ML-KEM-768 (FIPS 203). The master seed lives only in the Keychain.").font(.callout)
                    Toggle("Sign exported reports by default", isOn: $state.signReports)
                    HStack {
                        Button("Show public key") {
                            Task {
                                guard let seed = try? Keychain.pqcSeed() else { return }
                                if let r = await state.run("pqc", ["pqc", "pubkey"], stdin: seed) { pubkey = r }
                            }
                        }
                        Button("Export public key…") {
                            let p = NSSavePanel(); p.nameFieldStringValue = "argent-public-key.json"
                            if p.runModal() == .OK, let u = p.url { try? Data(pubkey.pretty.utf8).write(to: u) }
                        }.disabled(pubkey.isNull)
                    }
                    if !pubkey.isNull { Text("Fingerprint \(pubkey["fingerprint"].string ?? "") · \(pubkey["sig_suite"].string ?? "")").font(.caption.monospaced()).textSelection(.enabled) }
                }
                Panel(title: "Audit log (tamper-evident)", systemImage: "list.clipboard") {
                    HStack {
                        Button("Verify chain") { Task { if let r = await state.run("auditv", ["audit-verify"]) { auditStatus = r } } }
                        Button("Load entries") { Task { if let r = await state.run("auditl", ["audit-log", "--limit", "300"]) { audit = r.array } } }
                        if !auditStatus.isNull {
                            Label(auditStatus["intact"].bool == true ? "Intact (\(auditStatus["entries"].int ?? 0) entries)" : "BROKEN at #\(auditStatus["first_broken_seq"].int ?? 0)",
                                  systemImage: auditStatus["intact"].bool == true ? "checkmark.seal.fill" : "exclamationmark.octagon.fill")
                                .foregroundStyle(auditStatus["intact"].bool == true ? Theme.secure : Theme.critical)
                        }
                    }
                    ForEach(audit, id: \.self) { a in
                        Text("#\(a["seq"].int ?? 0) \(a["at"].string ?? "") \(a["actor"].string ?? "") \(a["action"].string ?? "") \(a["detail"].string ?? "")").font(.caption.monospaced()).lineLimit(1).textSelection(.enabled)
                    }
                }
                Panel(title: "Privacy", systemImage: "hand.raised") {
                    Text("Local-first: all scanning, decryption and AI anomaly detection run on this Mac. No APK, backup or personal data is uploaded. Online actions (intel updates, redirect tracing, cloud AI) only happen when you trigger them. iPhone backup passwords are never stored. No device configuration is changed and no application is deleted automatically.")
                        .font(.callout).fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(4)
        }
        .task { await loadRules() }
    }

    func loadRules() async { if let r = await state.run("rules", ["rules"]) { rules = r } }
}
