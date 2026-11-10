import SwiftUI
import AppKit

@MainActor
struct DeviceCenterView: View {
    @EnvironmentObject var state: AppState
    @State private var info: JSON = .null
    @State private var showWifiHelp = false

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            PageHeader(section: .devices, subtitle: "ARGENT DEVICE MANAGER — detection, pairing status and history (USB & local Wi-Fi)")
            HStack {
                Button { Task { await state.refreshDevices() } } label: { Label("Detect devices", systemImage: "arrow.clockwise") }
                    .buttonStyle(.borderedProminent)
                Button { showWifiHelp = true } label: { Label("Connect over Wi-Fi…", systemImage: "wifi") }
                Spacer()
                if state.isBusy("devices") { BusyOverlay(text: "Detecting…") }
            }
            toolStatus
            Panel(title: "Android (ADB)", systemImage: "candybarphone") {
                let list = state.devices["android"]["devices"].array
                if list.isEmpty { Text("No Android device detected. Enable Developer options › USB debugging, connect via USB and accept the RSA prompt on the phone.").foregroundStyle(.secondary) }
                ForEach(list, id: \.self) { d in
                    DeviceRow(platform: "android", id: d["serial"].string ?? "", name: d["model"].string ?? "Android device",
                              detail: "\(d["transport"].string?.uppercased() ?? "") · \(d["state"].string ?? "")",
                              ready: d["state"].string == "device",
                              hint: d["state"].string == "unauthorized" ? "Unlock the phone and tap ‘Allow USB debugging’." : nil,
                              info: $info)
                }
            }
            Panel(title: "iPhone / iPad (lockdown pairing)", systemImage: "iphone") {
                let list = state.devices["ios"]["devices"].array
                if list.isEmpty { Text("No iPhone detected. Connect via USB, unlock it and tap ‘Trust This Computer’.").foregroundStyle(.secondary) }
                ForEach(list, id: \.self) { d in
                    DeviceRow(platform: "ios", id: d["udid"].string ?? "", name: d["name"].string ?? "iPhone",
                              detail: "\(d["product_type"].string ?? "") · iOS \(d["ios_version"].string ?? "?") · \(d["connection"].string?.uppercased() ?? "")",
                              ready: d["paired"].bool ?? false,
                              hint: (d["paired"].bool ?? false) ? nil : "Not paired — unlock the iPhone and tap ‘Trust’.",
                              info: $info)
                }
            }
            Panel(title: "Device history", systemImage: "clock.arrow.circlepath") {
                if state.deviceHistory.isEmpty { Text("No devices examined yet.").foregroundStyle(.secondary) }
                Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 6) {
                    GridRow { Text("Device").bold(); Text("Platform").bold(); Text("OS").bold(); Text("Last scan").bold(); Text("Score").bold() }
                    ForEach(state.deviceHistory, id: \.self) { d in
                        GridRow {
                            Text("\(d["manufacturer"].string ?? "") \(d["model"].string ?? d["name"].string ?? d["device_id"].string ?? "")")
                            Text(d["platform"].string ?? "")
                            Text(d["os_version"].string ?? "—")
                            Text(d["last_scan"].string?.prefix(16).description ?? "—")
                            Text(d["last_score"].int.map(String.init) ?? "—").foregroundStyle(Theme.scoreColor(d["last_score"].int))
                        }
                    }
                }
            }
            if !info.isNull {
                Panel(title: "Device information", systemImage: "info.circle") { EngineOutputView(json: info) }
            }
        }
        .sheet(isPresented: $showWifiHelp) { WifiHelp() }
    }

    var toolStatus: some View {
        let missing = state.env["tools"].array.filter { ["adb", "idevice_id", "ideviceinfo", "idevicebackup2"].contains($0["name"].string ?? "") && $0["path"].isNull }
        return Group {
            if !missing.isEmpty {
                Panel(title: "Required tools missing", systemImage: "wrench.and.screwdriver") {
                    ForEach(missing, id: \.self) { t in
                        Text("• \(t["name"].string ?? "") — \(t["purpose"].string ?? ""): `\(t["install_hint"].string ?? "")`").font(.callout)
                    }
                }
            }
        }
    }
}

@MainActor
struct DeviceRow: View {
    @EnvironmentObject var state: AppState
    let platform: String, id: String, name: String, detail: String
    let ready: Bool
    let hint: String?
    @Binding var info: JSON
    var body: some View {
        HStack {
            Image(systemName: platform == "ios" ? "iphone" : "candybarphone").font(.title2).foregroundStyle(ready ? Theme.secure : Theme.amber)
            VStack(alignment: .leading) {
                Text(name).font(.headline)
                Text(detail).font(.caption).foregroundStyle(.secondary)
                Text(id).font(.caption2.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                if let hint { Text(hint).font(.caption).foregroundStyle(Theme.amber) }
            }
            Spacer()
            Button("Device Information") {
                Task { if let j = await state.run("info", platform == "ios" ? ["ios", "info", "--udid", id] : ["android", "info", "--serial", id]) { info = j } }
            }.disabled(!ready)
            Button("Start Scan") { state.selection = platform == "ios" ? .iphone : .android }
                .buttonStyle(.borderedProminent).disabled(!ready)
        }
        .padding(.vertical, 4)
    }
}

@MainActor
struct WifiHelp: View {
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Connect over the local network").font(.title3.bold())
            Text("Android 11+: Settings › Developer options › Wireless debugging › Pair device with pairing code, then on this Mac run:").font(.callout)
            Text("adb pair <ip>:<pair-port>   then   adb connect <ip>:<port>").font(.callout.monospaced()).textSelection(.enabled)
            Text("iPhone: connect once by USB, open Finder, select the iPhone and enable ‘Show this iPhone when on Wi-Fi’. Wi-Fi devices then appear with connection WIFI.").font(.callout)
            Text("Both mechanisms are the vendors' official, user-authorised pairing flows. ARGENT DEFENDER never enables them silently.").font(.caption).foregroundStyle(.secondary)
            HStack { Spacer(); Button("Done") { dismiss() }.keyboardShortcut(.defaultAction) }
        }.padding(24).frame(width: 560)
    }
}
