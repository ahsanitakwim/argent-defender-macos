import SwiftUI
import AppKit

@main
struct ArgentDefenderApp: App {
    @StateObject private var state = AppState()
    @AppStorage("appearance") private var appearance: String = "system"

    var body: some Scene {
        WindowGroup("ARGENT DEFENDER") {
            RootView()
                .environmentObject(state)
                .frame(minWidth: 1100, minHeight: 720)
                .preferredColorScheme(appearance == "dark" ? .dark : appearance == "light" ? .light : nil)
                .task { await state.bootstrap() }
        }
        .windowStyle(.titleBar)
        .windowToolbarStyle(.unified)
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About ARGENT DEFENDER") {
                    NSApp.orderFrontStandardAboutPanel(options: [
                        .applicationName: "ARGENT DEFENDER",
                        .credits: NSAttributedString(string: "\(Theme.positioning)\n\(Theme.tagline)"),
                    ])
                }
            }
            CommandMenu("Scan") {
                Button("Refresh Devices") { Task { await state.refreshDevices() } }.keyboardShortcut("r")
                Button("Quick Scan…") { state.selection = .quickScan }.keyboardShortcut("1")
                Button("Analyse APK / IPA…") { state.selection = .malware }.keyboardShortcut("2")
                Button("Check URL…") { state.selection = .network }.keyboardShortcut("3")
            }
        }
        Settings {
            SettingsView().environmentObject(state).frame(width: 720, height: 560)
        }
    }
}
