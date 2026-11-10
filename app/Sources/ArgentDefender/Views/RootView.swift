import SwiftUI
import AppKit

@MainActor
struct RootView: View {
    @EnvironmentObject var state: AppState
    @State private var showSplash = true
    @State private var showNotifications = false

    var body: some View {
        ZStack {
            HStack(spacing: 0) {
                Sidebar()
                    .frame(minWidth: 220, idealWidth: 250, maxWidth: 280)
                Divider()
                ScrollView {
                    detail
                        .padding(24)
                        .frame(maxWidth: 1400, alignment: .topLeading)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            }
            .toolbar {
                ToolbarItemGroup(placement: .primaryAction) {
                    if !state.busy.isEmpty { ProgressView().controlSize(.small) }
                    Button { Task { await state.refreshDevices() } } label: { Label("Refresh devices", systemImage: "arrow.clockwise") }
                    Button { showNotifications.toggle() } label: {
                        Label("Notifications", systemImage: state.notifications.isEmpty ? "bell" : "bell.badge")
                    }
                    .popover(isPresented: $showNotifications, arrowEdge: .bottom) { NotificationCenterView().environmentObject(state) }
                }
            }
            if showSplash {
                SplashView().transition(.opacity).zIndex(10)
            }
        }
        .alert("ARGENT DEFENDER", isPresented: Binding(get: { state.errorMessage != nil }, set: { if !$0 { state.errorMessage = nil } })) {
            Button("OK", role: .cancel) { state.errorMessage = nil }
        } message: { Text(state.errorMessage ?? "") }
        .task {
            try? await Task.sleep(nanoseconds: 1_300_000_000)
            withAnimation(.easeOut(duration: 0.4)) { showSplash = false }
        }
    }

    @ViewBuilder var detail: some View {
        switch state.selection ?? .overview {
        case .overview: OverviewView()
        case .devices: DeviceCenterView()
        case .quickScan: ScanView(mode: .quick)
        case .fullScan: ScanView(mode: .full)
        case .deepScan: ScanView(mode: .deep)
        case .android: AndroidScannerView()
        case .iphone: IPhoneScannerView()
        case .malware: MalwareAnalysisView()
        case .gaming: GamingWatchView()
        case .network: NetworkSecurityView()
        case .forensics: ForensicsView()
        case .intel: ThreatIntelView()
        case .ai: AIView()
        case .reports: ReportsView()
        case .history: HistoryView()
        case .settings: SettingsView()
        }
    }
}

@MainActor
struct Sidebar: View {
    @EnvironmentObject var state: AppState
    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Theme.logo.resizable().interpolation(.high).frame(width: 40, height: 40).clipShape(RoundedRectangle(cornerRadius: 9))
                VStack(alignment: .leading, spacing: 1) {
                    Text("ARGENT").font(.system(size: 14, weight: .heavy)).tracking(3)
                    Text("DEFENDER").font(.system(size: 10, weight: .semibold)).tracking(4).foregroundStyle(Theme.cyan)
                }
                Spacer()
            }
            .padding(.horizontal, 14).padding(.vertical, 12)
            List(selection: $state.selection) {
                ForEach(NavSection.groups) { group in
                    Section(group.title) {
                        ForEach(group.items) { s in
                            Label(s.rawValue, systemImage: s.icon).tag(s)
                        }
                    }
                }
            }
            .listStyle(.sidebar)
            HStack(spacing: 6) {
                Circle().fill(state.connectedCount > 0 ? Theme.secure : Color.gray).frame(width: 7, height: 7)
                Text("\(state.connectedCount) device(s) connected").font(.caption).foregroundStyle(.secondary)
                Spacer()
            }
            .padding(12)
        }
    }
}

@MainActor
struct SplashView: View {
    var body: some View {
        ZStack {
            LinearGradient(colors: [Theme.midnight, Theme.navy], startPoint: .topLeading, endPoint: .bottomTrailing).ignoresSafeArea()
            VStack(spacing: 18) {
                Theme.logo.resizable().interpolation(.high).frame(width: 150, height: 150).clipShape(RoundedRectangle(cornerRadius: 32))
                    .shadow(color: Theme.electric.opacity(0.5), radius: 30)
                Text("ARGENT DEFENDER").font(.system(size: 30, weight: .heavy)).tracking(6).foregroundStyle(Theme.platinum)
                Text(Theme.positioning).font(.system(size: 11, weight: .semibold)).tracking(3).foregroundStyle(Theme.titanium)
                Text(Theme.tagline).font(.system(size: 12, weight: .bold)).tracking(3).foregroundStyle(Theme.cyan)
            }
        }
    }
}

@MainActor
struct NotificationCenterView: View {
    @EnvironmentObject var state: AppState
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Notifications").font(.headline)
                Spacer()
                Button("Clear") { state.notifications.removeAll() }.disabled(state.notifications.isEmpty)
            }
            if state.notifications.isEmpty {
                Text("No notifications yet.").foregroundStyle(.secondary)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(state.notifications) { n in
                            HStack(alignment: .top) {
                                Circle().fill(n.severity.color).frame(width: 8, height: 8).padding(.top, 5)
                                VStack(alignment: .leading) {
                                    Text(n.title).font(.callout.bold())
                                    Text(n.detail).font(.caption).foregroundStyle(.secondary)
                                    Text(n.date, style: .time).font(.caption2).foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                }.frame(maxHeight: 360)
            }
        }
        .padding(14).frame(width: 340)
    }
}
