import SwiftUI
import AppKit

/// ARGENT DEFENDER design system — palette from the brand guidelines.
enum Theme {
    static let midnight = Color(hex: 0x101722)
    static let titanium = Color(hex: 0xC5CED8)
    static let platinum = Color(hex: 0xE5EAF0)
    static let navy = Color(hex: 0x17243A)
    static let electric = Color(hex: 0x3584D7)
    static let cyan = Color(hex: 0x48B8CF)
    static let amber = Color(hex: 0xE9A23B)
    static let critical = Color(hex: 0xD94A52)
    static let secure = Color(hex: 0x36A879)

    static let tagline = "DEFEND THE DIGITAL. REVEAL THE TRUTH."
    static let positioning = "ADVANCED CYBER INTELLIGENCE & DIGITAL FORENSICS"

    static func scoreColor(_ s: Int?) -> Color {
        guard let s else { return .secondary }
        switch s {
        case 90...: return secure
        case 70..<90: return cyan
        case 50..<70: return amber
        default: return critical
        }
    }

    static var logo: Image {
        // Inside the .app the build script copies the logo to Contents/Resources.
        // During `swift run` fall back to the source tree.
        let dev = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Resources/ArgentLogo.png")
        for url in [Bundle.main.url(forResource: "ArgentLogo", withExtension: "png"), dev].compactMap({ $0 }) {
            if let img = NSImage(contentsOf: url) { return Image(nsImage: img) }
        }
        return Image(systemName: "shield.lefthalf.filled")
    }

    static let panelBackground = Color(nsColor: .controlBackgroundColor)
}

extension Color {
    init(hex: UInt32, alpha: Double = 1) {
        self.init(.sRGB,
                  red: Double((hex >> 16) & 0xFF) / 255,
                  green: Double((hex >> 8) & 0xFF) / 255,
                  blue: Double(hex & 0xFF) / 255,
                  opacity: alpha)
    }
}

@MainActor
struct Panel<Content: View>: View {
    var title: String?
    var systemImage: String?
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let title {
                Label(title, systemImage: systemImage ?? "square.grid.2x2")
                    .font(.system(size: 12, weight: .semibold))
                    .tracking(1.2)
                    .textCase(.uppercase)
                    .foregroundStyle(.secondary)
            }
            content
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 14).fill(Theme.panelBackground))
        .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(Theme.titanium.opacity(0.25)))
    }
}
