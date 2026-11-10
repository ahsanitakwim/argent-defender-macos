import SwiftUI

// macOS 12 compatibility replacements for SwiftUI Grid and GridRow (introduced in macOS 13).
struct Grid<Content: View>: View {
    private let content: Content
    init(alignment: HorizontalAlignment = .center,
         horizontalSpacing: CGFloat? = nil,
         verticalSpacing: CGFloat? = nil,
         @ViewBuilder content: () -> Content) {
        self.content = content()
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 8) { content }
    }
}

struct GridRow<Content: View>: View {
    private let content: Content
    init(@ViewBuilder content: () -> Content) { self.content = content() }
    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            content
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
