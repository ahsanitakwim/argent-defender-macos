// swift-tools-version:5.9
// ARGENT DEFENDER — native macOS application (SwiftUI, MVVM, Swift Concurrency).
// Build: `swift build -c release --arch arm64 --arch x86_64` (Universal) or open this
// folder in Xcode. scripts/build_macos.sh assembles the signed .app and DMG.
import PackageDescription

let package = Package(
    name: "ArgentDefender",
    defaultLocalization: "en",
    platforms: [.macOS(.v12)],
    products: [.executable(name: "ArgentDefender", targets: ["ArgentDefender"])],
    targets: [
        .executableTarget(
            name: "ArgentDefender",
            path: "Sources/ArgentDefender",
            exclude: ["Resources"],
            linkerSettings: [.linkedFramework("Security"), .linkedFramework("WebKit")]
        ),
        .testTarget(
            name: "ArgentDefenderTests",
            dependencies: ["ArgentDefender"],
            path: "Tests/ArgentDefenderTests"
        ),
    ]
)
