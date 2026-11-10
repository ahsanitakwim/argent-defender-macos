import Foundation

struct EngineError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

/// Bridge to the Rust `argent-engine` binary. All calls run off the main thread,
/// exchange a single JSON envelope, and pass secrets only over stdin.
final class Engine: @unchecked Sendable {
    let binary: URL?
    let databaseURL: URL

    init() {
        let fm = FileManager.default
        let support = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("ArgentDefender", isDirectory: true)
        try? fm.createDirectory(at: support, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try? fm.createDirectory(at: support.appendingPathComponent("rules"), withIntermediateDirectories: true)
        databaseURL = support.appendingPathComponent("argent.db")

        var candidates: [URL] = []
        if let override = ProcessInfo.processInfo.environment["ARGENT_ENGINE"] { candidates.append(URL(fileURLWithPath: override)) }
        if let aux = Bundle.main.url(forAuxiliaryExecutable: "argent-engine") { candidates.append(aux) }
        if let res = Bundle.main.resourceURL { candidates.append(res.appendingPathComponent("argent-engine")) }
        // development: repo layout (app/ next to engine/)
        let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        candidates.append(repo.appendingPathComponent("engine/target/release/argent-engine"))
        binary = candidates.first { fm.isExecutableFile(atPath: $0.path) }
    }

    var supportDirectory: URL { databaseURL.deletingLastPathComponent() }
    var rulesDirectory: URL { supportDirectory.appendingPathComponent("rules") }
    var isAvailable: Bool { binary != nil }

    /// Runs the engine and returns `data` of the envelope, or throws the engine error.
    func run(_ args: [String], stdin: String? = nil) async throws -> JSON {
        guard let binary else {
            throw EngineError(message: "argent-engine binary not found in the application bundle. Reinstall ARGENT DEFENDER.")
        }
        let db = databaseURL.path
        return try await withCheckedThrowingContinuation { cont in
            DispatchQueue.global(qos: .userInitiated).async {
                let p = Process()
                p.executableURL = binary
                p.arguments = args
                var env = ProcessInfo.processInfo.environment
                env["ARGENT_DB"] = db
                // Homebrew / Android SDK tool locations for GUI apps (which lack a login PATH)
                env["PATH"] = (env["PATH"] ?? "/usr/bin:/bin") + ":/opt/homebrew/bin:/usr/local/bin"
                p.environment = env
                let out = Pipe(), err = Pipe(), inp = Pipe()
                p.standardOutput = out
                p.standardError = err
                p.standardInput = inp
                do { try p.run() } catch {
                    cont.resume(throwing: EngineError(message: "Failed to start engine: \(error.localizedDescription)"))
                    return
                }
                if let stdin {
                    inp.fileHandleForWriting.write(Data((stdin + "\n").utf8))
                }
                try? inp.fileHandleForWriting.close()
                // Drain stderr concurrently to avoid pipe-buffer deadlock.
                var errData = Data()
                let group = DispatchGroup()
                group.enter()
                DispatchQueue.global().async { errData = err.fileHandleForReading.readDataToEndOfFile(); group.leave() }
                let data = out.fileHandleForReading.readDataToEndOfFile()
                p.waitUntilExit()
                group.wait()
                do {
                    let env = try JSONDecoder().decode(JSON.self, from: data)
                    if env["ok"].bool == true {
                        cont.resume(returning: env["data"])
                    } else {
                        cont.resume(throwing: EngineError(message: env["error"].string ?? "Engine error"))
                    }
                } catch {
                    let msg = String(decoding: errData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                    cont.resume(throwing: EngineError(message: msg.isEmpty ? "Engine returned invalid output (exit \(p.terminationStatus))" : msg))
                }
            }
        }
    }
}
