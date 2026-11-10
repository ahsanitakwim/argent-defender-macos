import Foundation
import WebKit
import AppKit

/// Converts the engine's self-contained HTML report into a PDF using WebKit.
@MainActor
final class PDFRenderer: NSObject, WKNavigationDelegate {
    private var webView: WKWebView?
    private var continuation: CheckedContinuation<Data, Error>?

    func render(htmlURL: URL) async throws -> Data {
        let wv = WKWebView(frame: NSRect(x: 0, y: 0, width: 900, height: 1200))
        wv.navigationDelegate = self
        webView = wv
        return try await withCheckedThrowingContinuation { cont in
            continuation = cont
            wv.loadFileURL(htmlURL, allowingReadAccessTo: htmlURL.deletingLastPathComponent())
        }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        let config = WKPDFConfiguration()
        webView.createPDF(configuration: config) { [weak self] result in
            switch result {
            case .success(let data): self?.continuation?.resume(returning: data)
            case .failure(let e): self?.continuation?.resume(throwing: e)
            }
            self?.continuation = nil
            self?.webView = nil
        }
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        continuation?.resume(throwing: error)
        continuation = nil
    }
}

enum ReportExporter {
    enum Format: String, CaseIterable, Identifiable {
        case pdf = "PDF", html = "HTML", json = "JSON"
        var id: String { rawValue }
        var ext: String { rawValue.lowercased() }
    }

    @MainActor
    static func export(scanID: String, format: Format, sign: Bool, engine: Engine) async throws -> URL? {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "ARGENT-\(scanID).\(format.ext)"
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let dest = panel.url else { return nil }
        let seed = sign ? try Keychain.pqcSeed() : nil
        switch format {
        case .json:
            _ = try await engine.run(["report", "--scan", scanID, "--format", "json", "--out", dest.path] + (sign ? ["--sign"] : []), stdin: seed)
        case .html:
            _ = try await engine.run(["report", "--scan", scanID, "--format", "html", "--out", dest.path] + (sign ? ["--sign"] : []), stdin: seed)
        case .pdf:
            let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("argent-\(UUID().uuidString).html")
            _ = try await engine.run(["report", "--scan", scanID, "--format", "html", "--out", tmp.path] + (sign ? ["--sign"] : []), stdin: seed)
            let pdf = try await PDFRenderer().render(htmlURL: tmp)
            try pdf.write(to: dest)
            if sign {
                // sign the final PDF bytes too
                _ = try await engine.run(["pqc", "sign", "--file", dest.path, "--out", dest.path + ".sig.json"], stdin: seed)
            }
            try? FileManager.default.removeItem(at: tmp)
            try? FileManager.default.removeItem(at: tmp.deletingPathExtension().appendingPathExtension("sig.json"))
        }
        return dest
    }
}
