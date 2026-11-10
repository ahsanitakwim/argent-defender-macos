import Foundation

/// ARGENT AI narrative assistant. Talks to a LOCAL llama.cpp server (OpenAI-compatible
/// `/v1/chat/completions`) by default; a cloud endpoint is used only when the user has
/// explicitly enabled it. Only finding titles/evidence are sent — never files, APKs or
/// backups. The LLM explains results; it never decides detections.
struct AIAssistant {
    struct Config {
        var endpoint: URL
        var model: String
        var apiKey: String?
        var isCloud: Bool
    }

    static let systemPrompt = """
    You are ARGENT AI, a mobile-security and digital-forensics analyst assistant. \
    Explain the findings provided in plain language for a non-expert, in the user's language \
    (Bahasa Indonesia if the user writes Indonesian). Rules: cite finding IDs in [brackets] for \
    every claim; never invent findings, malware names or evidence that is not in the input; \
    clearly separate severity (impact) from confidence (certainty); state that items marked \
    'limitation' were not examined; give safe, practical next steps.
    """

    static func explain(findings: [Finding], question: String, config: Config) async throws -> String {
        let compact = findings.prefix(60).map { f in
            "[\(f.id)] \(f.severity.rawValue)/\(f.confidence.rawValue) \(f.category): \(f.title) — subject \(f.subject.name). Evidence: \(f.evidence.filter { !$0.isEmpty }.joined(separator: "; "))"
        }.joined(separator: "\n")
        let body: [String: Any] = [
            "model": config.model,
            "temperature": 0.2,
            "messages": [
                ["role": "system", "content": systemPrompt],
                ["role": "user", "content": "Findings:\n\(compact)\n\nQuestion: \(question)"],
            ],
        ]
        var req = URLRequest(url: config.endpoint.appendingPathComponent("v1/chat/completions"))
        req.httpMethod = "POST"
        req.timeoutInterval = 180
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let k = config.apiKey, !k.isEmpty { req.setValue("Bearer \(k)", forHTTPHeaderField: "Authorization") }
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, resp) = try await URLSession.shared.data(for: req)
        guard let http = resp as? HTTPURLResponse, http.statusCode == 200 else {
            throw EngineError(message: "AI endpoint returned \((resp as? HTTPURLResponse)?.statusCode ?? -1). Is llama.cpp `llama-server` running at \(config.endpoint.absoluteString)?")
        }
        let j = try JSONDecoder().decode(JSON.self, from: data)
        return j["choices"][0]["message"]["content"].string ?? "(empty response)"
    }
}
