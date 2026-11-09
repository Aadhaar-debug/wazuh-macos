import Foundation

/// Runs external commands (docker, open) with a PATH that works when launched from Finder.
enum Shell {
    static let searchPaths = [
        "/usr/local/bin",
        "/opt/homebrew/bin",
        "/Applications/Docker.app/Contents/Resources/bin",
        "/usr/bin", "/bin", "/usr/sbin", "/sbin",
    ]

    static var environment: [String: String] {
        var env = ProcessInfo.processInfo.environment
        let existing = env["PATH"] ?? ""
        env["PATH"] = (searchPaths + [existing]).joined(separator: ":")
        return env
    }

    static func which(_ name: String) -> String? {
        for dir in searchPaths {
            let p = "\(dir)/\(name)"
            if FileManager.default.isExecutableFile(atPath: p) { return p }
        }
        return nil
    }

    struct Result {
        let status: Int32
        let output: String
        var ok: Bool { status == 0 }
    }

    /// Run a command to completion. `onLine` receives output lines as they arrive.
    static func run(_ executable: String,
                    _ args: [String],
                    cwd: URL? = nil,
                    onLine: ((String) -> Void)? = nil) async -> Result {
        await withCheckedContinuation { cont in
            let p = Process()
            p.executableURL = URL(fileURLWithPath: executable)
            p.arguments = args
            p.environment = environment
            if let cwd { p.currentDirectoryURL = cwd }
            let pipe = Pipe()
            p.standardOutput = pipe
            p.standardError = pipe

            do {
                try p.run()
            } catch {
                cont.resume(returning: Result(status: -1, output: error.localizedDescription))
                return
            }
            // Read on a background thread until EOF, then reap the process: no output is lost.
            DispatchQueue.global(qos: .userInitiated).async {
                let h = pipe.fileHandleForReading
                var collected = Data()
                var pending = Data()
                while true {
                    let chunk = h.availableData
                    if chunk.isEmpty { break }
                    collected.append(chunk)
                    guard let onLine else { continue }
                    pending.append(chunk)
                    while let nl = pending.firstIndex(of: 0x0A) {
                        onLine(String(decoding: pending[pending.startIndex..<nl], as: UTF8.self))
                        pending.removeSubrange(pending.startIndex...nl)
                    }
                }
                p.waitUntilExit()
                if let onLine, !pending.isEmpty { onLine(String(decoding: pending, as: UTF8.self)) }
                cont.resume(returning: Result(status: p.terminationStatus, output: String(decoding: collected, as: UTF8.self)))
            }
        }
    }
}
