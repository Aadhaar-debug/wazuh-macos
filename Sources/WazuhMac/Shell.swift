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

            let lock = NSLock()
            var collected = Data()
            var pending = Data()
            pipe.fileHandleForReading.readabilityHandler = { h in
                let chunk = h.availableData
                guard !chunk.isEmpty else { return }
                lock.lock()
                collected.append(chunk)
                pending.append(chunk)
                var lines: [String] = []
                while let nl = pending.firstIndex(of: 0x0A) {
                    let lineData = pending[pending.startIndex..<nl]
                    pending.removeSubrange(pending.startIndex...nl)
                    lines.append(String(decoding: lineData, as: UTF8.self))
                }
                lock.unlock()
                if let onLine { lines.forEach(onLine) }
            }
            p.terminationHandler = { proc in
                pipe.fileHandleForReading.readabilityHandler = nil
                let rest = (try? pipe.fileHandleForReading.readToEnd()) ?? nil
                lock.lock()
                if let rest { collected.append(rest); pending.append(rest) }
                let tail = String(decoding: pending, as: UTF8.self)
                let all = String(decoding: collected, as: UTF8.self)
                lock.unlock()
                if let onLine, !tail.isEmpty { tail.split(separator: "\n").forEach { onLine(String($0)) } }
                cont.resume(returning: Result(status: proc.terminationStatus, output: all))
            }
            do {
                try p.run()
            } catch {
                pipe.fileHandleForReading.readabilityHandler = nil
                cont.resume(returning: Result(status: -1, output: error.localizedDescription))
            }
        }
    }
}
