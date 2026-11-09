import Foundation

/// Runs external commands (docker, open, nc) with a PATH that works when launched from Finder.
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
        var timedOut = false
        var ok: Bool { status == 0 && !timedOut }
    }

    /// Run a command to completion and return its combined stdout/stderr.
    ///
    /// Output goes to a temporary file rather than a pipe, so a helper process that inherits the
    /// descriptor (Docker's CLI can leave some behind) can never keep the call waiting. stdin is
    /// /dev/null, and the command is terminated after `timeout` seconds (nil = no limit, for pulls).
    /// `onLine` receives output lines as they arrive.
    static func run(_ executable: String,
                    _ args: [String],
                    cwd: URL? = nil,
                    timeout: TimeInterval? = 60,
                    onLine: ((String) -> Void)? = nil) async -> Result {
        await withCheckedContinuation { cont in
            let outURL = FileManager.default.temporaryDirectory
                .appendingPathComponent("wazuhmac-\(UUID().uuidString).out")
            FileManager.default.createFile(atPath: outURL.path, contents: nil)
            guard let writer = FileHandle(forWritingAtPath: outURL.path),
                  let reader = FileHandle(forReadingAtPath: outURL.path) else {
                cont.resume(returning: Result(status: -1, output: "Could not create output file"))
                return
            }

            let p = Process()
            p.executableURL = URL(fileURLWithPath: executable)
            p.arguments = args
            p.environment = environment
            if let cwd { p.currentDirectoryURL = cwd }
            p.standardInput = FileHandle.nullDevice
            p.standardOutput = writer
            p.standardError = writer
            // Signalled on exit. (waitUntilExit() can hang on a background queue with no run loop.)
            let exited = DispatchSemaphore(value: 0)
            p.terminationHandler = { _ in exited.signal() }

            do {
                try p.run()
            } catch {
                try? writer.close(); try? reader.close()
                try? FileManager.default.removeItem(at: outURL)
                cont.resume(returning: Result(status: -1, output: error.localizedDescription))
                return
            }
            try? writer.close()   // the child keeps its own copy

            DispatchQueue.global(qos: .userInitiated).async {
                var collected = Data()
                var pending = Data()
                var timedOut = false
                let deadline = timeout.map { Date().addingTimeInterval($0) }

                func drain() {
                    let chunk = reader.availableData   // regular file: returns at current EOF, never blocks
                    guard !chunk.isEmpty else { return }
                    collected.append(chunk)
                    guard let onLine else { return }
                    pending.append(chunk)
                    while let nl = pending.firstIndex(of: 0x0A) {
                        onLine(String(decoding: pending[pending.startIndex..<nl], as: UTF8.self))
                        pending.removeSubrange(pending.startIndex...nl)
                    }
                }

                while exited.wait(timeout: .now() + .milliseconds(50)) == .timedOut {
                    drain()
                    if let deadline, !timedOut, Date() > deadline {
                        timedOut = true
                        p.terminate()
                    }
                }
                drain()
                if let onLine, !pending.isEmpty { onLine(String(decoding: pending, as: UTF8.self)) }
                try? reader.close()
                try? FileManager.default.removeItem(at: outURL)

                var text = String(decoding: collected, as: UTF8.self)
                if timedOut { text += "\n[timed out after \(Int(timeout ?? 0))s]" }
                cont.resume(returning: Result(status: p.terminationStatus, output: text, timedOut: timedOut))
            }
        }
    }
}
