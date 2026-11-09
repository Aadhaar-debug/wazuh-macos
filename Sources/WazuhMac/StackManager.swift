import Foundation
import SwiftUI

/// Wazuh version bundled with this app (matches the upstream wazuh-docker tag).
let wazuhVersion = "4.14.10"
let composeProject = "wazuh-mac"

struct ServiceStatus: Identifiable, Equatable {
    let id: String          // compose service name, e.g. wazuh.manager
    var title: String
    var subtitle: String
    var containerState: String = "not created"   // running / exited / ...
    var health: String = ""
    var endpointOK: Bool? = nil
    var endpoint: String

    var isRunning: Bool { containerState == "running" }
}

enum DockerState: Equatable {
    case unknown, notInstalled, stopped, starting, ready
}

@MainActor
final class StackManager: ObservableObject {
    @Published var docker: DockerState = .unknown
    @Published var services: [ServiceStatus] = [
        ServiceStatus(id: "wazuh.manager", title: "Wazuh Server (Manager)",
                      subtitle: "Analysis engine, agent enrollment (1514/1515), API on 55000",
                      endpoint: "https://localhost:55000"),
        ServiceStatus(id: "wazuh.indexer", title: "Wazuh Indexer",
                      subtitle: "OpenSearch-based alert & event storage on 9200",
                      endpoint: "https://localhost:9200"),
        ServiceStatus(id: "wazuh.dashboard", title: "Wazuh Dashboard",
                      subtitle: "Web UI for SIEM, XDR, compliance and agents",
                      endpoint: "https://localhost"),
    ]
    @Published var activity: String = ""
    @Published var busy = false
    @Published var log: [String] = []

    var dockerPath: String? { Shell.which("docker") }

    var allRunning: Bool { services.allSatisfy(\.isRunning) }
    var anyRunning: Bool { services.contains(where: \.isRunning) }
    var dashboardReady: Bool { services.first { $0.id == "wazuh.dashboard" }?.endpointOK == true }

    /// Writable copy of the bundled compose stack.
    let stackDir: URL = {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("WazuhMac/stack", isDirectory: true)
    }()

    private var certsDir: URL { stackDir.appendingPathComponent("config/wazuh_indexer_ssl_certs") }
    private var pollTask: Task<Void, Never>?

    // MARK: - Lifecycle

    func bootstrap() {
        installStackIfNeeded()
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                try? await Task.sleep(nanoseconds: 5_000_000_000)
            }
        }
    }

    private func append(_ line: String) {
        log.append(line)
        if log.count > 4000 { log.removeFirst(log.count - 4000) }
    }

    /// Copy the bundled stack into Application Support (keeps certs & edits across app updates).
    private func installStackIfNeeded() {
        let fm = FileManager.default
        guard let bundled = Bundle.main.url(forResource: "stack", withExtension: nil) else {
            append("⚠️ Bundled stack resources not found")
            return
        }
        let marker = stackDir.appendingPathComponent(".version")
        let installed = (try? String(contentsOf: marker, encoding: .utf8)) ?? ""
        if installed == wazuhVersion, fm.fileExists(atPath: stackDir.path) { return }

        try? fm.createDirectory(at: stackDir, withIntermediateDirectories: true)
        // Copy files, never overwriting generated certificates.
        if let e = fm.enumerator(at: bundled, includingPropertiesForKeys: [.isDirectoryKey]) {
            for case let src as URL in e {
                let rel = src.path.replacingOccurrences(of: bundled.path + "/", with: "")
                let dst = stackDir.appendingPathComponent(rel)
                if (try? src.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true {
                    try? fm.createDirectory(at: dst, withIntermediateDirectories: true)
                } else {
                    try? fm.removeItem(at: dst)
                    try? fm.copyItem(at: src, to: dst)
                }
            }
        }
        try? wazuhVersion.write(to: marker, atomically: true, encoding: .utf8)
        append("Installed Wazuh \(wazuhVersion) stack to \(stackDir.path)")
    }

    // MARK: - Docker

    func refresh() async {
        guard let docker = dockerPath else { self.docker = .notInstalled; return }
        let info = await Shell.run(docker, ["info", "--format", "{{.ServerVersion}}"])
        if !info.ok {
            if self.docker != .starting { self.docker = .stopped }
            for i in services.indices { services[i].containerState = "unavailable"; services[i].endpointOK = nil }
            return
        }
        self.docker = .ready
        let ps = await Shell.run(docker, ["compose", "-p", composeProject, "ps", "-a", "--format", "json"], cwd: stackDir)
        var states: [String: (String, String)] = [:]
        for line in ps.output.split(separator: "\n") {
            guard let data = line.data(using: .utf8) else { continue }
            let obj = try? JSONSerialization.jsonObject(with: data)
            let items: [[String: Any]] = (obj as? [[String: Any]]) ?? ((obj as? [String: Any]).map { [$0] } ?? [])
            for it in items {
                if let svc = it["Service"] as? String {
                    states[svc] = ((it["State"] as? String) ?? "?", (it["Health"] as? String) ?? "")
                }
            }
        }
        for i in services.indices {
            let s = states[services[i].id]
            services[i].containerState = s?.0 ?? "not created"
            services[i].health = s?.1 ?? ""
        }
        await probeEndpoints()
    }

    private func probeEndpoints() async {
        for i in services.indices {
            guard services[i].isRunning else { services[i].endpointOK = nil; continue }
            services[i].endpointOK = await Probe.reachable(services[i].endpoint)
        }
    }

    func launchDockerDesktop() async {
        docker = .starting
        activity = "Starting Docker Desktop…"
        _ = await Shell.run("/usr/bin/open", ["-a", "Docker"])
        for _ in 0..<90 {
            if let d = dockerPath, await Shell.run(d, ["info"]).ok { break }
            try? await Task.sleep(nanoseconds: 2_000_000_000)
        }
        activity = ""
        docker = .unknown
        await refresh()
    }

    // MARK: - Stack actions

    private func compose(_ args: [String], file: String = "docker-compose.yml") async -> Bool {
        guard let docker = dockerPath else { return false }
        append("$ docker compose \(args.joined(separator: " "))")
        let r = await Shell.run(docker, ["compose", "-p", composeProject, "-f", file] + args, cwd: stackDir) { line in
            Task { @MainActor in self.append(line) }
        }
        if !r.ok { append("✖ exited with status \(r.status)") }
        return r.ok
    }

    private var certsExist: Bool {
        FileManager.default.fileExists(atPath: certsDir.appendingPathComponent("root-ca.pem").path)
    }

    func start() async {
        guard !busy else { return }
        busy = true; defer { busy = false; activity = "" }
        installStackIfNeeded()
        if docker != .ready { await launchDockerDesktop() }
        guard docker == .ready else { activity = ""; append("✖ Docker is not running"); return }

        if !certsExist {
            activity = "Generating TLS certificates…"
            let ok = await compose(["run", "--rm", "generator"], file: "generate-indexer-certs.yml")
            guard ok, certsExist else { append("✖ Certificate generation failed"); return }
        }
        activity = "Pulling images (first run can take several minutes)…"
        _ = await compose(["pull"])
        activity = "Starting Wazuh manager, indexer and dashboard…"
        _ = await compose(["up", "-d"])
        activity = "Waiting for the dashboard to come up…"
        for _ in 0..<90 {
            await refresh()
            if dashboardReady { break }
            try? await Task.sleep(nanoseconds: 4_000_000_000)
        }
        append(dashboardReady ? "✔ Wazuh is ready at https://localhost" : "… services still starting; check logs")
    }

    func stop() async {
        guard !busy else { return }
        busy = true; defer { busy = false; activity = "" }
        activity = "Stopping Wazuh…"
        _ = await compose(["stop"])
        await refresh()
    }

    func restart(_ service: String? = nil) async {
        guard !busy else { return }
        busy = true; defer { busy = false; activity = "" }
        activity = "Restarting \(service ?? "Wazuh")…"
        _ = await compose(["restart"] + (service.map { [$0] } ?? []))
        await refresh()
    }

    /// Remove containers AND data volumes (alerts, agents, config). Certificates kept.
    func reset() async {
        guard !busy else { return }
        busy = true; defer { busy = false; activity = "" }
        activity = "Removing containers and data…"
        _ = await compose(["down", "-v"])
        await refresh()
    }

    func logs(for service: String, tail: Int = 400) async -> String {
        guard let docker = dockerPath else { return "Docker not found" }
        let r = await Shell.run(docker, ["compose", "-p", composeProject, "logs", "--no-color", "--tail", "\(tail)", service], cwd: stackDir)
        return r.output
    }
}

/// TLS-tolerant reachability probe for the local self-signed endpoints.
enum Probe {
    final class TrustLocal: NSObject, URLSessionDelegate {
        func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
               ["localhost", "127.0.0.1"].contains(challenge.protectionSpace.host),
               let trust = challenge.protectionSpace.serverTrust {
                completionHandler(.useCredential, URLCredential(trust: trust))
            } else {
                completionHandler(.performDefaultHandling, nil)
            }
        }
    }

    static let session: URLSession = {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 3
        return URLSession(configuration: cfg, delegate: TrustLocal(), delegateQueue: nil)
    }()

    /// Any HTTP response (incl. 401) means the service is listening and speaking TLS.
    static func reachable(_ url: String) async -> Bool {
        guard let u = URL(string: url) else { return false }
        do {
            let (_, resp) = try await session.data(from: u)
            guard let code = (resp as? HTTPURLResponse)?.statusCode else { return false }
            return code < 500
        } catch { return false }
    }
}
