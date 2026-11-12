import Foundation

let managerContainer = "wazuh-mac-wazuh.manager-1"

struct AgentInfo: Identifiable {
    let id: String
    var name = ""
    var ip = ""
    var status = ""
    var os = ""
    var version = ""
    var lastKeepAlive: Date?
    var group = ""
    var synced: Bool?
    var fimLastScan = ""
    var hostname = ""

    var osFamily: AgentOS? {
        let o = os.lowercased()
        if o.contains("darwin") || o.contains("macos") { return .macOS }
        if o.contains("windows") { return .windows }
        if o.isEmpty { return nil }
        return .linux
    }
}

/// Manager-side operations: centralized agent configuration and agent status.
extension StackManager {
    var managerRunning: Bool { services.first { $0.id == "wazuh.manager" }?.isRunning == true }

    private func exec(_ args: [String]) async -> Shell.Result {
        guard let docker = dockerPath else { return Shell.Result(status: -1, output: "Docker not found") }
        return await Shell.run(docker, ["exec", managerContainer] + args)
    }

    func agentGroups() async -> [String] {
        let r = await exec(["/var/ossec/bin/agent_groups", "-l"])
        // Lines look like: "  default (1)"
        return r.output.split(separator: "\n").compactMap { line in
            let t = line.trimmingCharacters(in: .whitespaces)
            guard let paren = t.range(of: " (") , !t.hasPrefix("Groups") else { return nil }
            return String(t[..<paren.lowerBound])
        }
    }

    func readAgentConf(group: String) async -> String {
        await exec(["cat", "/var/ossec/etc/shared/\(group)/agent.conf"]).output
    }

    /// Validate with verify-agent-conf, back up the current file, then install. Agents in the group
    /// download the new configuration on their next keep-alive and restart themselves.
    func pushAgentConf(_ content: String, group: String) async -> (ok: Bool, message: String) {
        guard let docker = dockerPath, managerRunning else { return (false, "Start Wazuh first.") }
        guard group.range(of: "^[A-Za-z0-9._-]+$", options: .regularExpression) != nil else {
            return (false, "Group names may only contain letters, numbers, '.', '_' and '-'.")
        }
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("agent-\(UUID().uuidString).conf")
        do { try content.write(to: tmp, atomically: true, encoding: .utf8) } catch { return (false, error.localizedDescription) }
        defer { try? FileManager.default.removeItem(at: tmp) }

        let staged = "/tmp/wazuhmac-agent.conf"
        guard await Shell.run(docker, ["cp", tmp.path, "\(managerContainer):\(staged)"]).ok else {
            return (false, "Could not copy the configuration into the manager container.")
        }
        let verify = await exec(["/var/ossec/bin/verify-agent-conf", "-f", staged])
        guard verify.ok, !verify.output.contains("ERROR") else {
            return (false, "Wazuh rejected the configuration:\n" + verify.output)
        }
        if !(await agentGroups()).contains(group) {
            let mk = await exec(["/var/ossec/bin/agent_groups", "-a", "-g", group, "-q"])
            guard mk.ok else { return (false, "Could not create group '\(group)':\n" + mk.output) }
        }
        let dir = "/var/ossec/etc/shared/\(group)"
        let script = """
        set -e
        ts=$(date +%Y%m%d-%H%M%S)
        [ -f \(dir)/agent.conf ] && cp -p \(dir)/agent.conf \(dir)/agent.conf.bak-$ts
        cp \(staged) \(dir)/agent.conf
        chown wazuh:wazuh \(dir)/agent.conf
        chmod 660 \(dir)/agent.conf
        rm -f \(staged)
        echo "backup: agent.conf.bak-$ts"
        """
        let r = await exec(["sh", "-c", script])
        guard r.ok else { return (false, "Install failed:\n" + r.output) }
        append("Pushed scan configuration to agent group '\(group)' (\(r.output.trimmingCharacters(in: .whitespacesAndNewlines)))")
        return (true, "Applied to group “\(group)”. Agents in it pick this up within about a minute and restart themselves. Previous file kept as \(r.output.replacingOccurrences(of: "backup: ", with: "").trimmingCharacters(in: .whitespacesAndNewlines)).")
    }

    /// Wazuh 4.14 ships CIS benchmarks up to macOS 15 only. Copy the official macOS 15 policy into the
    /// group's shared folder with its version requirement relaxed to "any macOS", so newer Macs get SCA results.
    func installMacSCAPolicy(group: String) async -> (ok: Bool, message: String) {
        guard let docker = dockerPath else { return (false, "Docker not found") }
        let src = await exec(["sh", "-c", "cat /var/ossec/ruleset/sca/cis_apple_macOS_15.x.yml 2>/dev/null || cat /var/ossec/ruleset/sca/cis_apple_macOS_15.x.yml.disabled"])
        guard src.ok, src.output.contains("requirements:"), src.output.contains("checks:") else {
            return (false, "CIS macOS policy not found in the manager ruleset.")
        }
        var out: [String] = []
        var inRequirements = false
        for line in src.output.components(separatedBy: "\n") {
            if line.hasPrefix("requirements:") {
                inRequirements = true
                out += ["requirements:",
                        "  title: \"Check macOS platform (macOS 15 or later).\"",
                        "  description: \"CIS macOS 15 checks applied to newer macOS releases by Wazuh for macOS.\"",
                        "  condition: any",
                        "  rules:",
                        "    - 'c:sw_vers -> r:^ProductName:\\t*\\s*macOS'",
                        ""]
                continue
            }
            if inRequirements { if line.hasPrefix("checks:") { inRequirements = false } else { continue } }
            if line.hasPrefix("  id: ") { out.append("  id: \"cis_apple_macOS_latest\""); continue }
            if line.hasPrefix("  file: ") { out.append("  file: \"\(AgentConfig.macSCAPolicyFile)\""); continue }
            if line.hasPrefix("  name: \""), line.hasSuffix("\"") {
                out.append(String(line.dropLast()) + " (applied to macOS 15 and later)\""); continue
            }
            out.append(line)
        }
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("sca-\(UUID().uuidString).yml")
        do { try out.joined(separator: "\n").write(to: tmp, atomically: true, encoding: .utf8) } catch { return (false, error.localizedDescription) }
        defer { try? FileManager.default.removeItem(at: tmp) }
        let staged = "/tmp/\(AgentConfig.macSCAPolicyFile)"
        guard await Shell.run(docker, ["cp", tmp.path, "\(managerContainer):\(staged)"]).ok else { return (false, "Copy failed") }
        let dst = "/var/ossec/etc/shared/\(group)/\(AgentConfig.macSCAPolicyFile)"
        let r = await exec(["sh", "-c", "mv \(staged) \(dst) && chown wazuh:wazuh \(dst) && chmod 660 \(dst)"])
        return r.ok ? (true, "macOS CIS policy installed.") : (false, r.output)
    }

    func removeAgent(id: String) async -> Bool {
        guard id.range(of: "^[0-9]+$", options: .regularExpression) != nil else { return false }
        let r = await exec(["/var/ossec/bin/manage_agents", "-r", id])
        append("Removed agent \(id) from the server")
        return r.ok
    }

    func agents() async -> [AgentInfo] {
        guard managerRunning else { return [] }
        let list = await exec(["/var/ossec/bin/agent_control", "-l"]).output
        var result: [AgentInfo] = []
        for row in list.split(separator: "\n") where row.contains("ID:") && !row.contains("ID: 000") {
            let parts = row.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            guard parts.count >= 4 else { continue }
            var a = AgentInfo(id: parts[0].replacingOccurrences(of: "ID: ", with: ""))
            a.name = parts[1].replacingOccurrences(of: "Name: ", with: "")
            a.ip = parts[2].replacingOccurrences(of: "IP: ", with: "")
            a.status = parts[3...].joined(separator: ", ")
            result.append(a)
        }
        for i in result.indices.prefix(100) {
            let info = await exec(["/var/ossec/bin/agent_control", "-i", result[i].id]).output
            for line in info.split(separator: "\n") {
                let kv = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                guard kv.count == 2 else { continue }
                switch kv[0] {
                case "Operating system":
                    let f = kv[1].split(separator: "|").map { $0.trimmingCharacters(in: .whitespaces) }
                    result[i].os = f.first ?? kv[1]
                    if f.count > 1 { result[i].hostname = f[1] }
                case "Client version": result[i].version = kv[1]
                case "Syscheck last ended at": result[i].fimLastScan = kv[1]
                case "Last keep alive": if let t = TimeInterval(kv[1]), t > 0 { result[i].lastKeepAlive = Date(timeIntervalSince1970: t) }
                default: break
                }
            }
            let g = await exec(["/var/ossec/bin/agent_groups", "-s", "-i", result[i].id]).output
            if let r = g.range(of: "belongs to groups: ") {
                result[i].group = g[r.upperBound...].trimmingCharacters(in: .whitespacesAndNewlines).trimmingCharacters(in: CharacterSet(charactersIn: "."))
            }
            let s = await exec(["/var/ossec/bin/agent_groups", "-S", "-i", result[i].id]).output.lowercased()
            if s.contains("not synchronized") { result[i].synced = false }
            else if s.contains("synchronized") { result[i].synced = true }
        }
        return result
    }

    /// Evidence that each scan type has actually run for an agent (from the indexer and manager).
    func scanEvidence(_ a: AgentInfo) async -> [(label: String, ok: Bool, detail: String)] {
        func q(_ extra: String) -> String {
            "{\"query\":{\"bool\":{\"filter\":[{\"term\":{\"agent.id\":\"\(a.id)\"}}\(extra)]}}}"
        }
        let grp = { (g: String) in ",{\"term\":{\"rule.groups\":\"\(g)\"}}" }
        let pkgs = await Probe.indexerCount(index: "wazuh-states-inventory-packages-*", body: q("")) ?? 0
        let vulns = await Probe.indexerCount(index: "wazuh-states-vulnerabilities-*", body: q("")) ?? 0
        let sca = await Probe.indexerCount(index: "wazuh-alerts-*", body: q(grp("sca"))) ?? 0
        let rc = await Probe.indexerCount(index: "wazuh-alerts-*", body: q(grp("rootcheck"))) ?? 0
        let fim = await Probe.indexerCount(index: "wazuh-alerts-*", body: q(grp("syscheck"))) ?? 0
        return [
            ("File integrity (FIM)", !a.fimLastScan.isEmpty,
             a.fimLastScan.isEmpty ? "no scan completed yet" : "last scan \(a.fimLastScan) UTC, \(fim) change alert(s)"),
            ("Configuration assessment (SCA)", sca > 0, sca > 0 ? "\(sca) result(s)" : "no results yet (first scan runs on start)"),
            ("Rootkit / malware (rootcheck)", rc > 0, rc > 0 ? "\(rc) event(s)" : "no events yet"),
            ("System inventory", pkgs > 0, pkgs > 0 ? "\(pkgs) packages inventoried" : "no inventory yet"),
            ("Vulnerability detection", vulns > 0 || pkgs > 0, vulns > 0 ? "\(vulns) vulnerabilities found" : (pkgs > 0 ? "inventory received, none found yet" : "waiting for inventory")),
        ]
    }
}

extension Probe {
    /// Count documents in the local indexer (default single-node credentials).
    static func indexerCount(index: String, body: String) async -> Int? {
        guard let u = URL(string: "https://localhost:9200/\(index)/_count") else { return nil }
        var req = URLRequest(url: u)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("Basic " + Data("admin:SecretPassword".utf8).base64EncodedString(), forHTTPHeaderField: "Authorization")
        req.httpBody = Data(body.utf8)
        guard let (data, _) = try? await session.data(for: req),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return obj["count"] as? Int
    }
}
