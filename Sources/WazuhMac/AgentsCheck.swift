import SwiftUI

/// Connection and scan check for this server, this Mac's agent, and every registered agent (any OS).
struct AgentsCheck: View {
    @EnvironmentObject var stack: StackManager
    @State private var serverLines: [(ok: Bool?, text: String)] = []
    @State private var agents: [AgentInfo] = []
    @State private var localAgentID: String?
    @State private var running = false
    @State private var lastRun: Date?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Button { Task { await run() } } label: { Label("Run check", systemImage: "stethoscope") }
                    .disabled(running)
                if running { ProgressView().controlSize(.small) }
                Spacer()
                if let lastRun { Text("Checked \(lastRun.formatted(date: .omitted, time: .standard))").font(.caption).foregroundStyle(.secondary) }
            }
            ForEach(Array(serverLines.enumerated()), id: \.offset) { _, l in StatusLine(ok: l.ok, text: l.text) }
            if stack.managerRunning {
                Text(agents.isEmpty ? "No agents registered yet." : "Registered agents (\(agents.count))")
                    .font(.callout.weight(.semibold)).padding(.top, 4)
                ForEach(agents) { a in AgentRow(agent: a, isThisMac: a.id == localAgentID) { await run() } }
            }
        }
        .task { await run() }
    }

    func run() async {
        running = true; defer { running = false; lastRun = Date() }
        var out: [(Bool?, String)] = []

        var closed: [String] = []
        for port in ["1514", "1515"] where !(await Shell.run("/usr/bin/nc", ["-z", "-G", "2", "127.0.0.1", port]).ok) {
            closed.append(port)
        }
        out.append(closed.isEmpty
            ? (true, "Server is accepting agent connections on 1514 (events) and 1515 (enrollment).")
            : (false, "Server is not accepting connections on \(closed.joined(separator: ", ")). Start Wazuh, or wait for the manager to finish starting."))

        let list = await stack.agents()
        localAgentID = nil
        if FileManager.default.fileExists(atPath: "/Library/Ossec") {
            let running = await Shell.run("/usr/bin/pgrep", ["-x", "wazuh-agentd"]).ok
            if !running {
                out.append((false, "This Mac's agent is installed but not running. Start it with: sudo /Library/Ossec/bin/wazuh-control start"))
            } else {
                let host = (ProcessInfo.processInfo.hostName.lowercased().components(separatedBy: ".").first) ?? ""
                if let m = await matchLocal(list, host: host) {
                    localAgentID = m.id
                    out.append(m.status.hasPrefix("Active")
                        ? (true, "This Mac's agent is connected as “\(m.name)” (ID \(m.id)).")
                        : (false, "This Mac's agent is enrolled as “\(m.name)” but is \(m.status). Re-point it to 127.0.0.1 (Troubleshooting)."))
                } else {
                    out.append((false, "This Mac's agent is running but not connected to this server. It is probably pointed at another address; re-point it to 127.0.0.1 (Troubleshooting)."))
                }
            }
        }
        serverLines = out.map { (ok: $0.0, text: $0.1) }
        agents = list
    }

    private func matchLocal(_ list: [AgentInfo], host: String) async -> AgentInfo? {
        guard let docker = stack.dockerPath, !host.isEmpty else { return nil }
        for a in list where a.osFamily == .macOS || a.os.isEmpty {
            let info = await Shell.run(docker, ["exec", managerContainer, "/var/ossec/bin/agent_control", "-i", a.id]).output.lowercased()
            if info.contains(host) { return a }
        }
        return nil
    }
}

struct StatusLine: View {
    let ok: Bool?; let text: String
    var body: some View {
        HStack(alignment: .top) {
            Image(systemName: ok == nil ? "info.circle" : (ok! ? "checkmark.circle.fill" : "xmark.octagon.fill"))
                .foregroundStyle(ok == nil ? Color.secondary : (ok! ? Color.green : Color.red))
            Text(text).font(.callout).textSelection(.enabled)
        }
    }
}

struct AgentRow: View {
    @EnvironmentObject var stack: StackManager
    let agent: AgentInfo
    let isThisMac: Bool
    let refresh: () async -> Void
    @State private var expanded = false
    @State private var evidence: [(label: String, ok: Bool, detail: String)] = []
    @State private var confirmRemove = false

    var color: Color {
        if agent.status.hasPrefix("Active") { return agent.synced == false ? .orange : .green }
        if agent.status.hasPrefix("Pending") { return .orange }
        return .red
    }

    var advice: String? {
        let os = agent.osFamily?.label ?? "endpoint"
        if agent.status.hasPrefix("Active") {
            return agent.synced == false ? "Connected; it has not downloaded the latest group configuration yet (happens on the next keep-alive, within about a minute)." : nil
        }
        if agent.status.hasPrefix("Never connected") {
            return "It enrolled on 1515 but has never sent events on 1514. Usually the server address in the agent's ossec.conf is wrong, or TCP 1514 is blocked. Check the server address and firewall under Troubleshooting → “The agent does not connect”."
        }
        if agent.status.hasPrefix("Disconnected") {
            return "It was connected before, but now the agent is stopped or cannot reach this Mac on TCP 1514. Did this Mac's IP change? See Troubleshooting → “The agent does not connect” for the \(os) commands to check and fix it."
        }
        if agent.status.hasPrefix("Pending") { return "Handshake in progress. Check again in a few seconds." }
        return nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 10) {
                Circle().fill(color).frame(width: 9, height: 9)
                Image(systemName: icon).frame(width: 18)
                Text("\(agent.name)").font(.callout.weight(.semibold))
                if isThisMac { Text("this Mac").font(.caption2).padding(.horizontal, 5).padding(.vertical, 1).background(.blue.opacity(0.15), in: Capsule()) }
                Text("ID \(agent.id)").font(.caption.monospaced()).foregroundStyle(.secondary)
                Spacer()
                Text(agent.status).font(.callout)
                Button { expanded.toggle() } label: { Image(systemName: expanded ? "chevron.up" : "chevron.down") }
                    .buttonStyle(.borderless).help("Show details and scan status")
            }
            HStack(spacing: 14) {
                Text(agent.os.ifEmpty("OS not reported yet"))
                Text(agent.version.ifEmpty("—"))
                Text("group: \(agent.group.ifEmpty("—"))")
                if let s = agent.synced { Text(s ? "config synced" : "config not synced") }
                if let k = agent.lastKeepAlive { Text("last seen \(k.formatted(.relative(presentation: .named)))") }
            }
            .font(.caption).foregroundStyle(.secondary)
            if let advice { Text(advice).font(.caption).foregroundStyle(.red) }
            if expanded {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Scan status").font(.caption.weight(.semibold))
                    if evidence.isEmpty { ProgressView().controlSize(.small) }
                    ForEach(evidence, id: \.label) { e in
                        HStack {
                            Image(systemName: e.ok ? "checkmark.circle.fill" : "clock").foregroundStyle(e.ok ? .green : .secondary)
                            Text(e.label).font(.caption).frame(width: 210, alignment: .leading)
                            Text(e.detail).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    HStack {
                        Spacer()
                        Button("Remove agent from server…", role: .destructive) { confirmRemove = true }.controlSize(.small)
                    }
                }
                .padding(.leading, 28)
                .task { evidence = await stack.scanEvidence(agent) }
            }
        }
        .padding(10)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10))
        .confirmationDialog("Remove agent “\(agent.name)” (ID \(agent.id))?", isPresented: $confirmRemove) {
            Button("Remove", role: .destructive) {
                Task {
                    _ = await stack.removeAgent(id: agent.id)
                    await refresh()
                }
            }
        } message: { Text("Deletes its key from the server. The endpoint must re-enroll to come back (Troubleshooting). Its past alerts stay in the indexer.") }
    }

    var icon: String {
        switch agent.osFamily {
        case .macOS: "apple.logo"
        case .windows: "pc"
        case .linux: "terminal"
        case nil: "questionmark.circle"
        }
    }
}
