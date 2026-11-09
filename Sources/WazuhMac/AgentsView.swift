import SwiftUI
import AppKit

/// Agent deployment: install commands, ossec.conf configuration, firewall rules and a live connection check.
struct AgentsView: View {
    @EnvironmentObject var stack: StackManager
    @State private var managerHost = AgentsView.primaryIPv4() ?? "127.0.0.1"
    @State private var agentName = ""
    @State private var group = "default"
    @State private var platform = Platform.macARM

    enum Platform: String, CaseIterable, Identifiable {
        case macARM = "macOS (Apple silicon)"
        case macIntel = "macOS (Intel)"
        case debAMD = "Linux DEB amd64"
        case debARM = "Linux DEB aarch64"
        case rpmAMD = "Linux RPM x86_64"
        case rpmARM = "Linux RPM aarch64"
        case windows = "Windows (PowerShell, admin)"
        var id: String { rawValue }
        var isMac: Bool { self == .macARM || self == .macIntel }
        var isLinux: Bool { !isMac && self != .windows }
    }

    // MARK: Commands

    var vars: String {
        var s = "WAZUH_MANAGER='\(managerHost)'"
        if !group.isEmpty { s += " WAZUH_AGENT_GROUP='\(group)'" }
        if !agentName.isEmpty { s += " WAZUH_AGENT_NAME='\(agentName)'" }
        return s
    }

    var install: String {
        let v = wazuhVersion
        switch platform {
        case .macARM, .macIntel:
            let arch = platform == .macARM ? "arm64" : "intel64"
            var env = "echo \"WAZUH_MANAGER='\(managerHost)'"
            if !group.isEmpty { env += " && WAZUH_AGENT_GROUP='\(group)'" }
            if !agentName.isEmpty { env += " && WAZUH_AGENT_NAME='\(agentName)'" }
            env += "\" > /tmp/wazuh_envs"
            return "curl -so wazuh-agent.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-\(v)-1.\(arch).pkg && \(env) && sudo installer -pkg ./wazuh-agent.pkg -target /"
        case .debAMD, .debARM:
            let arch = platform == .debAMD ? "amd64" : "arm64"
            return "wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_\(v)-1_\(arch).deb && sudo \(vars) dpkg -i ./wazuh-agent_\(v)-1_\(arch).deb"
        case .rpmAMD, .rpmARM:
            let arch = platform == .rpmAMD ? "x86_64" : "aarch64"
            return "curl -o wazuh-agent-\(v)-1.\(arch).rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-\(v)-1.\(arch).rpm && sudo \(vars) rpm -ihv wazuh-agent-\(v)-1.\(arch).rpm"
        case .windows:
            var args = "WAZUH_MANAGER='\(managerHost)'"
            if !group.isEmpty { args += " WAZUH_AGENT_GROUP='\(group)'" }
            if !agentName.isEmpty { args += " WAZUH_AGENT_NAME='\(agentName)'" }
            return "Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-\(v)-1.msi -OutFile $env:tmp\\wazuh-agent; msiexec.exe /i $env:tmp\\wazuh-agent /q \(args)"
        }
    }

    var startCmd: String {
        switch platform {
        case .macARM, .macIntel: "sudo /Library/Ossec/bin/wazuh-control start"
        case .windows: "NET START Wazuh"
        default: "sudo systemctl daemon-reload && sudo systemctl enable wazuh-agent && sudo systemctl start wazuh-agent"
        }
    }

    var confPath: String {
        switch platform {
        case .macARM, .macIntel: "/Library/Ossec/etc/ossec.conf"
        case .windows: "C:\\Program Files (x86)\\ossec-agent\\ossec.conf"
        default: "/var/ossec/etc/ossec.conf"
        }
    }

    var confSnippet: String {
        var enroll = "    <enrollment>\n      <enabled>yes</enabled>\n"
        if !agentName.isEmpty { enroll += "      <agent_name>\(agentName)</agent_name>\n" }
        if !group.isEmpty { enroll += "      <groups>\(group)</groups>\n" }
        enroll += "    </enrollment>\n"
        return """
        <ossec_config>
          <client>
            <server>
              <address>\(managerHost)</address>
              <port>1514</port>
              <protocol>tcp</protocol>
            </server>
        \(enroll)  </client>
        </ossec_config>
        """
    }

    /// One-liner that rewrites <address> in an already-installed agent and restarts it.
    var retargetCmd: String {
        switch platform {
        case .macARM, .macIntel:
            return "sudo sed -i '' 's|<address>[^<]*</address>|<address>\(managerHost)</address>|' \(confPath) && sudo /Library/Ossec/bin/wazuh-control restart"
        case .windows:
            return "$c='\(confPath)'; (Get-Content $c) -replace '<address>[^<]*</address>','<address>\(managerHost)</address>' | Set-Content $c; Restart-Service -Name wazuh"
        default:
            return "sudo sed -i 's|<address>[^<]*</address>|<address>\(managerHost)</address>|' \(confPath) && sudo systemctl restart wazuh-agent"
        }
    }

    var agentLogCmd: String {
        switch platform {
        case .macARM, .macIntel: "sudo tail -n 30 /Library/Ossec/logs/ossec.log"
        case .windows: "Get-Content 'C:\\Program Files (x86)\\ossec-agent\\ossec.log' -Tail 30"
        default: "sudo tail -n 30 /var/ossec/logs/ossec.log"
        }
    }

    var endpointFirewall: String {
        switch platform {
        case .macARM, .macIntel:
            "# Nothing to open: the macOS application firewall only filters inbound traffic.\n# Check reachability from the endpoint:\nnc -vz \(managerHost) 1514 && nc -vz \(managerHost) 1515"
        case .windows:
            "New-NetFirewallRule -DisplayName 'Wazuh agent' -Direction Outbound -Protocol TCP -RemotePort 1514,1515 -Action Allow\nTest-NetConnection \(managerHost) -Port 1514; Test-NetConnection \(managerHost) -Port 1515"
        default:
            "# ufw (Ubuntu/Debian) — only needed if outbound traffic is restricted\nsudo ufw allow out 1514:1515/tcp\n# firewalld (RHEL/Fedora) — only needed if outbound traffic is restricted\nsudo firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 -p tcp -m multiport --dports 1514,1515 -j ACCEPT && sudo firewall-cmd --reload\n# Check reachability\nnc -vz \(managerHost) 1514 && nc -vz \(managerHost) 1515"
        }
    }

    let serverFirewall = """
    # Allow Docker Desktop (which publishes Wazuh's ports) through the macOS firewall
    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /Applications/Docker.app/Contents/MacOS/com.docker.backend
    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp /Applications/Docker.app/Contents/MacOS/com.docker.backend
    # "Block all incoming connections" overrides the above — make sure it is off
    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall off
    """

    // MARK: View

    var body: some View {
        Form {
            Section("Agent settings") {
                LabeledContent("Wazuh server address") {
                    HStack {
                        TextField("", text: $managerHost).labelsHidden()
                        Button("This Mac (127.0.0.1)") { managerHost = "127.0.0.1" }
                            .help("Use when installing the agent on this same Mac. Never changes.")
                        Button("LAN IP") { managerHost = AgentsView.primaryIPv4() ?? managerHost }
                        Button("Hostname") { managerHost = AgentsView.localHostName() }
                            .help("Bonjour name: keeps working when DHCP changes this Mac's IP")
                    }
                }
                Text("Installing on this Mac? Use 127.0.0.1. For other machines, the hostname (\(AgentsView.localHostName())) keeps working when DHCP changes this Mac's IP; a raw LAN IP (\(AgentsView.primaryIPv4() ?? "unknown")) breaks if it changes.")
                    .font(.caption).foregroundStyle(.secondary)
                TextField("Agent name (optional)", text: $agentName)
                TextField("Group", text: $group)
                Picker("Operating system", selection: $platform) {
                    ForEach(Platform.allCases) { Text($0.rawValue).tag($0) }
                }
            }

            Section("1. Download and install the agent") { CommandBox(text: install) }
            Section("2. Start the agent") { CommandBox(text: startCmd) }

            Section {
                Text("The installer writes the server address into the agent's ossec.conf. If an agent was installed with the wrong address, or this Mac's IP changed, fix the <client> block and restart the agent.")
                    .font(.callout).foregroundStyle(.secondary)
                LabeledContent("File", value: confPath).font(.callout.monospaced())
                CommandBox(text: confSnippet)
                Text("Re-point an installed agent to the address above and restart it:").font(.callout)
                CommandBox(text: retargetCmd)
                Text("Agent log, for troubleshooting:").font(.callout)
                CommandBox(text: agentLogCmd)
            } header: { Text("3. Agent ossec.conf") }

            Section {
                PortTable()
                Text("On this Mac (Wazuh server)").font(.callout.weight(.semibold))
                FirewallStatus()
                CommandBox(text: serverFirewall)
                Text("On the endpoint (\(platform.rawValue))").font(.callout.weight(.semibold))
                CommandBox(text: endpointFirewall)
                Text("Routers, VPNs and cloud security groups between the endpoint and this Mac must also allow TCP 1514 and 1515.")
                    .font(.caption).foregroundStyle(.secondary)
            } header: { Text("4. Allow agent traffic") }

            Section("5. Connection check") { ConnectionCheck() }
        }
        .formStyle(.grouped)
        .navigationTitle("Deploy Agents")
    }

    // MARK: Helpers

    static func localHostName() -> String {
        let name = ProcessInfo.processInfo.hostName
        if name.hasSuffix(".local") { return name }
        let short = Host.current().localizedName?.replacingOccurrences(of: " ", with: "-") ?? name
        return short.hasSuffix(".local") ? short : "\(short).local"
    }

    static func primaryIPv4() -> String? {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return nil }
        defer { freeifaddrs(ifaddr) }
        var candidates: [(String, String)] = []
        for ptr in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let ifa = ptr.pointee
            guard let addr = ifa.ifa_addr, addr.pointee.sa_family == UInt8(AF_INET) else { continue }
            let name = String(cString: ifa.ifa_name)
            guard name.hasPrefix("en") else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(addr, socklen_t(addr.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                candidates.append((name, String(cString: host)))
            }
        }
        return candidates.sorted { $0.0 < $1.0 }.first?.1
    }
}

struct PortTable: View {
    let rows = [
        ("1514/tcp", "Agent → server", "Event and log data (required)"),
        ("1515/tcp", "Agent → server", "Agent enrollment (required for new agents)"),
        ("514/udp", "Device → server", "Syslog from network devices (optional)"),
        ("55000/tcp", "Admin → server", "Wazuh API (optional, remote admin only)"),
        ("443/tcp", "Browser → server", "Dashboard (optional, remote access only)"),
    ]
    var body: some View {
        Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 6) {
            ForEach(rows, id: \.0) { r in
                GridRow {
                    Text(r.0).font(.callout.monospaced())
                    Text(r.1).font(.callout)
                    Text(r.2).font(.callout).foregroundStyle(.secondary)
                }
            }
        }
    }
}

struct FirewallStatus: View {
    @State private var state = "Checking…"
    @State private var ok = true
    var body: some View {
        HStack {
            Image(systemName: ok ? "checkmark.shield" : "exclamationmark.shield").foregroundStyle(ok ? .green : .orange)
            Text(state).font(.callout)
        }
        .task {
            let fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
            let g = await Shell.run(fw, ["--getglobalstate"]).output
            let b = await Shell.run(fw, ["--getblockall"]).output
            if g.contains("disabled") {
                state = "macOS firewall is off. Agent ports are reachable; no change needed."; ok = true
            } else if b.contains("enabled") && !b.contains("disabled") {
                state = "macOS firewall is blocking ALL incoming connections. Agents cannot connect; run the commands below."; ok = false
            } else {
                state = "macOS firewall is on. Allow Docker Desktop with the commands below if agents cannot connect."; ok = false
            }
        }
    }
}

/// Live diagnostics: registered agents on the manager and agent connection attempts on this Mac.
struct ConnectionCheck: View {
    @EnvironmentObject var stack: StackManager
    @State private var lines: [(ok: Bool?, text: String)] = []
    @State private var agents = ""
    @State private var running = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Button { Task { await run() } } label: { Label("Run check", systemImage: "stethoscope") }
                    .disabled(running)
                if running { ProgressView().controlSize(.small) }
            }
            ForEach(Array(lines.enumerated()), id: \.offset) { _, l in
                HStack(alignment: .top) {
                    Image(systemName: l.ok == nil ? "info.circle" : (l.ok! ? "checkmark.circle.fill" : "xmark.octagon.fill"))
                        .foregroundStyle(l.ok == nil ? Color.secondary : (l.ok! ? Color.green : Color.red))
                    Text(l.text).font(.callout).textSelection(.enabled)
                }
            }
            if !agents.isEmpty {
                Text(agents).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
            }
        }
        .task { await run() }
    }

    func run() async {
        running = true; defer { running = false }
        var out: [(Bool?, String)] = []

        // 1. Server ports: actually connect, like an agent would.
        var open: [String] = [], closed: [String] = []
        for port in ["1514", "1515"] {
            let ok = await Shell.run("/usr/bin/nc", ["-z", "-G", "2", "127.0.0.1", port]).ok
            if ok { open.append(port) } else { closed.append(port) }
        }
        out.append(closed.isEmpty
            ? (true, "Server is accepting agent connections on 1514 and 1515.")
            : (false, "Server is not accepting connections on \(closed.joined(separator: ", ")). Start Wazuh (or wait for the manager to finish starting)."))

        // 2. Registered agents, as the manager sees them.
        var registered: [(id: String, name: String, status: String)] = []
        let docker = stack.dockerPath
        let managerUp = stack.services.first(where: { $0.id == "wazuh.manager" })?.isRunning == true
        if let docker, managerUp {
            let r = await Shell.run(docker, ["exec", "wazuh-mac-wazuh.manager-1", "/var/ossec/bin/agent_control", "-l"])
            for row in r.output.split(separator: "\n") where row.contains("ID:") && !row.contains("ID: 000") {
                let parts = row.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                guard parts.count >= 4 else { continue }
                registered.append((id: parts[0].replacingOccurrences(of: "ID: ", with: ""),
                                   name: parts[1].replacingOccurrences(of: "Name: ", with: ""),
                                   status: parts[3...].joined(separator: ", ")))
            }
        }

        // 3. This Mac's own agent: find it on the manager by hostname.
        if FileManager.default.fileExists(atPath: "/Library/Ossec") {
            let agentProc = await Shell.run("/usr/bin/pgrep", ["-x", "wazuh-agentd"]).ok
            out.append((agentProc, agentProc ? "Wazuh agent is installed and running on this Mac."
                                             : "Wazuh agent is installed on this Mac but not running. Start it with section 2."))
            if agentProc, let docker, managerUp {
                let host = ProcessInfo.processInfo.hostName.lowercased()
                let shortHost = host.components(separatedBy: ".").first ?? host
                var match: (id: String, name: String, status: String)?
                for a in registered.prefix(50) {
                    let info = await Shell.run(docker, ["exec", "wazuh-mac-wazuh.manager-1", "/var/ossec/bin/agent_control", "-i", a.id]).output.lowercased()
                    if info.contains(shortHost) { match = a; break }
                }
                if let m = match {
                    if m.status.hasPrefix("Active") {
                        out.append((true, "This Mac's agent is connected as “\(m.name)” (ID \(m.id))."))
                    } else {
                        out.append((false, "This Mac's agent is enrolled as “\(m.name)” but is \(m.status). Re-point it to 127.0.0.1 with the command in section 3."))
                    }
                } else {
                    out.append((false, "This Mac's agent is not connected to this server. It is probably pointed at another address; re-point it to 127.0.0.1 with the command in section 3, then run the check again."))
                }
            }
        } else {
            out.append((nil, "No Wazuh agent installed on this Mac."))
        }

        if managerUp {
            out.append((registered.isEmpty ? false : true,
                        registered.isEmpty ? "No agents have enrolled with the server yet." : "\(registered.count) agent(s) registered with the server:"))
            agents = registered.map { "ID \($0.id)  \($0.name)  —  \($0.status)" }.joined(separator: "\n")
        } else {
            agents = ""
        }
        lines = out.map { (ok: $0.0, text: $0.1) }
    }
}


struct CommandBox: View {
    let text: String
    @State private var copied = false
    var body: some View {
        HStack(alignment: .top) {
            Text(text)
                .font(.system(.callout, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
            Button {
                NSPasteboard.general.clearContents(); NSPasteboard.general.setString(text, forType: .string)
                copied = true
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
            } label: { Label(copied ? "Copied" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc") }
        }
        .padding(8)
        .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }
}
