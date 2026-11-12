import SwiftUI
import AppKit

/// Guided agent setup: one numbered step at a time, each a single paste-safe command.
struct AgentsView: View {
    @EnvironmentObject var stack: StackManager

    enum Target: String, CaseIterable, Identifiable {
        case thisMac = "This Mac"
        case other = "Another computer"
        var id: String { rawValue }
    }

    @State private var target = Target.thisMac
    @State private var os = TargetOS.macOS
    @State private var manager = "127.0.0.1"
    @State private var agentName = ""
    @State private var group = "default"

    var cmds: AgentCommands { AgentCommands(os: os, manager: manager, name: agentName, group: group) }
    var onThisMac: Bool { target == .thisMac }
    /// The name the agent will register under (empty = unknown hostname of another computer).
    var expectedName: String {
        if !agentName.isEmpty { return agentName }
        return onThisMac ? ProcessInfo.processInfo.hostName : ""
    }

    var body: some View {
        Form {
            Section {
                Text("Follow the steps in order. Each **Copy** button copies one complete command: paste it into \(os.shell) and press Return. Commands that need administrator rights ask for your password. Every step is safe to run again.")
                    .font(.callout)
                if onThisMac {
                    Text("Installing on this Mac: you can also press **Run on this Mac** to run a step directly. macOS asks for your administrator password.")
                        .font(.callout).foregroundStyle(.secondary)
                }
            }

            Section("Agent settings") {
                Picker("Install the agent on", selection: $target) {
                    ForEach(Target.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .onChange(of: target) {
                    if target == .thisMac { os = .macOS; manager = "127.0.0.1" }
                    else { manager = AgentsView.localHostName() }
                }
                if !onThisMac {
                    Picker("Operating system", selection: $os) {
                        ForEach(TargetOS.allCases) { Text($0.rawValue).tag($0) }
                    }
                }
                LabeledContent("Wazuh server address") {
                    HStack {
                        TextField("", text: $manager).labelsHidden().disabled(onThisMac)
                        if !onThisMac {
                            Button("Hostname") { manager = AgentsView.localHostName() }
                                .help("This Mac's Bonjour name: keeps working when DHCP changes its IP")
                            Button("LAN IP") { manager = AgentsView.primaryIPv4() ?? manager }
                        }
                    }
                }
                Text(onThisMac
                     ? "The agent on this Mac talks to the server on this Mac, so 127.0.0.1 always works, even if your IP changes."
                     : "The other computer must reach this Mac at this address on TCP 1514 and 1515. The hostname \(AgentsView.localHostName()) survives IP changes; the LAN IP \(AgentsView.primaryIPv4() ?? "—") stops working if your router assigns a new one.")
                    .font(.caption).foregroundStyle(.secondary)
                TextField("Agent name (optional)", text: $agentName, prompt: Text(onThisMac ? ProcessInfo.processInfo.hostName : "the computer's hostname"))
                TextField("Agent group", text: $group, prompt: Text("default"))
                if !cmds.valid {
                    Label("Use only letters, numbers, dots, dashes and underscores in the address, name and group.", systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange).font(.callout)
                }
            }

            Section {
                StepText("Do this once on the server. Every agent in group “\(cmds.groupOrDefault)”, now and in the future, receives the full scan configuration automatically when it connects.")
                ScansSection(group: $group)
            } header: { StepHeader(n: 1, title: "Turn on all scans on the server") }

            Section {
                StepText("Removes any existing Wazuh agent with all its old settings and keys. If none is installed it does nothing.")
                CommandBox(text: cmds.uninstall, runOnMac: onThisMac)
                StepText("The server also refuses a new agent whose name is still registered. Remove the old registration of this computer if it is listed:")
                RegistrationList(highlightName: expectedName, matchThisMac: onThisMac)
            } header: { StepHeader(n: 2, title: "Remove any previous agent (clean install)") }

            Section {
                StepText("Downloads the official Wazuh \(wazuhVersion) agent for this \(os == .macOS ? "Mac (Apple silicon or Intel is detected automatically)" : "system (the processor type is detected automatically)") and installs it, pointed at \(manager) in group “\(cmds.groupOrDefault)”.")
                CommandBox(text: cmds.install, runOnMac: onThisMac)
            } header: { StepHeader(n: 3, title: "Download and install the agent") }

            Section {
                StepText("Lets the agent run the configuration-assessment (CIS) policies the server sends. On macOS 15 and later this is how the CIS benchmark reaches the agent.")
                CommandBox(text: cmds.allowServerPolicies, runOnMac: onThisMac)
            } header: { StepHeader(n: 4, title: "Allow the server's scan policies") }

            Section {
                StepText("Starts the agent. After 20 seconds it prints the result: “Valid key received” and “Connected to the server” mean success.")
                CommandBox(text: cmds.start, runOnMac: onThisMac)
                LiveEnrollment(expectedName: expectedName)
            } header: { StepHeader(n: 5, title: "Start the agent and connect") }

            Section {
                StepText("Scans start right away. Inventory and vulnerabilities appear within a few minutes, and the CIS assessment within about 10 minutes. Expand the agent to see each scan type.")
                AgentsCheck()
            } header: { StepHeader(n: 6, title: "Check that every scan is running") }

            Section("Troubleshooting") {
                Troubleshooting(cmds: cmds, onThisMac: onThisMac)
            }
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

struct StepHeader: View {
    let n: Int, title: String
    var body: some View {
        HStack(spacing: 8) {
            Text("\(n)").font(.callout.weight(.bold)).foregroundStyle(.white)
                .frame(width: 22, height: 22).background(wazuhBlue, in: Circle())
            Text(title).font(.headline)
        }
    }
}

struct StepText: View {
    let s: String
    init(_ s: String) { self.s = s }
    var body: some View { Text(s).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true) }
}

/// Server-side registrations, with removal (needed before re-installing under the same name).
struct RegistrationList: View {
    @EnvironmentObject var stack: StackManager
    let highlightName: String
    let matchThisMac: Bool
    @State private var agents: [AgentInfo] = []
    @State private var toRemove: AgentInfo?
    @State private var message = ""

    func isMatch(_ a: AgentInfo) -> Bool {
        if !highlightName.isEmpty && a.name.caseInsensitiveCompare(highlightName) == .orderedSame { return true }
        if matchThisMac {
            let host = ProcessInfo.processInfo.hostName.lowercased().components(separatedBy: ".").first ?? ""
            return a.osFamily == .macOS && a.hostname.lowercased().hasPrefix(host) && !host.isEmpty
        }
        return false
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if !stack.managerRunning {
                Label("Start Wazuh to see registered agents.", systemImage: "info.circle").font(.callout).foregroundStyle(.secondary)
            } else if agents.isEmpty {
                Label("No agents are registered. Nothing to remove.", systemImage: "checkmark.circle.fill").font(.callout).foregroundStyle(.green)
            }
            ForEach(agents) { a in
                HStack {
                    Circle().fill(a.status.hasPrefix("Active") ? .green : .secondary).frame(width: 8, height: 8)
                    Text(a.name).font(.callout.weight(isMatch(a) ? .semibold : .regular))
                    Text("ID \(a.id) · \(a.status)\(a.os.isEmpty ? "" : " · \(a.os)")").font(.caption).foregroundStyle(.secondary)
                    if isMatch(a) {
                        Text(matchThisMac ? "this Mac" : "same name").font(.caption2)
                            .padding(.horizontal, 5).padding(.vertical, 1).background(.orange.opacity(0.2), in: Capsule())
                    }
                    Spacer()
                    Button("Remove", role: .destructive) { toRemove = a }.controlSize(.small)
                }
            }
            if !message.isEmpty { Text(message).font(.caption).foregroundStyle(.secondary) }
        }
        .task(id: stack.managerRunning) { agents = await stack.agents() }
        .confirmationDialog("Remove “\(toRemove?.name ?? "")” (ID \(toRemove?.id ?? "")) from the server?",
                            isPresented: Binding(get: { toRemove != nil }, set: { if !$0 { toRemove = nil } })) {
            Button("Remove", role: .destructive) {
                guard let a = toRemove else { return }
                Task {
                    let ok = await stack.removeAgent(id: a.id)
                    message = ok ? "Removed \(a.name) (ID \(a.id))." : "Could not remove \(a.name)."
                    agents = await stack.agents()
                }
            }
        } message: { Text("Its key is deleted. Past alerts stay in the indexer.") }
    }
}

/// Watches the server until the agent being installed shows up and connects.
struct LiveEnrollment: View {
    @EnvironmentObject var stack: StackManager
    let expectedName: String
    @State private var baseline: Set<String>?
    @State private var found: AgentInfo?

    var body: some View {
        HStack(spacing: 8) {
            if let a = found, a.status.hasPrefix("Active") {
                Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                Text("“\(a.name)” (ID \(a.id)) is connected to the server.").font(.callout)
            } else if let a = found {
                ProgressView().controlSize(.small)
                Text("“\(a.name)” (ID \(a.id)) is registered: \(a.status). Waiting for it to connect…").font(.callout)
            } else if stack.managerRunning {
                ProgressView().controlSize(.small)
                Text(expectedName.isEmpty ? "Waiting for a new agent to register…" : "Waiting for “\(expectedName)” to register…")
                    .font(.callout).foregroundStyle(.secondary)
            } else {
                Image(systemName: "info.circle").foregroundStyle(.secondary)
                Text("Start Wazuh to watch the agent connect.").font(.callout).foregroundStyle(.secondary)
            }
        }
        .task {
            while !Task.isCancelled {
                let list = await stack.agents()
                if baseline == nil { baseline = Set(list.filter { !$0.status.hasPrefix("Active") }.map(\.id)) }
                if !expectedName.isEmpty {
                    found = list.last { $0.name.caseInsensitiveCompare(expectedName) == .orderedSame }
                } else {
                    found = list.last { !(baseline ?? []).contains($0.id) }
                }
                try? await Task.sleep(nanoseconds: 4_000_000_000)
            }
        }
    }
}

struct Troubleshooting: View {
    let cmds: AgentCommands
    let onThisMac: Bool
    @State private var opts = ScanOptions()

    var body: some View {
        DisclosureGroup("The agent does not connect") {
            VStack(alignment: .leading, spacing: 8) {
                StepText("Which server address is the agent using?")
                CommandBox(text: cmds.serverAddressInConfig, runOnMac: onThisMac)
                StepText("Point the agent at \(cmds.manager) and restart it:")
                CommandBox(text: cmds.repoint, runOnMac: onThisMac)
                StepText("Can this computer reach the server's agent ports?")
                CommandBox(text: cmds.reachability, runOnMac: false)
                if let fw = cmds.endpointFirewall {
                    StepText("Allow outgoing agent traffic on the endpoint (only needed if outbound traffic is restricted):")
                    CommandBox(text: fw, runOnMac: false)
                }
                StepText("On this Mac (the server): agents connect to TCP 1514 (events) and 1515 (enrollment).")
                PortTable()
                FirewallStatus()
                StepText("If the macOS firewall blocks agents, allow Docker Desktop, which publishes the Wazuh ports:")
                CommandBox(text: "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /Applications/Docker.app/Contents/MacOS/com.docker.backend && sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp /Applications/Docker.app/Contents/MacOS/com.docker.backend && sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall off", runOnMac: true)
                StepText("Routers, VPNs and cloud security groups between the endpoint and this Mac must also allow TCP 1514 and 1515.")
            }.padding(.top, 4)
        }
        DisclosureGroup("“Duplicate agent name” or “Invalid ID” in the agent log") {
            VStack(alignment: .leading, spacing: 8) {
                StepText("Remove the old registration in step 2, then make the agent enroll again:")
                CommandBox(text: cmds.reenroll, runOnMac: onThisMac)
            }.padding(.top, 4)
        }
        DisclosureGroup("Agent status, log and scan modules") {
            VStack(alignment: .leading, spacing: 8) {
                StepText("Agent processes:")
                CommandBox(text: cmds.status, runOnMac: onThisMac)
                StepText("Scan modules that started:")
                CommandBox(text: cmds.modulesStarted, runOnMac: onThisMac)
                StepText("Last 40 lines of the agent log:")
                CommandBox(text: cmds.logTail, runOnMac: onThisMac)
            }.padding(.top, 4)
        }
        DisclosureGroup("Configure scans on one agent instead of from the server") {
            VStack(alignment: .leading, spacing: 8) {
                StepText("Writes the same scan settings into this agent's own ossec.conf and restarts it. Use this only for an agent that is not in a group configured in step 1; settings from the server take precedence. Running it again replaces the block instead of adding a second copy.")
                CommandBox(text: cmds.localScans(opts), display: "\(cmds.os == .windows ? "$f=…" : "sudo sed …") (writes \(cmds.confPath), then restarts the agent)", runOnMac: onThisMac)
            }.padding(.top, 4)
        }
        DisclosureGroup("Optional: osquery") {
            VStack(alignment: .leading, spacing: 8) {
                StepText("The osquery scan option in step 1 needs osquery installed on the endpoint:")
                CommandBox(text: cmds.osqueryInstall, runOnMac: false)
            }.padding(.top, 4)
        }
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
                state = "macOS firewall is blocking ALL incoming connections. Agents cannot connect; run the command below."; ok = false
            } else {
                state = "macOS firewall is on. Run the command below if agents cannot connect."; ok = false
            }
        }
    }
}

/// One command: shown, copied exactly, and optionally run on this Mac with administrator rights.
struct CommandBox: View {
    let text: String
    var display: String? = nil
    var runOnMac = false
    @State private var copied = false
    @State private var running = false
    @State private var output: (ok: Bool, text: String)?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .top) {
                Text(display ?? text)
                    .font(.system(.callout, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .fixedSize(horizontal: false, vertical: true)
                VStack(alignment: .trailing, spacing: 6) {
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(text, forType: .string)
                        copied = true
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
                    } label: { Label(copied ? "Copied" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc").frame(minWidth: 70) }
                    if runOnMac {
                        Button {
                            Task {
                                running = true
                                output = await AdminRunner.run(text)
                                running = false
                            }
                        } label: {
                            if running { ProgressView().controlSize(.small).frame(minWidth: 120) }
                            else { Label("Run on this Mac", systemImage: "play.fill") }
                        }
                        .disabled(running)
                    }
                }
            }
            if let o = output {
                Text(o.text.ifEmpty(o.ok ? "Done." : "Failed."))
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(o.ok ? Color.primary : Color.red)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
                    .background((o.ok ? Color.green : Color.red).opacity(0.08), in: RoundedRectangle(cornerRadius: 6))
            }
        }
        .padding(8)
        .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }
}

/// Runs a command as administrator via the standard macOS password prompt.
enum AdminRunner {
    static func run(_ command: String) async -> (ok: Bool, text: String) {
        let dir = FileManager.default.temporaryDirectory
        let script = dir.appendingPathComponent("wazuhmac-step-\(UUID().uuidString).sh")
        // zsh, like Terminal, so the command behaves exactly as when pasted.
        let body = "#!/bin/zsh\nexport PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin\ncd /tmp\n\(command)\n"
        do { try body.write(to: script, atomically: true, encoding: .utf8) } catch { return (false, error.localizedDescription) }
        defer { try? FileManager.default.removeItem(at: script) }
        let apple = "do shell script \"/bin/zsh \(script.path) 2>&1\" with administrator privileges"
        let r = await Shell.run("/usr/bin/osascript", ["-e", apple], timeout: 900)
        var text = r.output.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.contains("User canceled") || text.contains("(-128)") { return (false, "Cancelled.") }
        if !r.ok, let range = text.range(of: "execution error: ") { text = String(text[range.upperBound...]) }
        return (r.ok, text)
    }
}
