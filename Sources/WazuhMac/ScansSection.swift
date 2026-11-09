import SwiftUI
import AppKit

/// "Enable all scans": push centralized config to an agent group, or configure one agent by hand.
struct ScansSection: View {
    @EnvironmentObject var stack: StackManager
    @Binding var group: String
    let os: AgentOS

    @State private var opts = ScanOptions()
    @State private var applying = false
    @State private var result: (ok: Bool, message: String)?
    @State private var currentConf = ""
    @State private var showCurrent = false
    @State private var showXML = false
    @State private var confirmReset = false

    var targetGroup: String { group.isEmpty ? "default" : group }

    var body: some View {
        Group {
            Text("Turns on every Wazuh agent capability: file integrity monitoring, rootkit and malware detection, CIS configuration assessment, full system inventory (which feeds vulnerability detection), and security log collection. Vulnerability detection itself runs on the server and is already on.")
                .font(.callout).foregroundStyle(.secondary)

            Grid(alignment: .leading, horizontalSpacing: 24, verticalSpacing: 6) {
                GridRow {
                    Toggle("File integrity monitoring", isOn: $opts.fim)
                    Toggle("Real-time FIM (Linux, Windows)", isOn: $opts.fimRealtime).disabled(!opts.fim)
                }
                GridRow {
                    Toggle("Record diffs of changed config files", isOn: $opts.fimReportChanges).disabled(!opts.fim)
                    Toggle("Windows registry monitoring", isOn: $opts.registry).disabled(!opts.fim)
                }
                GridRow {
                    Toggle("Rootkit & malware detection", isOn: $opts.rootcheck)
                    Toggle("Security configuration assessment (CIS)", isOn: $opts.sca)
                }
                GridRow {
                    Toggle("System inventory + vulnerability detection", isOn: $opts.inventory)
                    Toggle("Security log collection", isOn: $opts.logs)
                }
                GridRow {
                    Toggle("osquery (needs osquery installed)", isOn: $opts.osquery)
                    Toggle("Docker events (Linux, needs Docker)", isOn: $opts.docker)
                }
            }
            .toggleStyle(.checkbox)

            // Centralized, recommended.
            VStack(alignment: .leading, spacing: 8) {
                Text("Recommended: apply from this server").font(.callout.weight(.semibold))
                Text("Writes one configuration with separate macOS, Linux and Windows blocks to group “\(targetGroup)” (agents join “default” unless a group was set). Every agent in the group, current and future, picks it up within about a minute and restarts itself. Wazuh validates the file before it is installed, and the previous version is backed up.")
                    .font(.caption).foregroundStyle(.secondary)
                HStack {
                    Button {
                        Task {
                            applying = true
                            result = await stack.pushAgentConf(AgentConfig.agentConf(opts), group: targetGroup)
                            if result?.ok == true, opts.sca {
                                let p = await stack.installMacSCAPolicy(group: targetGroup)
                                if !p.ok { result = (false, "Scans enabled, but the macOS CIS policy could not be installed: \(p.message)") }
                            }
                            applying = false
                            if showCurrent { currentConf = await stack.readAgentConf(group: targetGroup) }
                        }
                    } label: { Label("Enable scans on all agents in “\(targetGroup)”", systemImage: "bolt.shield") }
                        .buttonStyle(.borderedProminent).tint(wazuhBlue)
                        .disabled(applying || !stack.managerRunning)
                    if applying { ProgressView().controlSize(.small) }
                    Spacer()
                    Button("Reset group to empty…") { confirmReset = true }
                        .disabled(applying || !stack.managerRunning)
                }
                if let r = result {
                    Label(r.message, systemImage: r.ok ? "checkmark.circle.fill" : "xmark.octagon.fill")
                        .foregroundStyle(r.ok ? .green : .red).font(.callout).textSelection(.enabled)
                }
                DisclosureGroup("Show the configuration that will be pushed", isExpanded: $showXML) {
                    CommandBox(text: AgentConfig.agentConf(opts))
                }
                DisclosureGroup("Show group “\(targetGroup)” agent.conf currently on the server", isExpanded: $showCurrent) {
                    CommandBox(text: currentConf.ifEmpty("(loading…)"))
                }
                .onChange(of: showCurrent) { if showCurrent { Task { currentConf = await stack.readAgentConf(group: targetGroup) } } }
            }

            if opts.sca {
                VStack(alignment: .leading, spacing: 8) {
                    Text("macOS agents: CIS assessment on newer macOS").font(.callout.weight(.semibold))
                    Text("Wazuh 4.14 has CIS benchmarks only up to macOS 15, so the push also distributes the official macOS 15 benchmark adapted to run on newer macOS. If a Mac agent still shows no configuration assessment results after a few minutes (scan status in section 7), allow server-sent policies on that Mac once:")
                        .font(.caption).foregroundStyle(.secondary)
                    CommandBox(text: "echo 'sca.remote_commands=1' | sudo tee -a /Library/Ossec/etc/local_internal_options.conf > /dev/null && sudo /Library/Ossec/bin/wazuh-control restart")
                }
            }

            // Manual, per agent.
            VStack(alignment: .leading, spacing: 8) {
                Text("Or configure one \(os.label) agent by hand").font(.callout.weight(.semibold))
                Text("Run on the endpoint. It appends the block to the agent's ossec.conf and restarts the agent. Settings pushed from the server take precedence over local ones.")
                    .font(.caption).foregroundStyle(.secondary)
                CommandBox(text: manualCommand)
                if opts.osquery {
                    Text("Install osquery on the endpoint first:").font(.caption)
                    CommandBox(text: osqueryInstall)
                }
            }
        }
        .confirmationDialog("Reset agent.conf for “\(targetGroup)”?", isPresented: $confirmReset) {
            Button("Reset", role: .destructive) {
                Task {
                    applying = true
                    result = await stack.pushAgentConf("<agent_config>\n\n  <!-- Shared agent configuration here -->\n\n</agent_config>\n", group: targetGroup)
                    applying = false
                }
            }
        } message: { Text("Agents go back to their local ossec.conf settings. The current file is backed up.") }
    }

    var manualCommand: String {
        let xml = AgentConfig.localConf(os, opts)
        switch os {
        case .macOS:
            return "sudo tee -a /Library/Ossec/etc/ossec.conf > /dev/null <<'EOF'\n\(xml)EOF\nsudo /Library/Ossec/bin/wazuh-control restart"
        case .linux:
            return "sudo tee -a /var/ossec/etc/ossec.conf > /dev/null <<'EOF'\n\(xml)EOF\nsudo systemctl restart wazuh-agent"
        case .windows:
            return "# PowerShell (Run as Administrator)\n$x = @'\n\(xml)'@\nAdd-Content -Path 'C:\\Program Files (x86)\\ossec-agent\\ossec.conf' -Value $x\nRestart-Service -Name wazuh"
        }
    }

    var osqueryInstall: String {
        switch os {
        case .macOS: "brew install --cask osquery"
        case .linux: "# Debian/Ubuntu\ncurl -fsSL https://pkg.osquery.io/deb/pubkey.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/osquery.gpg\necho 'deb [arch=amd64 signed-by=/etc/apt/keyrings/osquery.gpg] https://pkg.osquery.io/deb deb main' | sudo tee /etc/apt/sources.list.d/osquery.list\nsudo apt-get update && sudo apt-get install -y osquery"
        case .windows: "choco install osquery -y"
        }
    }
}

/// Commands to run on an endpoint to confirm the agent is connected and its scans started.
struct EndpointVerify: View {
    let os: AgentOS
    var body: some View {
        Group {
            Text("Agent service status").font(.callout)
            CommandBox(text: status)
            Text("Connection to the server (look for “Connected to the server”)").font(.callout)
            CommandBox(text: connection)
            Text("Scan modules started").font(.callout)
            CommandBox(text: modules)
            Text("Re-enroll an agent (after it was removed from the server, or shows “Invalid ID”)").font(.callout)
            CommandBox(text: reenroll)
        }
    }
    var log: String {
        switch os {
        case .macOS: "/Library/Ossec/logs/ossec.log"
        case .linux: "/var/ossec/logs/ossec.log"
        case .windows: "C:\\Program Files (x86)\\ossec-agent\\ossec.log"
        }
    }
    var status: String {
        switch os {
        case .macOS: "sudo /Library/Ossec/bin/wazuh-control status"
        case .linux: "sudo systemctl status wazuh-agent --no-pager"
        case .windows: "Get-Service -Name wazuh"
        }
    }
    var connection: String {
        os == .windows
            ? "Select-String -Path '\(log)' -Pattern 'Connected to the server|ERROR|WARNING' | Select-Object -Last 20"
            : "sudo grep -E 'Connected to the server|ERROR|WARNING' \(log) | tail -n 20"
    }
    var modules: String {
        let pat = "sca|syscollector|syscheck|rootcheck|logcollector|osquery|docker"
        return os == .windows
            ? "Select-String -Path '\(log)' -Pattern '(\(pat)).*(start|scan|Monitoring|Analyzing)' | Select-Object -Last 30"
            : "sudo grep -iE '(\(pat)).*(start|scan|Monitoring|Analyzing)' \(log) | tail -n 30"
    }
    var reenroll: String {
        switch os {
        case .macOS: "sudo /Library/Ossec/bin/wazuh-control stop && sudo rm -f /Library/Ossec/etc/client.keys && sudo /Library/Ossec/bin/wazuh-control start"
        case .linux: "sudo systemctl stop wazuh-agent && sudo truncate -s 0 /var/ossec/etc/client.keys && sudo systemctl start wazuh-agent"
        case .windows: "Stop-Service wazuh; Clear-Content 'C:\\Program Files (x86)\\ossec-agent\\client.keys'; Start-Service wazuh"
        }
    }
}
