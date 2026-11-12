import SwiftUI
import AppKit

/// "Enable all scans": push centralized config to an agent group, or configure one agent by hand.
struct ScansSection: View {
    @EnvironmentObject var stack: StackManager
    @Binding var group: String

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
                Text("Writes separate macOS, Linux and Windows settings for group “\(targetGroup)”. Wazuh validates the file before installing it and keeps a backup of the previous one. Connected agents apply it within about a minute. Vulnerability detection runs on the server and is always on.")
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

}
