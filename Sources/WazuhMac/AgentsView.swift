import SwiftUI
import AppKit

/// Agent deployment commands, same as the dashboard's "Deploy new agent" wizard.
struct AgentsView: View {
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
    }

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

    var body: some View {
        Form {
            Section("Agent settings") {
                TextField("Wazuh server address", text: $managerHost)
                Text("Agents connect to this Mac on TCP 1514 (events) and 1515 (enrollment). Use an address reachable from the endpoint.")
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
                Text("New agents appear under Agents management → Summary in the dashboard within a minute. The dashboard's “Deploy new agent” wizard offers the same commands.")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Deploy Agents")
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
