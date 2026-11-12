import Foundation

/// Where and how the agent is being installed.
enum TargetOS: String, CaseIterable, Identifiable {
    case macOS = "macOS"
    case deb = "Linux (Debian, Ubuntu)"
    case rpm = "Linux (RHEL, Rocky, Alma, Fedora, Amazon, SUSE)"
    case windows = "Windows"
    var id: String { rawValue }
    var agentOS: AgentOS { self == .macOS ? .macOS : (self == .windows ? .windows : .linux) }
    var shell: String { self == .windows ? "PowerShell, as Administrator" : "Terminal" }
}

/// Every command on the Deploy Agents page. Each is ONE line, so it can be pasted into zsh, bash or
/// PowerShell as-is: no comment lines (zsh treats a pasted `#` as a command) and no multi-line
/// input that a sudo password prompt could swallow. All steps are safe to re-run.
struct AgentCommands {
    let os: TargetOS
    let manager: String
    let name: String      // empty = the endpoint's hostname
    let group: String     // empty = "default"

    static let version = wazuhVersion

    /// Values are inserted into shell commands, so only allow characters that need no quoting.
    static func isSafe(_ s: String) -> Bool {
        s.range(of: "^[A-Za-z0-9._-]*$", options: .regularExpression) != nil
    }
    var valid: Bool { !manager.isEmpty && Self.isSafe(manager) && Self.isSafe(name) && Self.isSafe(group) }
    var groupOrDefault: String { group.isEmpty ? "default" : group }

    var confPath: String {
        switch os {
        case .macOS: "/Library/Ossec/etc/ossec.conf"
        case .windows: "C:\\Program Files (x86)\\ossec-agent\\ossec.conf"
        default: "/var/ossec/etc/ossec.conf"
        }
    }
    var logPath: String {
        switch os {
        case .macOS: "/Library/Ossec/logs/ossec.log"
        case .windows: "C:\\Program Files (x86)\\ossec-agent\\ossec.log"
        default: "/var/ossec/logs/ossec.log"
        }
    }
    var optionsPath: String {
        switch os {
        case .macOS: "/Library/Ossec/etc/local_internal_options.conf"
        case .windows: "C:\\Program Files (x86)\\ossec-agent\\local_internal_options.conf"
        default: "/var/ossec/etc/local_internal_options.conf"
        }
    }
    private var restartUnix: String {
        os == .macOS ? "sudo /Library/Ossec/bin/wazuh-control restart"
                     : "(sudo systemctl restart wazuh-agent 2>/dev/null || sudo /var/ossec/bin/wazuh-control restart)"
    }

    // MARK: Step: remove any previous agent

    var uninstall: String {
        switch os {
        case .macOS:
            return "sudo sh -c '/Library/Ossec/bin/wazuh-control stop >/dev/null 2>&1; launchctl unload /Library/LaunchDaemons/com.wazuh.agent.plist >/dev/null 2>&1; rm -rf /Library/Ossec /Library/LaunchDaemons/com.wazuh.agent.plist /Library/StartupItems/WAZUH; dscl . -delete /Users/wazuh >/dev/null 2>&1; dscl . -delete /Groups/wazuh >/dev/null 2>&1; pkgutil --forget com.wazuh.pkg.wazuh-agent >/dev/null 2>&1; echo \"Clean: no Wazuh agent left on this Mac.\"'"
        case .deb:
            return "sudo sh -c 'systemctl disable --now wazuh-agent >/dev/null 2>&1; /var/ossec/bin/wazuh-control stop >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y wazuh-agent >/dev/null 2>&1; rm -rf /var/ossec; systemctl daemon-reload >/dev/null 2>&1; echo \"Clean: no Wazuh agent left on this machine.\"'"
        case .rpm:
            return "sudo sh -c 'systemctl disable --now wazuh-agent >/dev/null 2>&1; /var/ossec/bin/wazuh-control stop >/dev/null 2>&1; if command -v dnf >/dev/null; then dnf remove -y wazuh-agent; elif command -v yum >/dev/null; then yum remove -y wazuh-agent; elif command -v zypper >/dev/null; then zypper -n remove wazuh-agent; fi >/dev/null 2>&1; rm -rf /var/ossec; systemctl daemon-reload >/dev/null 2>&1; echo \"Clean: no Wazuh agent left on this machine.\"'"
        case .windows:
            return "Stop-Service -Name WazuhSvc -ErrorAction SilentlyContinue; Get-CimInstance Win32_Product | Where-Object { $_.Name -like 'Wazuh Agent*' } | ForEach-Object { Start-Process msiexec.exe -Wait -ArgumentList \"/x $($_.IdentifyingNumber) /qn\" }; Remove-Item -Recurse -Force 'C:\\Program Files (x86)\\ossec-agent' -ErrorAction SilentlyContinue; 'Clean: no Wazuh agent left on this PC.'"
        }
    }

    // MARK: Step: download and install

    var install: String {
        let v = Self.version
        switch os {
        case .macOS:
            var envs = "WAZUH_MANAGER='\(manager)' && WAZUH_AGENT_GROUP='\(groupOrDefault)'"
            if !name.isEmpty { envs += " && WAZUH_AGENT_NAME='\(name)'" }
            return "A=$([ \"$(uname -m)\" = arm64 ] && echo arm64 || echo intel64) && curl -fsSL -o /tmp/wazuh-agent.pkg \"https://packages.wazuh.com/4.x/macos/wazuh-agent-\(v)-1.$A.pkg\" && echo \"\(envs)\" > /tmp/wazuh_envs && sudo installer -pkg /tmp/wazuh-agent.pkg -target / && rm -f /tmp/wazuh-agent.pkg"
        case .deb:
            return "A=$(dpkg --print-architecture) && curl -fsSL -o /tmp/wazuh-agent.deb \"https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_\(v)-1_$A.deb\" && sudo \(envVars) DEBIAN_FRONTEND=noninteractive apt-get install -y /tmp/wazuh-agent.deb && rm -f /tmp/wazuh-agent.deb"
        case .rpm:
            return "A=$(uname -m) && curl -fsSL -o /tmp/wazuh-agent.rpm \"https://packages.wazuh.com/4.x/yum/wazuh-agent-\(v)-1.$A.rpm\" && sudo \(envVars) sh -c 'if command -v dnf >/dev/null; then dnf install -y /tmp/wazuh-agent.rpm; elif command -v yum >/dev/null; then yum install -y /tmp/wazuh-agent.rpm; else zypper -n --no-gpg-checks install /tmp/wazuh-agent.rpm; fi' && rm -f /tmp/wazuh-agent.rpm"
        case .windows:
            var props = "WAZUH_MANAGER=`\"\(manager)`\" WAZUH_AGENT_GROUP=`\"\(groupOrDefault)`\""
            if !name.isEmpty { props += " WAZUH_AGENT_NAME=`\"\(name)`\"" }
            return "$ProgressPreference='SilentlyContinue'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $m=\"$env:TEMP\\wazuh-agent.msi\"; Invoke-WebRequest -UseBasicParsing -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-\(v)-1.msi -OutFile $m; Start-Process msiexec.exe -Wait -ArgumentList \"/i `\"$m`\" /qn \(props)\"; Remove-Item $m; 'Installed.'"
        }
    }
    private var envVars: String {
        var s = "WAZUH_MANAGER='\(manager)' WAZUH_AGENT_GROUP='\(groupOrDefault)'"
        if !name.isEmpty { s += " WAZUH_AGENT_NAME='\(name)'" }
        return s
    }

    // MARK: Step: allow scan policies sent by the server

    var allowServerPolicies: String {
        switch os {
        case .windows:
            return "$f='\(optionsPath)'; if (-not (Select-String -Path $f -SimpleMatch 'sca.remote_commands=1' -Quiet)) { Add-Content -Path $f -Value 'sca.remote_commands=1' }; 'Server policies allowed.'"
        default:
            return "sudo sh -c 'grep -qxF sca.remote_commands=1 \(optionsPath) || echo sca.remote_commands=1 >> \(optionsPath); echo \"Server policies allowed.\"'"
        }
    }

    // MARK: Step: start and confirm connection

    var start: String {
        switch os {
        case .macOS:
            return "sudo /Library/Ossec/bin/wazuh-control restart >/dev/null && sleep 20 && sudo grep -E 'Valid key received|Connected to the server|ERROR' \(logPath) | tail -n 3"
        case .windows:
            return "Restart-Service -Name WazuhSvc; Start-Sleep 20; Select-String -Path '\(logPath)' -Pattern 'Valid key received|Connected to the server|ERROR' | Select-Object -Last 3"
        default:
            return "(sudo systemctl daemon-reload && sudo systemctl enable wazuh-agent && sudo systemctl restart wazuh-agent || sudo /var/ossec/bin/wazuh-control restart) >/dev/null 2>&1 && sleep 20 && sudo grep -E 'Valid key received|Connected to the server|ERROR' \(logPath) | tail -n 3"
        }
    }

    // MARK: Verification and troubleshooting

    var status: String {
        switch os {
        case .macOS: "sudo /Library/Ossec/bin/wazuh-control status"
        case .windows: "Get-Service -Name WazuhSvc"
        default: "sudo /var/ossec/bin/wazuh-control status"
        }
    }
    var serverAddressInConfig: String {
        os == .windows ? "Select-String -Path '\(confPath)' -Pattern '<address>'"
                       : "sudo grep '<address>' \(confPath)"
    }
    var modulesStarted: String {
        let pat = "sca|syscollector|syscheck|rootcheck|logcollector|osquery|docker-listener"
        return os == .windows
            ? "Select-String -Path '\(logPath)' -Pattern '(\(pat)).*(start|Starting|scan|Monitoring|Analyzing)' | Select-Object -Last 25"
            : "sudo grep -iE '(\(pat)).*(start|scan|monitoring|analyzing)' \(logPath) | tail -n 25"
    }
    var logTail: String {
        os == .windows ? "Get-Content '\(logPath)' -Tail 40" : "sudo tail -n 40 \(logPath)"
    }
    var reachability: String {
        switch os {
        case .windows: "Test-NetConnection \(manager) -Port 1514; Test-NetConnection \(manager) -Port 1515"
        default: "nc -vz -w 3 \(manager) 1514; nc -vz -w 3 \(manager) 1515"
        }
    }
    var endpointFirewall: String? {
        switch os {
        case .macOS: nil   // the macOS application firewall filters inbound traffic only
        case .windows: "New-NetFirewallRule -DisplayName 'Wazuh agent' -Direction Outbound -Protocol TCP -RemotePort 1514,1515 -Action Allow"
        case .deb: "sudo ufw allow out 1514:1515/tcp"
        case .rpm: "sudo firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 -p tcp -m multiport --dports 1514,1515 -j ACCEPT && sudo firewall-cmd --reload"
        }
    }
    var repoint: String {
        switch os {
        case .macOS:
            return "sudo sed -i '' 's|<address>[^<]*</address>|<address>\(manager)</address>|' \(confPath) && \(restartUnix)"
        case .windows:
            return "$f='\(confPath)'; [IO.File]::WriteAllText($f, ((Get-Content $f -Raw) -replace '<address>[^<]*</address>','<address>\(manager)</address>')); Restart-Service -Name WazuhSvc"
        default:
            return "sudo sed -i 's|<address>[^<]*</address>|<address>\(manager)</address>|' \(confPath) && \(restartUnix)"
        }
    }
    var reenroll: String {
        switch os {
        case .macOS: "sudo sh -c '/Library/Ossec/bin/wazuh-control stop; : > /Library/Ossec/etc/client.keys; /Library/Ossec/bin/wazuh-control start'"
        case .windows: "Stop-Service -Name WazuhSvc; Clear-Content '\(confPath.replacingOccurrences(of: "ossec.conf", with: "client.keys"))'; Start-Service -Name WazuhSvc"
        default: "sudo sh -c '/var/ossec/bin/wazuh-control stop; : > /var/ossec/etc/client.keys; systemctl restart wazuh-agent 2>/dev/null || /var/ossec/bin/wazuh-control start'"
        }
    }

    /// Write the scan block into this agent's own ossec.conf (instead of the server push). Replaces a
    /// previous block written by this command, so it can be re-run. Base64 keeps it one line.
    func localScans(_ opts: ScanOptions) -> String {
        let xml = AgentConfig.localConf(os.agentOS, opts)
        let b64 = Data(xml.utf8).base64EncodedString()
        let begin = AgentConfig.localBegin, end = AgentConfig.localEnd
        switch os {
        case .macOS:
            return "sudo sed -i '' '/\(begin)/,/\(end)/d' \(confPath) && echo '\(b64)' | base64 -D | sudo tee -a \(confPath) >/dev/null && \(restartUnix)"
        case .windows:
            return "$f='\(confPath)'; $c=[regex]::Replace((Get-Content $f -Raw), '(?s)\(begin).*?\(end)\\r?\\n?', ''); [IO.File]::WriteAllText($f, $c + [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('\(b64)'))); Restart-Service -Name WazuhSvc"
        default:
            return "sudo sed -i '/\(begin)/,/\(end)/d' \(confPath) && echo '\(b64)' | base64 -d | sudo tee -a \(confPath) >/dev/null && \(restartUnix)"
        }
    }

    var osqueryInstall: String {
        switch os {
        case .macOS: "brew install --cask osquery"
        case .deb: "sudo mkdir -p /etc/apt/keyrings && curl -fsSL https://pkg.osquery.io/deb/pubkey.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/osquery.gpg && echo \"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/osquery.gpg] https://pkg.osquery.io/deb deb main\" | sudo tee /etc/apt/sources.list.d/osquery.list >/dev/null && sudo apt-get update && sudo apt-get install -y osquery"
        case .rpm: "curl -fsSL https://pkg.osquery.io/rpm/GPG | sudo tee /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery >/dev/null && sudo curl -fsSL -o /etc/yum.repos.d/osquery-s3-rpm.repo https://pkg.osquery.io/rpm/osquery-s3-rpm.repo && sudo dnf install -y osquery"
        case .windows: "winget install --id osquery.osquery -e --accept-source-agreements --accept-package-agreements"
        }
    }
}
