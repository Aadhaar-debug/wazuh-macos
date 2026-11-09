import SwiftUI
import AppKit

enum NavSection: String, CaseIterable, Identifiable {
    case overview = "Overview"
    case dashboard = "Dashboard"
    case agents = "Deploy Agents"
    case logs = "Logs"
    case settings = "Settings"
    var id: String { rawValue }
    var icon: String {
        switch self {
        case .overview: "gauge.with.dots.needle.33percent"
        case .dashboard: "rectangle.3.group"
        case .agents: "desktopcomputer.and.arrow.down"
        case .logs: "text.alignleft"
        case .settings: "gearshape"
        }
    }
}

let wazuhBlue = Color(red: 0.24, green: 0.40, blue: 0.94)

struct ContentView: View {
    @EnvironmentObject var stack: StackManager
    @State private var selection: NavSection? = .overview

    var body: some View {
        NavigationSplitView {
            List(NavSection.allCases, selection: $selection) { s in
                Label(s.rawValue, systemImage: s.icon).tag(s)
            }
            .navigationSplitViewColumnWidth(min: 190, ideal: 210)
            .safeAreaInset(edge: .bottom) { SidebarFooter() }
        } detail: {
            switch selection ?? .overview {
            case .overview: OverviewView(selection: $selection)
            case .dashboard: DashboardPane()
            case .agents: AgentsView()
            case .logs: LogsView()
            case .settings: SettingsView()
            }
        }
    }
}

struct SidebarFooter: View {
    @EnvironmentObject var stack: StackManager
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Circle().fill(stack.allRunning ? .green : (stack.anyRunning ? .orange : .secondary))
                    .frame(width: 8, height: 8)
                Text(stack.allRunning ? "Running" : (stack.anyRunning ? "Partially running" : "Stopped"))
                    .font(.caption.weight(.medium))
            }
            Text("Wazuh \(wazuhVersion)").font(.caption2).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
    }
}

// MARK: - Overview

struct OverviewView: View {
    @EnvironmentObject var stack: StackManager
    @Binding var selection: NavSection?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                header
                dockerBanner
                VStack(spacing: 12) {
                    ForEach(stack.services) { ServiceCard(service: $0) }
                }
                credentials
                recentLog
            }
            .padding(28)
            .frame(maxWidth: 980, alignment: .leading)
        }
        .navigationTitle("Overview")
    }

    var header: some View {
        HStack(alignment: .center, spacing: 16) {
            ZStack {
                RoundedRectangle(cornerRadius: 14).fill(wazuhBlue.gradient).frame(width: 60, height: 60)
                Image(systemName: "shield.lefthalf.filled").font(.system(size: 28, weight: .semibold)).foregroundStyle(.white)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text("Wazuh SIEM & XDR").font(.title.bold())
                Text("Server, indexer and dashboard \(wazuhVersion) running locally on your Mac")
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if stack.busy {
                ProgressView().controlSize(.small)
                Text(stack.activity).font(.callout).foregroundStyle(.secondary).lineLimit(1)
            }
            if stack.anyRunning {
                Button { Task { await stack.restart() } } label: { Label("Restart", systemImage: "arrow.clockwise") }
                    .disabled(stack.busy)
                Button(role: .destructive) { Task { await stack.stop() } } label: { Label("Stop", systemImage: "stop.fill") }
                    .disabled(stack.busy)
            }
            if !stack.allRunning {
                Button { Task { await stack.start() } } label: { Label("Start Wazuh", systemImage: "play.fill") }
                    .buttonStyle(.borderedProminent).tint(wazuhBlue)
                    .disabled(stack.busy || stack.docker == .notInstalled)
            } else {
                Button { selection = .dashboard } label: { Label("Open Dashboard", systemImage: "arrow.up.right.square") }
                    .buttonStyle(.borderedProminent).tint(wazuhBlue)
            }
        }
    }

    @ViewBuilder var dockerBanner: some View {
        switch stack.docker {
        case .notInstalled:
            Banner(icon: "exclamationmark.triangle.fill", tint: .orange,
                   text: "Docker Desktop is required. Wazuh's server and indexer run as Linux containers.") {
                Button("Get Docker Desktop") { NSWorkspace.shared.open(URL(string: "https://www.docker.com/products/docker-desktop/")!) }
            }
        case .stopped:
            Banner(icon: "shippingbox", tint: .orange, text: "Docker Desktop is not running.") {
                Button("Launch Docker") { Task { await stack.launchDockerDesktop() } }
            }
        case .starting:
            Banner(icon: "hourglass", tint: .blue, text: "Starting Docker Desktop…") { EmptyView() }
        default: EmptyView()
        }
    }

    var credentials: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                CredRow(label: "Dashboard", url: "https://localhost", user: "admin", pass: "SecretPassword")
                CredRow(label: "Wazuh API", url: "https://localhost:55000", user: "wazuh-wui", pass: "MyS3cr37P450r.*-")
                CredRow(label: "Indexer", url: "https://localhost:9200", user: "admin", pass: "SecretPassword")
                Text("These are the upstream wazuh-docker defaults. Change them before exposing the stack to a network.")
                    .font(.caption).foregroundStyle(.secondary)
            }.padding(6)
        } label: { Label("Access", systemImage: "key") }
    }

    var recentLog: some View {
        GroupBox {
            ScrollView {
                Text(stack.log.suffix(12).joined(separator: "\n").ifEmpty("No activity yet."))
                    .font(.system(.caption, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
            }.frame(height: 150)
        } label: { Label("Activity", systemImage: "list.bullet.rectangle") }
    }
}

struct Banner<Content: View>: View {
    let icon: String; let tint: Color; let text: String
    @ViewBuilder var action: () -> Content
    var body: some View {
        HStack {
            Image(systemName: icon).foregroundStyle(tint)
            Text(text)
            Spacer()
            action()
        }
        .padding(12)
        .background(tint.opacity(0.1), in: RoundedRectangle(cornerRadius: 10))
    }
}

struct ServiceCard: View {
    @EnvironmentObject var stack: StackManager
    let service: ServiceStatus

    var color: Color {
        if service.isRunning { return service.endpointOK == true ? .green : .orange }
        return service.containerState == "unavailable" || service.containerState == "not created" ? .secondary : .red
    }
    var statusText: String {
        if service.isRunning { return service.endpointOK == true ? "Healthy" : "Starting…" }
        return service.containerState.capitalized
    }

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: icon).font(.title2).foregroundStyle(wazuhBlue).frame(width: 36)
            VStack(alignment: .leading, spacing: 3) {
                Text(service.title).font(.headline)
                Text(service.subtitle).font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
            Text(service.endpoint).font(.caption.monospaced()).foregroundStyle(.secondary)
            HStack(spacing: 6) {
                Circle().fill(color).frame(width: 9, height: 9)
                Text(statusText).font(.callout.weight(.medium))
            }.frame(width: 120, alignment: .leading)
            Button { Task { await stack.restart(service.id) } } label: { Image(systemName: "arrow.clockwise") }
                .buttonStyle(.borderless).help("Restart \(service.title)")
                .disabled(stack.busy || !service.isRunning)
        }
        .padding(14)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 12))
    }

    var icon: String {
        switch service.id {
        case "wazuh.manager": "server.rack"
        case "wazuh.indexer": "cylinder.split.1x2"
        default: "chart.bar.xaxis"
        }
    }
}

struct CredRow: View {
    let label: String, url: String, user: String, pass: String
    @State private var reveal = false
    var body: some View {
        HStack {
            Text(label).frame(width: 90, alignment: .leading).fontWeight(.medium)
            Link(url, destination: URL(string: url)!).font(.callout.monospaced()).frame(width: 230, alignment: .leading)
            Text(user).font(.callout.monospaced()).frame(width: 90, alignment: .leading)
            Text(reveal ? pass : String(repeating: "•", count: 10)).font(.callout.monospaced())
                .textSelection(.enabled)
            Button { reveal.toggle() } label: { Image(systemName: reveal ? "eye.slash" : "eye") }.buttonStyle(.borderless)
            Button {
                NSPasteboard.general.clearContents(); NSPasteboard.general.setString(pass, forType: .string)
            } label: { Image(systemName: "doc.on.doc") }.buttonStyle(.borderless).help("Copy password")
        }
    }
}

extension String {
    func ifEmpty(_ s: String) -> String { isEmpty ? s : self }
}

// MARK: - Dashboard

struct DashboardPane: View {
    @EnvironmentObject var stack: StackManager
    @State private var reload = 0

    var body: some View {
        Group {
            if stack.dashboardReady {
                DashboardWebView(url: URL(string: "https://localhost")!, reloadToken: $reload)
            } else {
                VStack(spacing: 14) {
                    Image(systemName: "rectangle.3.group").font(.system(size: 44)).foregroundStyle(.secondary)
                    Text(stack.anyRunning ? "The Wazuh dashboard is starting…" : "Wazuh is not running")
                        .font(.title3.weight(.semibold))
                    Text(stack.anyRunning ? "This usually takes 1–3 minutes after the containers start."
                                          : "Start the stack to use the dashboard.")
                        .foregroundStyle(.secondary)
                    if stack.anyRunning || stack.busy { ProgressView() }
                    else {
                        Button("Start Wazuh") { Task { await stack.start() } }
                            .buttonStyle(.borderedProminent).tint(wazuhBlue)
                    }
                }.frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .navigationTitle("Wazuh Dashboard")
        .toolbar {
            Button { reload += 1 } label: { Label("Reload", systemImage: "arrow.clockwise") }
            Button { NSWorkspace.shared.open(URL(string: "https://localhost")!) } label: {
                Label("Open in Browser", systemImage: "safari")
            }
        }
    }
}

// MARK: - Logs

struct LogsView: View {
    @EnvironmentObject var stack: StackManager
    @State private var source = "app"
    @State private var text = ""
    @State private var follow = true

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Picker("Source", selection: $source) {
                    Text("App activity").tag("app")
                    ForEach(stack.services) { Text($0.title).tag($0.id) }
                }.frame(width: 320)
                Toggle("Auto-refresh", isOn: $follow)
                Spacer()
                Button("Copy") {
                    NSPasteboard.general.clearContents(); NSPasteboard.general.setString(displayed, forType: .string)
                }
                Button { Task { await load() } } label: { Image(systemName: "arrow.clockwise") }
            }.padding(10)
            Divider()
            ScrollViewReader { proxy in
                ScrollView {
                    Text(displayed.ifEmpty("No logs."))
                        .font(.system(size: 11, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(10)
                    Color.clear.frame(height: 1).id("end")
                }
                .onChange(of: displayed) { if follow { proxy.scrollTo("end") } }
            }
            .background(Color(nsColor: .textBackgroundColor))
        }
        .navigationTitle("Logs")
        .task(id: source) {
            while !Task.isCancelled {
                await load()
                try? await Task.sleep(nanoseconds: 4_000_000_000)
                if !follow { break }
            }
        }
    }

    var displayed: String { source == "app" ? stack.log.joined(separator: "\n") : text }

    func load() async {
        if source != "app" { text = await stack.logs(for: source) }
    }
}

// MARK: - Settings

struct SettingsView: View {
    @EnvironmentObject var stack: StackManager
    @State private var confirmReset = false

    var body: some View {
        Form {
            Section("Deployment") {
                LabeledContent("Wazuh version", value: wazuhVersion)
                LabeledContent("Compose project", value: composeProject)
                LabeledContent("Stack folder") {
                    HStack {
                        Text(stack.stackDir.path).font(.callout.monospaced()).textSelection(.enabled)
                        Button("Reveal") { NSWorkspace.shared.activateFileViewerSelecting([stack.stackDir]) }
                    }
                }
                LabeledContent("Docker", value: stack.dockerPath ?? "not found")
                Text("Edit files in the stack folder (ossec.conf in config/wazuh_cluster, indexer and dashboard YAML) and restart the affected service to apply. The Wazuh dashboard also lets you edit rules, decoders, lists and ossec.conf directly.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Ports") {
                LabeledContent("Dashboard", value: "443 → 5601")
                LabeledContent("Agent events / enrollment", value: "1514/tcp, 1515/tcp")
                LabeledContent("Syslog", value: "514/udp")
                LabeledContent("Wazuh API", value: "55000/tcp")
                LabeledContent("Indexer API", value: "9200/tcp")
            }
            Section("Maintenance") {
                Button("Stop and remove all Wazuh data…", role: .destructive) { confirmReset = true }
                    .disabled(stack.busy)
                Text("Deletes containers and volumes: alerts, registered agents, and configuration changes. TLS certificates are kept.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("About") {
                Text("Unofficial macOS packaging of the open-source Wazuh platform (GPLv2). Runs the unmodified official Wazuh \(wazuhVersion) images from wazuh/wazuh-docker. Not affiliated with or endorsed by Wazuh, Inc.")
                    .font(.callout)
                Link("Wazuh documentation", destination: URL(string: "https://documentation.wazuh.com/current/")!)
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Settings")
        .confirmationDialog("Remove all Wazuh data?", isPresented: $confirmReset) {
            Button("Remove data", role: .destructive) { Task { await stack.reset() } }
        } message: { Text("This cannot be undone.") }
    }
}
