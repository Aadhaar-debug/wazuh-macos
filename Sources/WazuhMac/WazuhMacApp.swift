import SwiftUI
import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var activity: NSObjectProtocol?

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Keep status polling and agent checks running while the window is in the background (no App Nap).
        activity = ProcessInfo.processInfo.beginActivity(options: [.userInitiatedAllowingIdleSystemSleep],
                                                         reason: "Monitoring the local Wazuh stack")
        // Built as a plain SwiftPM executable: make sure it behaves like a regular Dock app.
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }
}

@main
struct WazuhMacApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @StateObject private var stack = StackManager()

    var body: some Scene {
        WindowGroup("Wazuh") {
            ContentView()
                .environmentObject(stack)
                .frame(minWidth: 1100, minHeight: 720)
                .onAppear { stack.bootstrap() }
        }
        .windowToolbarStyle(.unified)
        .commands {
            CommandMenu("Wazuh") {
                Button("Start Wazuh") { Task { await stack.start() } }
                    .keyboardShortcut("r", modifiers: [.command, .shift])
                Button("Stop Wazuh") { Task { await stack.stop() } }
                    .keyboardShortcut(".", modifiers: [.command, .shift])
                Divider()
                Button("Open Dashboard in Browser") {
                    NSWorkspace.shared.open(URL(string: "https://localhost")!)
                }
                Button("Reveal Stack Folder") {
                    NSWorkspace.shared.activateFileViewerSelecting([stack.stackDir])
                }
            }
        }

        MenuBarExtra {
            MenuBarContent().environmentObject(stack)
        } label: {
            Image(systemName: stack.allRunning ? "shield.lefthalf.filled" : "shield")
        }
    }
}

struct MenuBarContent: View {
    @EnvironmentObject var stack: StackManager
    var body: some View {
        Text(stack.allRunning ? "Wazuh \(wazuhVersion) — running" : "Wazuh \(wazuhVersion) — stopped")
        Divider()
        ForEach(stack.services) { s in
            Text("\(s.isRunning ? "●" : "○")  \(s.title)")
        }
        Divider()
        Button("Start Wazuh") { Task { await stack.start() } }.disabled(stack.busy || stack.allRunning)
        Button("Stop Wazuh") { Task { await stack.stop() } }.disabled(stack.busy || !stack.anyRunning)
        Button("Open Dashboard in Browser") { NSWorkspace.shared.open(URL(string: "https://localhost")!) }
        Divider()
        Button("Quit") { NSApp.terminate(nil) }.keyboardShortcut("q")
    }
}
