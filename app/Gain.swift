// Gain.app: a menu bar front end for `gain agent` (README "Gain.app"). It speaks the agent's socket
// protocol directly and keeps no state of its own; the cask installs it with the CLI inside.
// Build: scripts/build-app.sh
import AppKit
import Darwin
import ServiceManagement
import SwiftUI

let home = ProcessInfo.processInfo.environment["HOME"] ?? NSHomeDirectory()
let dataDir = home + "/.local/share/gain"

enum AgentError: Error {
    case notRunning
    case failed(String)
}

// One JSON request line per connection, one JSON response line back (src/main.rs `call`).
func call(_ req: [String: String]) throws -> [String: Any] {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { throw AgentError.failed("socket: errno \(errno)") }
    defer { close(fd) }
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let path = Array((dataDir + "/agent.sock").utf8CString)
    guard path.count <= MemoryLayout.size(ofValue: addr.sun_path) else {
        throw AgentError.failed("socket path too long")
    }
    withUnsafeMutableBytes(of: &addr.sun_path) { dst in path.withUnsafeBytes { dst.copyMemory(from: $0) } }
    let connected = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
    guard connected == 0 else { throw AgentError.notRunning }
    var line = try JSONSerialization.data(withJSONObject: req)
    line.append(0x0A)
    defer { line.resetBytes(in: 0..<line.count) } // the request may hold the passphrase
    let sent = line.withUnsafeBytes { buf in
        var off = 0
        while off < buf.count {
            let n = write(fd, buf.baseAddress! + off, buf.count - off)
            if n <= 0 { return false }
            off += n
        }
        return true
    }
    guard sent else { throw AgentError.failed("write: errno \(errno)") }
    var out = Data()
    var buf = [UInt8](repeating: 0, count: 4096)
    while case let n = read(fd, &buf, buf.count), n > 0 { out.append(contentsOf: buf[0..<n]) }
    guard let res = (try? JSONSerialization.jsonObject(with: out)) as? [String: Any] else {
        throw AgentError.failed("the agent closed the connection")
    }
    if let e = res["error"] as? String { throw AgentError.failed(e) }
    return res
}

@MainActor
final class Model: ObservableObject {
    enum State { case notRunning, locked, unlocked, failed(String) }
    @Published var state = State.notRunning
    @Published var version = ""
    @Published var openAtLogin = SMAppService.mainApp.status == .enabled
    private var prompted = false
    private var window: NSWindow?

    var vaultExists: Bool { FileManager.default.fileExists(atPath: dataDir + "/vault") }

    init() {
        // First launch: start at login (the toggle in the menu turns it off for good).
        if !UserDefaults.standard.bool(forKey: "loginItemSet") {
            UserDefaults.standard.set(true, forKey: "loginItemSet")
            setOpenAtLogin(true)
        }
        refresh()
        Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { _ in
            Task { @MainActor in self.refresh() }
        }
    }

    func refresh() {
        Task {
            let r = await Task.detached { Result { try call(["cmd": "status"]) } }.value
            switch r {
            case let .success(res):
                version = res["version"] as? String ?? ""
                state = res["unlocked"] as? Bool == true ? .unlocked : .locked
            case .failure(AgentError.notRunning): state = .notRunning
            case let .failure(e): state = .failed("\(e)")
            }
            // At login the app may come up before the agent: ask once, when it is first seen locked.
            if case .locked = state, !prompted, vaultExists {
                prompted = true
                showUnlock()
            }
        }
    }

    // nil on success, else the agent's error. Never sends a passphrase without a vault: the agent
    // would create one from it, unconfirmed (`gain agent unlock` asks twice and checks the length).
    func unlock(_ passphrase: String) async -> String? {
        guard vaultExists else { return "No vault yet: run gain agent unlock in a terminal." }
        let r = await Task.detached { Result { try call(["cmd": "unlock", "passphrase": passphrase]) } }.value
        refresh()
        switch r {
        case .success:
            closeUnlock()
            return nil
        case let .failure(AgentError.failed(e)): return e
        case .failure(AgentError.notRunning): return "The agent is not running: gain agent install"
        case let .failure(e): return "\(e)"
        }
    }

    func lock() {
        Task.detached { _ = try? call(["cmd": "lock"]) }
        refresh()
    }

    func setOpenAtLogin(_ on: Bool) {
        try? on ? SMAppService.mainApp.register() : SMAppService.mainApp.unregister()
        openAtLogin = SMAppService.mainApp.status == .enabled
    }

    func showUnlock() {
        if window == nil {
            let w = NSWindow(contentViewController: NSHostingController(rootView: UnlockView(model: self)))
            w.title = "gain"
            w.styleMask = [.titled, .closable]
            w.isReleasedWhenClosed = false
            w.level = .floating
            window = w
        }
        window?.center()
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }

    func closeUnlock() {
        window?.close()
        window = nil // a fresh view next time: no passphrase left in its state
    }
}

// The login window's "wrong password" shake.
struct Shake: GeometryEffect {
    var animatableData: CGFloat
    func effectValue(size: CGSize) -> ProjectionTransform {
        ProjectionTransform(CGAffineTransform(translationX: 10 * sin(animatableData * .pi * 6), y: 0))
    }
}

struct UnlockView: View {
    @ObservedObject var model: Model
    @State private var passphrase = ""
    @State private var message: String?
    @State private var busy = false
    @State private var shakes: CGFloat = 0
    @FocusState private var focused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 12) {
                Image(systemName: "lock.fill").font(.largeTitle).foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Unlock gain").font(.headline)
                    Text("The GitHub App agent is locked.").font(.caption).foregroundStyle(.secondary)
                }
            }
            SecureField("Passphrase", text: $passphrase)
                .textFieldStyle(.roundedBorder)
                .onSubmit(submit)
                .disabled(busy)
                .focused($focused)
                .onAppear { focused = true }
                .modifier(Shake(animatableData: shakes))
            if let message {
                Text(message).font(.caption).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button("Later") { model.closeUnlock() }.keyboardShortcut(.cancelAction)
                Button("Unlock", action: submit)
                    .keyboardShortcut(.defaultAction)
                    .disabled(passphrase.isEmpty || busy)
            }
        }
        .padding(20)
        .frame(width: 340)
    }

    func submit() {
        guard !passphrase.isEmpty, !busy else { return }
        busy = true
        let p = passphrase
        Task {
            let error = await model.unlock(p)
            busy = false
            guard let error else { return }
            passphrase = ""
            message = error == "wrong passphrase" ? nil : error
            focused = true // disabling the field while busy took the focus away
            withAnimation(.linear(duration: 0.4)) { shakes += 1 }
        }
    }
}

struct MenuContent: View {
    @ObservedObject var model: Model

    var body: some View {
        switch model.state {
        case .notRunning: Text("Agent not running")
        case .locked: Text("Locked (agent \(model.version))")
        case .unlocked: Text("Unlocked (agent \(model.version))")
        case let .failed(e): Text("Error: \(e)")
        }
        if !model.vaultExists { Text("No vault: run gain agent unlock in a terminal") }
        Divider()
        if case .locked = model.state, model.vaultExists {
            Button("Unlock…") { model.showUnlock() }
        }
        if case .unlocked = model.state {
            Button("Lock") { model.lock() }
        }
        Toggle("Open at Login", isOn: Binding(get: { model.openAtLogin }, set: { model.setOpenAtLogin($0) }))
        Divider()
        Button("Quit Gain") { NSApp.terminate(nil) }.keyboardShortcut("q")
    }
}

@main
struct GainApp: App {
    @StateObject private var model = Model()

    var body: some Scene {
        MenuBarExtra {
            MenuContent(model: model)
        } label: {
            switch model.state {
            case .unlocked: Image(systemName: "lock.open.fill")
            case .locked: Image(systemName: "lock.fill")
            case .notRunning, .failed: Image(systemName: "lock.slash")
            }
        }
    }
}
