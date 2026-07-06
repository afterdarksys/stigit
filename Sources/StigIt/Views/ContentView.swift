import SwiftUI
import StigItCore

enum SidebarItem: Hashable {
    case dashboard
    case profile(ComplianceProfile)
    case fleet
    case waivers
    case backups
}

struct ContentView: View {
    @Environment(RuleStore.self) var store
    @State private var selection: SidebarItem? = .dashboard

    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                Section("Overview") {
                    Label("Dashboard", systemImage: "gauge.with.needle")
                        .tag(SidebarItem.dashboard)
                }
                Section("This Mac") {
                    ForEach(ComplianceProfile.allCases) { profile in
                        Label(profile.rawValue, systemImage: "checkmark.shield")
                            .tag(SidebarItem.profile(profile))
                    }
                }
                Section("Management") {
                    Label("Fleet", systemImage: "server.rack")
                        .tag(SidebarItem.fleet)
                    Label("Waivers", systemImage: "doc.badge.clock")
                        .tag(SidebarItem.waivers)
                    Label("Backups", systemImage: "archivebox")
                        .tag(SidebarItem.backups)
                }
            }
            .listStyle(.sidebar)
            .navigationSplitViewColumnWidth(min: 200, ideal: 230)
        } detail: {
            switch selection {
            case .dashboard, nil:
                DashboardView()
            case .profile(let profile):
                StandardWorkflowView(profile: profile)
                    .id(profile)   // reset category/filter state when switching profiles
            case .fleet:
                FleetView()
            case .waivers:
                WaiversView()
            case .backups:
                BackupsView()
            }
        }
        .onChange(of: selection) { _, newValue in
            if case .profile(let profile) = newValue {
                store.activeProfile = profile
            }
        }
    }
}
