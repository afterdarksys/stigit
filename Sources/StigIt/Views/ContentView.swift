import SwiftUI
import StigItCore

struct ContentView: View {
    @Environment(RuleStore.self) var store
    
    var body: some View {
        TabView(selection: Bindable(store).activeProfile) {
            ForEach(ComplianceProfile.allCases) { profile in
                StandardWorkflowView(profile: profile)
                    .tabItem {
                        Text(profile.rawValue)
                    }
                    .tag(profile)
            }
        }
    }
}
