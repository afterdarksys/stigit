import SwiftUI
import StigItCore

@main
struct StigItApp: App {
    @State private var store = RuleStore()
    
    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(store)
                .frame(minWidth: 800, minHeight: 600)
        }
        .windowStyle(HiddenTitleBarWindowStyle())
    }
}
