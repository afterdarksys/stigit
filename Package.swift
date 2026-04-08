// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "StigIt",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "StigIt",     targets: ["StigIt"]),
        .executable(name: "stigit-cli", targets: ["StigItCLI"]),
    ],
    dependencies: [
        .package(url: "https://github.com/jpsim/Yams.git", from: "5.1.0"),
    ],
    targets: [
        .target(
            name: "StigItCore",
            dependencies: ["Yams"],
            path: "Sources/Shared"
        ),
        .executableTarget(
            name: "StigIt",
            dependencies: ["StigItCore"],
            path: "Sources/StigIt"
        ),
        .executableTarget(
            name: "StigItCLI",
            dependencies: ["StigItCore"],
            path: "Sources/StigItCLI"
        ),
    ]
)
