// swift-tools-version: 5.9
// Three Pillars VoIP — iOS Swift Package

import PackageDescription

let package = Package(
    name: "ThreePillarsVoIP",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
    ],
    products: [
        .library(
            name: "ThreePillarsVoIP",
            targets: ["ThreePillarsVoIP"]
        ),
    ],
    targets: [
        .binaryTarget(
            name: "ThreePillarsVoIP",
            path: "ThreePillarsVoIP.xcframework"
        ),
        .testTarget(
            name: "ThreePillarsVoIPTests",
            dependencies: ["ThreePillarsVoIP"],
            path: "Tests"
        ),
    ]
)
