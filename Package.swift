// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "WazuhMac",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "WazuhMac",
            path: "Sources/WazuhMac",
            swiftSettings: [.unsafeFlags(["-swift-version", "5"])]
        )
    ]
)
