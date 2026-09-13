// swift-tools-version: 5.9
// The swift-tools-version declares the minimum Swift version required to build this package.

import PackageDescription

let package = Package(
    name: "AIOSSLTool",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(
            name: "AIOSSLTool",
            targets: ["AIOSSLTool"]
        )
    ],
    dependencies: [
    ],
    targets: [
        .target(
            name: "AIOSSLToolCore",
            path: ".",
            exclude: [
                "Info.plist",
                "AIOSSLTool.entitlements",
                "build.sh",
                "AIO SSL Tool.app",
                "AppIcon.icns",
                "icon-source.png",
                "AIOSSLToolApp.swift",
                "ContentView.swift",
                "ViewModels",
                "Views",
                "aiossltool",
                "AppIcon.iconset",
                "PRISM.app",
                "release.sh",
                "HomeIcon.png",
                "Tests",
                "AIO-SSL-Tool-macOS-V6.4.3.dmg"
            ],
            sources: [
                "Models/CSRDetails.swift",
                "Models/PFXOptions.swift",
                "Utils/CertificateUtils.swift"
            ]
        ),
        .executableTarget(
            name: "AIOSSLTool",
            dependencies: [
                "AIOSSLToolCore"
            ],
            path: ".",
            exclude: [
                "Info.plist",
                "AIOSSLTool.entitlements",
                "build.sh",
                "AIO SSL Tool.app",
                "AppIcon.icns",
                "icon-source.png",
                "Models",
                "Utils",
                "Tests",
                "aiossltool",
                "AppIcon.iconset",
                "PRISM.app",
                "release.sh",
                "AIO-SSL-Tool-macOS-V6.4.3.dmg"
            ],
            sources: [
                "AIOSSLToolApp.swift",
                "ContentView.swift",
                "ViewModels/SSLToolViewModel.swift",
                "ViewModels/UpdaterViewModel.swift",
                "Views/HomeView.swift",
                "Views/ChainBuilderView.swift",
                "Views/CSRGenerationView.swift",
                "Views/PFXGeneratorView.swift",
                "Views/SettingsView.swift"
            ],
            resources: [
                .process("HomeIcon.png")
            ],
            swiftSettings: [
                .unsafeFlags(["-parse-as-library"])
            ]
        ),
        .testTarget(
            name: "AIOSSLToolTests",
            dependencies: ["AIOSSLToolCore"],
            path: "Tests"
        )
    ]
)
