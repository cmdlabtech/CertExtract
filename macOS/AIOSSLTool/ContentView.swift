//
//  ContentView.swift
//  AIO SSL Tool
//

import SwiftUI

struct ContentView: View {
    @StateObject private var viewModel = SSLToolViewModel()
    @EnvironmentObject private var updaterViewModel: UpdaterViewModel
    @State private var selectedTool: Tool? = .home
    @State private var showPRISMNotice: Bool = false
    
    enum Tool: String, CaseIterable, Identifiable {
        case home = "Home"
        case csrGenerator = "CSR Generator"
        case chainBuilder = "Chain Builder"
        case pfxGenerator = "PFX Generator"
        case settings = "Settings"

        var id: String { rawValue }
        var icon: String {
            switch self {
            case .home: return "house.fill"
            case .csrGenerator: return "doc.badge.plus"
            case .chainBuilder: return "link.circle.fill"
            case .pfxGenerator: return "shippingbox.fill"
            case .settings: return "gearshape.fill"
            }
        }
    }

    var body: some View {
        NavigationSplitView {
            List(Tool.allCases, selection: $selectedTool) { tool in
                NavigationLink(value: tool) {
                    Label(tool.rawValue, systemImage: tool.icon)
                        .padding(.vertical, 8)
                        .font(.system(size: 14, weight: .medium))
                }
            }
            .navigationSplitViewColumnWidth(min: 200, ideal: 220, max: 250)
            .listStyle(.sidebar)
            .navigationTitle("SSL Suite")
        } detail: {
            Group {
                if let tool = selectedTool {
                    switch tool {
                    case .home:
                        HomeView(viewModel: viewModel)
                    case .csrGenerator:
                        CSRGenerationView(viewModel: viewModel)
                    case .chainBuilder:
                        ChainBuilderView(viewModel: viewModel)
                    case .pfxGenerator:
                        PFXGeneratorView(viewModel: viewModel)
                    case .settings:
                        SettingsView()
                            .environmentObject(updaterViewModel)
                    }
                } else {
                    ContentUnavailableView("Select a Tool", systemImage: "wrench.and.screwdriver")
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .preferredColorScheme(.dark)
        .frame(minWidth: 900, minHeight: 750)
        .onAppear {
            if !UserDefaults.standard.bool(forKey: "prismNoticeShown_6.4.1") {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                    showPRISMNotice = true
                }
            }
        }
        .alert("Update Available", isPresented: $updaterViewModel.showUpdateAlert) {
            Button("Download v\(updaterViewModel.latestVersion)") {
                updaterViewModel.openReleaseURL()
            }
            Button("Later", role: .cancel) { }
        } message: {
            Text("A new version (\(updaterViewModel.latestVersion)) is available. Click Download to open the release page in your browser.")
        }
        .alert("AIO SSL Tool Has Grown", isPresented: $showPRISMNotice) {
            Button("Learn More") {
                UserDefaults.standard.set(true, forKey: "prismNoticeShown_6.4.1")
                NSWorkspace.shared.open(URL(string: "https://prism.cmdlab.tech")!)
            }
            Button("Dismiss") {
                UserDefaults.standard.set(true, forKey: "prismNoticeShown_6.4.1")
            }
        } message: {
            Text("AIO SSL Tool has evolved into PRISM — a full PKI and certificate management suite.\n\nVisit prism.cmdlab.tech to download PRISM and purchase a license key.")
        }
    }
}
