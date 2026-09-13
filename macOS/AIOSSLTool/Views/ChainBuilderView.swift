//
//  ChainBuilderView.swift
//  AIO SSL Tool
//

import SwiftUI

struct ChainBuilderView: View {
    @ObservedObject var viewModel: SSLToolViewModel
    
    var body: some View {
        VStack(spacing: 0) {
            // Top Bar
            HStack {
                VStack(alignment: .leading) {
                    Text("Chain Builder")
                        .font(.largeTitle)
                        .fontWeight(.bold)
                    Text("Build complete certificate chains from leaf certificates")
                        .foregroundColor(.secondary)
                }
                Spacer()
                
                // Working Directory Indicator
                HStack {
                    Image(systemName: "folder")
                    if let path = viewModel.saveDirectory?.path {
                        Text(shortenPath(path))
                            .font(.caption)
                            .monospaced()
                    } else {
                        Text("No Save Location Set")
                            .font(.caption)
                            .italic()
                    }
                }
                .padding(8)
                .background(.regularMaterial)
                .cornerRadius(8)
            }
            .padding()
            .background(.thinMaterial)
            
            ScrollView {
                VStack(spacing: 20) {
                    
                    if viewModel.saveDirectory == nil {
                        ContentUnavailableView {
                            Label("Select working directory", systemImage: "folder.badge.plus")
                        } description: {
                            Text("Go to Home and set your working directory first.")
                        }
                        .frame(height: 300)
                    } else {
                        // Main Workflow Card
                        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 20) {
                            
                            // Input Card - Show files from directory
                            WorkflowCard(title: "Certificate", icon: "certificate", color: .blue) {
                                VStack(alignment: .leading, spacing: 10) {
                                    if let cert = viewModel.certificateFile {
                                        HStack {
                                            Image(systemName: "checkmark.circle.fill")
                                                .foregroundColor(.green)
                                            VStack(alignment: .leading) {
                                                Text(cert.lastPathComponent)
                                                    .font(.headline)
                                                Text("Selected")
                                                    .font(.caption)
                                                    .foregroundColor(.secondary)
                                            }
                                            Spacer()
                                            Button("Change") {
                                                viewModel.certificateFile = nil
                                            }
                                            .buttonStyle(.link)
                                            .font(.caption)
                                        }
                                    } else {
                                        if viewModel.workingDirectoryFiles.isEmpty {
                                            VStack(spacing: 12) {
                                                Text("No certificate files found")
                                                    .font(.caption)
                                                    .foregroundColor(.secondary)
                                                Button(action: { viewModel.browseCertificate() }) {
                                                    HStack {
                                                        Image(systemName: "arrow.up.doc")
                                                        Text("Browse Files")
                                                    }
                                                }
                                                .buttonStyle(.bordered)
                                            }
                                            .frame(maxWidth: .infinity, minHeight: 100)
                                            .background(Color.secondary.opacity(0.1))
                                            .cornerRadius(8)
                                        } else {
                                            VStack(alignment: .leading, spacing: 8) {
                                                Text("Select a certificate file:")
                                                    .font(.caption)
                                                    .foregroundColor(.secondary)
                                                
                                                ScrollView {
                                                    VStack(spacing: 4) {
                                                        ForEach(viewModel.workingDirectoryFiles, id: \.self) { file in
                                                            Button(action: {
                                                                viewModel.selectCertificateFromDirectory(file)
                                                            }) {
                                                                HStack {
                                                                    Image(systemName: fileIcon(for: file))
                                                                        .foregroundColor(fileColor(for: file))
                                                                    Text(file.lastPathComponent)
                                                                        .font(.system(.body, design: .monospaced))
                                                                        .lineLimit(1)
                                                                    Spacer()
                                                                }
                                                                .padding(.horizontal, 8)
                                                                .padding(.vertical, 6)
                                                                .background(Color.secondary.opacity(0.1))
                                                                .cornerRadius(6)
                                                            }
                                                            .buttonStyle(.plain)
                                                        }
                                                    }
                                                }
                                                .frame(maxHeight: 150)
                                                
                                                Button("Browse Other Files") {
                                                    viewModel.browseCertificate()
                                                }
                                                .buttonStyle(.link)
                                                .font(.caption)
                                            }
                                        }
                                    }
                                }
                            }
                            
                            // Chain Status Card
                            WorkflowCard(title: "Chain Status", icon: "link", color: .orange) {
                                VStack {
                                    if viewModel.fullChainCreated {
                                        VStack(spacing: 12) {
                                            HStack {
                                                Image(systemName: "checkmark.shield.fill")
                                                    .font(.largeTitle)
                                                    .foregroundColor(.green)
                                                VStack(alignment: .leading) {
                                                    Text("Chain Built")
                                                        .font(.headline)
                                                    Text("FullChain.cer ready")
                                                        .font(.caption)
                                                        .foregroundColor(.secondary)
                                                }
                                            }
                                            Button("Rebuild Chain") {
                                                viewModel.createFullChain()
                                            }
                                            .buttonStyle(.bordered)
                                            .disabled(viewModel.certificateFile == nil || viewModel.isBuilding)
                                        }
                                        .frame(maxWidth: .infinity, minHeight: 100)
                                    } else {
                                        if viewModel.isBuilding {
                                            ProgressView("Building Chain...")
                                        } else {
                                            Button("Build Full Chain") {
                                                viewModel.createFullChain()
                                            }
                                            .buttonStyle(.borderedProminent)
                                            .disabled(viewModel.certificateFile == nil)
                                            .controlSize(.large)
                                        }
                                    }
                                }
                            }
                        }
                        .padding()
                    }
                }
                .padding()
            }
        }
        .alert("Error", isPresented: $viewModel.showingError) {
            Button("OK") { }
        } message: {
            Text(viewModel.errorMessage)
        }
        .alert("Chain Builder", isPresented: $viewModel.showingSuccess) {
            Button("OK") { }
        } message: {
            Text(viewModel.successMessage)
        }
        .onAppear {
            viewModel.loadWorkingDirectoryFiles()
            viewModel.refreshChainStatus()
        }
    }
    
    func fileIcon(for url: URL) -> String {
        let ext = url.pathExtension.lowercased()
        switch ext {
        case "cer", "crt", "pem", "der", "cert":
            return "doc.badge.ellipsis"
        case "key":
            return "key.fill"
        case "pfx", "p12":
            return "lock.doc.fill"
        case "p7b":
            return "doc.text.fill"
        default:
            return "doc.fill"
        }
    }
    
    func fileColor(for url: URL) -> Color {
        let ext = url.pathExtension.lowercased()
        switch ext {
        case "cer", "crt", "pem", "der", "cert":
            return .blue
        case "key":
            return .purple
        case "pfx", "p12":
            return .pink
        case "p7b":
            return .orange
        default:
            return .gray
        }
    }
    
    func shortenPath(_ path: String) -> String {
        let components = path.split(separator: "/")
        if components.count > 2 {
            return ".../" + components.suffix(2).joined(separator: "/")
        }
        return path
    }
}

struct WorkflowCard<Content: View>: View {
    let title: String
    let icon: String
    let color: Color
    let content: Content
    
    init(title: String, icon: String, color: Color, @ViewBuilder content: () -> Content) {
        self.title = title
        self.icon = icon
        self.color = color
        self.content = content()
    }
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: icon)
                    .foregroundColor(color)
                    .font(.title3)
                Text(title)
                    .font(.headline)
                    .foregroundColor(.primary)
                Spacer()
            }
            .padding(.bottom, 4)
            
            content
        }
        .padding()
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(12)
        .shadow(color: Color.black.opacity(0.2), radius: 4, x: 0, y: 2)
    }
}
