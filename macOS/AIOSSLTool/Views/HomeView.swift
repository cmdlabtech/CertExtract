//
//  HomeView.swift
//  AIO SSL Tool
//

import SwiftUI

struct HomeView: View {
    @ObservedObject var viewModel: SSLToolViewModel
    @State private var iconImage: NSImage?
    
    var body: some View {
        ScrollView {
            VStack(spacing: 30) {
                // Icon
                Group {
                    if let icon = iconImage {
                        Image(nsImage: icon)
                            .resizable()
                            .aspectRatio(contentMode: .fit)
                            .frame(width: 220, height: 220)
                            .shadow(color: .blue.opacity(0.4), radius: 20, x: 0, y: 10)
                    } else {
                        // Fallback icon
                        ZStack {
                            Circle()
                                .fill(LinearGradient(
                                    colors: [.blue, .purple],
                                    startPoint: .topLeading,
                                    endPoint: .bottomTrailing
                                ))
                                .frame(width: 220, height: 220)
                                .shadow(color: .blue.opacity(0.4), radius: 20, x: 0, y: 10)
                            
                            Image(systemName: "lock.shield.fill")
                                .font(.system(size: 90))
                                .foregroundColor(.white)
                        }
                    }
                }
                .padding(.top, 60)
                .onAppear {
                    loadIcon()
                }
                
                // Title & Description
                VStack(spacing: 12) {
                    Text("Welcome to AIO SSL Tool")
                        .font(.title)
                        .fontWeight(.semibold)
                    
                    Text("Start by setting your working directory where all certificates will be saved")
                        .font(.body)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 400)
                }
                
                // Working Directory Section
                VStack(spacing: 16) {
                    if let directory = viewModel.saveDirectory {
                        HStack {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundColor(.green)
                                .font(.title2)
                            
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Working Directory Set")
                                    .font(.headline)
                                Text(directory.path)
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                            }
                            
                            Spacer()
                            
                            Button("Change") {
                                viewModel.selectSaveDirectory()
                            }
                            .buttonStyle(.bordered)
                        }
                        .padding()
                        .frame(maxWidth: 500)
                        .background(.regularMaterial)
                        .cornerRadius(12)
                        
                        Text("You can now use the Chain Builder and other tools from the sidebar")
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .padding(.top, 8)
                    } else {
                        Button(action: {
                            viewModel.selectSaveDirectory()
                        }) {
                            HStack {
                                Image(systemName: "folder.badge.plus")
                                    .font(.title3)
                                Text("Set Working Directory")
                                    .font(.headline)
                            }
                            .padding(.horizontal, 32)
                            .padding(.vertical, 16)
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.large)
                    }
                }
                
                // Quick Tips
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Image(systemName: "lightbulb.fill")
                            .foregroundColor(.yellow)
                        Text("Quick Tips")
                            .font(.headline)
                    }
                    
                    HStack(alignment: .top, spacing: 12) {
                        QuickTipView(
                            icon: "link.circle.fill",
                            title: "Chain Builder",
                            description: "Build complete certificate chains and create PFX files"
                        )
                        
                        QuickTipView(
                            icon: "doc.badge.plus",
                            title: "CSR Generator",
                            description: "Generate Certificate Signing Requests and private keys"
                        )
                        
                        QuickTipView(
                            icon: "shippingbox.fill",
                            title: "PFX Generator",
                            description: "Create PFX/P12 files from certificate chains and private keys"
                        )
                    }
                }
                .padding()
                .frame(maxWidth: 700)
                .background(.regularMaterial)
                .cornerRadius(12)
                .padding(.bottom, 30)
            }
            .padding()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
    
    private func loadIcon() {
        // Load from bundle
        if let bundleURL = Bundle.main.url(forResource: "HomeIcon", withExtension: "png"),
           let image = NSImage(contentsOf: bundleURL) {
            iconImage = image
        }
        // If not found, iconImage stays nil and system icon fallback is shown
    }
}

struct QuickTipView: View {
    let icon: String
    let title: String
    let description: String
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: icon)
                    .foregroundColor(.blue)
                    .font(.title3)
                Text(title)
                    .font(.subheadline)
                    .fontWeight(.semibold)
            }
            
            Text(description)
                .font(.caption)
                .foregroundColor(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }
}
