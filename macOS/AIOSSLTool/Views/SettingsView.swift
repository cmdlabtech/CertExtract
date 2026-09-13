//
//  SettingsView.swift
//  AIO SSL Tool
//

import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var updaterViewModel: UpdaterViewModel
    @State private var showSarcasticWarning = false
    @State private var iconImage: NSImage?
    
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Settings & About")
                    .font(.largeTitle)
                    .fontWeight(.bold)
                Spacer()
            }
            .padding()
            .background(.thinMaterial)
            
            ScrollView {
                VStack(spacing: 30) {
                    VStack(spacing: 16) {
                        if let icon = iconImage {
                            Image(nsImage: icon)
                                .resizable()
                                .aspectRatio(contentMode: .fit)
                                .frame(width: 100, height: 100)
                                .shadow(radius: 10)
                        } else {
                            Image(systemName: "lock.shield.fill")
                                .symbolRenderingMode(.hierarchical)
                                .foregroundStyle(
                                    LinearGradient(colors: [.blue, .purple], startPoint: .topLeading, endPoint: .bottomTrailing)
                                )
                                .font(.system(size: 80))
                                .shadow(radius: 10)
                        }
                        
                        Text("AIO SSL Suite")
                            .font(.title)
                            .fontWeight(.bold)
                        
                        Text("Version \(updaterViewModel.currentVersion)")
                            .font(.headline)
                            .foregroundColor(.secondary)
                            .padding(.horizontal, 12)
                            .padding(.vertical, 4)
                            .background(.ultraThinMaterial)
                            .cornerRadius(20)
                    }
                    .padding(.top, 40)
                    .onAppear {
                        loadIcon()
                    }
                    
                    VStack(alignment: .leading, spacing: 20) {
                        // Updates Section
                        GroupBox(label: Label("Updates", systemImage: "arrow.down.circle")) {
                            VStack(alignment: .leading, spacing: 12) {
                                HStack {
                                    Text("Last checked:")
                                    Spacer()
                                    Text(updaterViewModel.formattedLastCheckDate)
                                        .foregroundColor(.secondary)
                                }
                                
                                Divider()
                                
                                Toggle(isOn: $updaterViewModel.automaticUpdateChecks) {
                                    Text("Check for updates automatically")
                                }
                                .onChange(of: updaterViewModel.automaticUpdateChecks) {
                                    updaterViewModel.savePreferences()
                                }
                                
                                Divider()
                                
                                Button(action: {
                                    updaterViewModel.checkForUpdates()
                                }) {
                                    Label("Check for Updates", systemImage: "arrow.clockwise")
                                        .frame(maxWidth: .infinity)
                                }
                                .buttonStyle(.borderedProminent)
                                .disabled(!updaterViewModel.canCheckForUpdates)
                            }
                            .padding()
                        }
                        
                        GroupBox(label: Label("Advanced Options", systemImage: "gearshape.2")) {
                            VStack(alignment: .leading, spacing: 12) {
                                Toggle(isOn: $updaterViewModel.neverShowAdvancedOptionsWarning) {
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text("Never show advanced options warning")
                                        Text("Disable the caution message when using legacy cryptographic options")
                                            .font(.caption)
                                            .foregroundColor(.secondary)
                                    }
                                }
                                .onChange(of: updaterViewModel.neverShowAdvancedOptionsWarning) { _, newValue in
                                    if newValue {
                                        showSarcasticWarning = true
                                    }
                                    updaterViewModel.savePreferences()
                                }
                                
                                Divider()
                                
                                Toggle(isOn: $updaterViewModel.enableCertificateArchive) {
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text("Enable certificate archive")
                                        Text("Automatically save a timestamped copy of generated files, organized by domain")
                                            .font(.caption)
                                            .foregroundColor(.secondary)
                                    }
                                }
                                .onChange(of: updaterViewModel.enableCertificateArchive) {
                                    updaterViewModel.savePreferences()
                                }
                                
                                if updaterViewModel.enableCertificateArchive {
                                    Toggle(isOn: $updaterViewModel.hideArchiveFolder) {
                                        VStack(alignment: .leading, spacing: 4) {
                                            Text("Hide archive folder")
                                            Text("Archive folder will be hidden from Finder")
                                                .font(.caption)
                                                .foregroundColor(.secondary)
                                        }
                                    }
                                    .padding(.leading, 20)
                                    .onChange(of: updaterViewModel.hideArchiveFolder) {
                                        updaterViewModel.savePreferences()
                                    }

                                    HStack(spacing: 6) {
                                        Image(systemName: "info.circle")
                                            .foregroundColor(.blue)
                                        Text("Archives are saved to \(updaterViewModel.hideArchiveFolder ? ".archive" : "archive")/ inside your working directory, organized as domain/timestamp/")
                                            .font(.caption)
                                            .foregroundColor(.secondary)
                                    }
                                    .padding(.leading, 2)
                                }
                            }
                            .padding()
                        }
                        
                        GroupBox(label: Label("System", systemImage: "cpu")) {
                            VStack(alignment: .leading, spacing: 10) {
                                HStack {
                                    Text("Certificate Store")
                                    Spacer()
                                    Label("macOS Keychain", systemImage: "checkmark.seal.fill")
                                        .foregroundColor(.green)
                                }
                                Text("Chain building uses Apple's Security framework and the system keychain to locate issuers. CSR generation and PFX creation use the system OpenSSL (/usr/bin/openssl).")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                    .padding(.leading, 2)
                                HStack {
                                    Text("Local only")
                                    Spacer()
                                    Label("Yes", systemImage: "lock.fill")
                                        .foregroundColor(.green)
                                }
                                Text("Certificate files stay on your Mac. Network access is used only to check for app updates.")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                    .padding(.leading, 2)
                            }
                            .padding()
                        }
                        
                        GroupBox(label: Label("About", systemImage: "info.circle")) {
                            VStack(alignment: .leading, spacing: 10) {
                                Text("A modern, native macOS application for SSL certificate management.")
                                    .fixedSize(horizontal: false, vertical: true)
                                
                                Divider()
                                
                                HStack {
                                    Text("License")
                                    Spacer()
                                    Text("MIT")
                                        .foregroundColor(.secondary)
                                }
                                
                                HStack {
                                    Text("Developer")
                                    Spacer()
                                    Text("CMDLAB")
                                        .foregroundColor(.secondary)
                                }
                            }
                            .padding()
                        }
                    }
                    .padding()
                    .frame(maxWidth: 600)
                    
                    Spacer()
                    
                    Text("© 2026 CMDLAB. All rights reserved.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .padding(.bottom)
                }
            }
        }
        .alert("⚠️ SAFETY OFF ⚠️", isPresented: $showSarcasticWarning) {
            Button("I Like to Live Dangerously") {
                // Keep the setting enabled
            }
            Button("Actually, I Value My Security", role: .cancel) {
                // Revert the setting
                updaterViewModel.neverShowAdvancedOptionsWarning = false
                updaterViewModel.savePreferences()
            }
        } message: {
            Text("Somewhere, a help desk ticket was just pre-generated in your name. Subject: 'I don't know what happened.' Spoiler: this. This is what happened.")
        }
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
