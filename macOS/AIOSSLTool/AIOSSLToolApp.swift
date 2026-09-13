//
//  AIOSSLToolApp.swift
//  CMDLAB AIO SSL Tool
//
//  Modern macOS SSL Certificate Management Tool
//

import SwiftUI

@main
struct AIOSSLToolApp: App {
    @StateObject private var updaterViewModel = UpdaterViewModel()
    
    var body: some Scene {
        WindowGroup {
            ContentView()
                .frame(minWidth: 900, minHeight: 750)
                .environmentObject(updaterViewModel)
        }
        .windowStyle(.hiddenTitleBar)
        .windowResizability(.contentSize)
        
        Settings {
            SettingsView()
                .environmentObject(updaterViewModel)
        }
    }
}
