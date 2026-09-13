//
//  UpdaterViewModel.swift
//  AIO SSL Tool
//
//  Manual Update Checker (opens GitHub release page for unsigned apps)
//

import SwiftUI
import AppKit

final class UpdaterViewModel: ObservableObject {
    @Published var canCheckForUpdates = true
    @Published var lastUpdateCheckDate: Date?
    @Published var automaticUpdateChecks = true
    @Published var automaticDownload = false
    @Published var isChecking = false
    @Published var showUpdateAlert = false
    @Published var latestVersion = ""
    @Published var releaseURL = ""
    @Published var neverShowAdvancedOptionsWarning = false
    @Published var enableCertificateArchive = false
    @Published var hideArchiveFolder = true
    
    private let appcastURL = "https://raw.githubusercontent.com/cmdlabtech/AIO-SSL-Tool/main/appcast.xml"
    private let fallbackReleaseURL = "https://github.com/cmdlabtech/AIO-SSL-Tool/releases/latest"
    
    init() {
        loadPreferences()
        
        if automaticUpdateChecks {
            DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
                self.checkForUpdatesInBackground()
            }
        }
    }
    
    // MARK: - Update Actions
    
    func checkForUpdates() {
        guard !isChecking else { return }
        
        isChecking = true
        canCheckForUpdates = false
        
        Task {
            await performUpdateCheck(showNoUpdateAlert: true)
            
            await MainActor.run {
                isChecking = false
                canCheckForUpdates = true
                lastUpdateCheckDate = Date()
                savePreferences()
            }
        }
    }
    
    func checkForUpdatesInBackground() {
        guard automaticUpdateChecks, !isChecking else { return }
        
        Task {
            await performUpdateCheck(showNoUpdateAlert: false)
            
            await MainActor.run {
                lastUpdateCheckDate = Date()
                savePreferences()
            }
        }
    }
    
    private func performUpdateCheck(showNoUpdateAlert: Bool) async {
        guard let url = URL(string: appcastURL) else { return }
        
        do {
            let (data, _) = try await URLSession.shared.data(from: url)
            guard let xmlString = String(data: data, encoding: .utf8) else { return }
            
            if let latestInfo = parseAppcast(xmlString) {
                await MainActor.run {
                    if isNewerVersion(latestInfo.version) {
                        self.latestVersion = latestInfo.displayVersion
                        self.releaseURL = latestInfo.url
                        self.showUpdateAlert = true
                    } else if showNoUpdateAlert {
                        showNoUpdatesAvailable()
                    }
                }
            }
        } catch {
            print("Update check failed: \(error)")
            if showNoUpdateAlert {
                await MainActor.run {
                    showUpdateCheckFailed()
                }
            }
        }
    }
    
    private func parseAppcast(_ xml: String) -> (version: Int, displayVersion: String, url: String)? {
        // Parse only the first <item> so we don't pick up the channel <link>
        guard let itemRange = xml.range(of: #"<item>[\s\S]*?</item>"#, options: .regularExpression) else {
            return nil
        }
        let item = String(xml[itemRange])
        
        guard let versionRange = item.range(of: #"<sparkle:version>(\d+)</sparkle:version>"#, options: .regularExpression),
              let shortVersionRange = item.range(of: #"<sparkle:shortVersionString>([\d.]+)</sparkle:shortVersionString>"#, options: .regularExpression) else {
            return nil
        }
        
        let versionText = String(item[versionRange])
        let shortVersionText = String(item[shortVersionRange])
        
        guard let versionMatch = versionText.range(of: #"\d+"#, options: .regularExpression),
              let shortVersionMatch = shortVersionText.range(of: #"[\d.]+"#, options: .regularExpression) else {
            return nil
        }
        
        let version = Int(String(versionText[versionMatch])) ?? 0
        let displayVersion = String(shortVersionText[shortVersionMatch])
        
        var url = fallbackReleaseURL
        if let enclosureRange = item.range(of: #"url="(https://[^"]+)""#, options: .regularExpression) {
            let enclosureText = String(item[enclosureRange])
            if let urlMatch = enclosureText.range(of: #"https://[^"]+"#, options: .regularExpression) {
                url = String(enclosureText[urlMatch])
            }
        } else if let linkRange = item.range(of: #"<link>(https://github\.com/[^<]+)</link>"#, options: .regularExpression) {
            let linkText = String(item[linkRange])
            if let urlMatch = linkText.range(of: #"https://[^<]+"#, options: .regularExpression) {
                url = String(linkText[urlMatch])
            }
        }
        
        return (version, displayVersion, url)
    }
    
    private func isNewerVersion(_ latestVersion: Int) -> Bool {
        let currentVersion = Int(buildNumber) ?? 0
        return latestVersion > currentVersion
    }
    
    func openReleaseURL() {
        let urlString = releaseURL.isEmpty ? fallbackReleaseURL : releaseURL
        if let url = URL(string: urlString) {
            NSWorkspace.shared.open(url)
        }
    }
    
    private func showNoUpdatesAvailable() {
        let alert = NSAlert()
        alert.messageText = "You're up to date!"
        alert.informativeText = "AIO SSL Tool \(currentVersion) is currently the latest version."
        alert.alertStyle = .informational
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }
    
    private func showUpdateCheckFailed() {
        let alert = NSAlert()
        alert.messageText = "Update Check Failed"
        alert.informativeText = "Unable to check for updates. Please check your internet connection."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }
    
    // MARK: - Settings
    
    func toggleAutomaticUpdates() {
        savePreferences()
    }
    
    func toggleAutomaticDownload() {
        automaticDownload.toggle()
        savePreferences()
    }
    
    // MARK: - Persistence
    
    private func loadPreferences() {
        if UserDefaults.standard.object(forKey: "AutomaticUpdateChecks") == nil {
            automaticUpdateChecks = true
        } else {
            automaticUpdateChecks = UserDefaults.standard.bool(forKey: "AutomaticUpdateChecks")
        }
        automaticDownload = UserDefaults.standard.bool(forKey: "AutomaticDownload")
        neverShowAdvancedOptionsWarning = UserDefaults.standard.bool(forKey: "NeverShowAdvancedOptionsWarning")
        enableCertificateArchive = UserDefaults.standard.bool(forKey: "EnableCertificateArchive")
        hideArchiveFolder = UserDefaults.standard.object(forKey: "HideArchiveFolder") as? Bool ?? true
        
        if let lastCheck = UserDefaults.standard.object(forKey: "LastUpdateCheckDate") as? Date {
            lastUpdateCheckDate = lastCheck
        }
    }
    
    func savePreferences() {
        UserDefaults.standard.set(automaticUpdateChecks, forKey: "AutomaticUpdateChecks")
        UserDefaults.standard.set(automaticDownload, forKey: "AutomaticDownload")
        UserDefaults.standard.set(neverShowAdvancedOptionsWarning, forKey: "NeverShowAdvancedOptionsWarning")
        UserDefaults.standard.set(enableCertificateArchive, forKey: "EnableCertificateArchive")
        UserDefaults.standard.set(hideArchiveFolder, forKey: "HideArchiveFolder")
        
        if let date = lastUpdateCheckDate {
            UserDefaults.standard.set(date, forKey: "LastUpdateCheckDate")
        }
    }
    
    // MARK: - Version Info
    
    var currentVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "Unknown"
    }
    
    var buildNumber: String {
        Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "Unknown"
    }
    
    var formattedLastCheckDate: String {
        guard let date = lastUpdateCheckDate else {
            return "Never"
        }
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        return formatter.localizedString(for: date, relativeTo: Date())
    }
}
