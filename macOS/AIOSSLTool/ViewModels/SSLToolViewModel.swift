//
//  SSLToolViewModel.swift
//  AIO SSL Tool
//

import SwiftUI
import AppKit
import AIOSSLToolCore

@MainActor
class SSLToolViewModel: ObservableObject {
    @Published var saveDirectory: URL?
    @Published var certificateFile: URL? {
        didSet { if certificateFile != oldValue { fullChainCreated = false } }
    }
    @Published var privateKeyFile: URL?
    @Published var keyPassphrase: String = ""
    @Published var pfxPassphrase: String = ""
    @Published var statusMessage: String = "Ready"
    @Published var isBuilding: Bool = false
    @Published var fullChainCreated: Bool = false
    @Published var pfxCreated: Bool = false
    @Published var hasError: Bool = false
    @Published var showingError: Bool = false
    @Published var showingSuccess: Bool = false
    @Published var errorMessage: String = ""
    @Published var successMessage: String = ""
    @Published var workingDirectoryFiles: [URL] = []
    
    private static let saveDirectoryKey = "SaveDirectoryPath"
    
    init() {
        if let path = UserDefaults.standard.string(forKey: Self.saveDirectoryKey),
           FileManager.default.fileExists(atPath: path) {
            saveDirectory = URL(fileURLWithPath: path)
            loadWorkingDirectoryFiles()
            refreshChainStatus()
        }
    }
    
    var canCreatePFX: Bool {
        privateKeyFile != nil && fullChainFileExists && !pfxPassphrase.isEmpty
    }
    
    var fullChainFileExists: Bool {
        guard let saveDir = saveDirectory else { return false }
        return FileManager.default.fileExists(atPath: saveDir.appendingPathComponent("FullChain.cer").path)
    }
    
    func refreshChainStatus() {
        fullChainCreated = fullChainFileExists
    }
    
    func selectSaveDirectory() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = "Select Save Location"
        
        if panel.runModal() == .OK {
            saveDirectory = panel.url
            UserDefaults.standard.set(panel.url?.path, forKey: Self.saveDirectoryKey)
            statusMessage = "Save location set"
            hasError = false
            loadWorkingDirectoryFiles()
            refreshChainStatus()
        }
    }
    
    func loadWorkingDirectoryFiles() {
        guard let directory = saveDirectory else {
            workingDirectoryFiles = []
            return
        }
        
        do {
            let fileManager = FileManager.default
            let files = try fileManager.contentsOfDirectory(
                at: directory,
                includingPropertiesForKeys: [.isRegularFileKey],
                options: [.skipsHiddenFiles]
            )
            
            // Chain builder should only list certificate files, not keys or PFX.
            let certificateExtensions = ["cer", "crt", "pem", "der", "cert"]
            workingDirectoryFiles = files.filter { url in
                let pathExtension = url.pathExtension.lowercased()
                return certificateExtensions.contains(pathExtension)
            }.sorted { $0.lastPathComponent < $1.lastPathComponent }
        } catch {
            workingDirectoryFiles = []
            print("Error loading directory files: \(error)")
        }
    }
    
    func selectCertificateFromDirectory(_ url: URL) {
        certificateFile = url
        statusMessage = "Certificate loaded"
        hasError = false
    }
    
    func browseCertificate() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowedContentTypes = [.x509Certificate, .data]
        panel.allowsOtherFileTypes = true
        panel.prompt = "Select Certificate"
        
        if panel.runModal() == .OK {
            certificateFile = panel.url
            statusMessage = "Certificate loaded"
            hasError = false
        }
    }
    
    func browsePrivateKey() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.prompt = "Select Private Key"
        panel.allowedContentTypes = [.data]
        
        if panel.runModal() == .OK {
            privateKeyFile = panel.url
            statusMessage = "Private key selected"
            hasError = false
        }
    }
    
    func createFullChain() {
        guard let certFile = certificateFile,
              let saveDir = saveDirectory else {
            showError("Missing certificate or save location")
            return
        }
        
        isBuilding = true
        statusMessage = "Building certificate chain..."
        
        let extraURLs = workingDirectoryFiles.filter { $0 != certFile }
        
        Task.detached {
            do {
                let certData = try Data(contentsOf: certFile)
                let certificates = try CertificateUtils.loadCertificates(from: certData)
                
                guard !certificates.isEmpty else {
                    throw SSLError.noCertificateFound
                }
                
                var additional: [Certificate] = []
                for url in extraURLs {
                    if let data = try? Data(contentsOf: url),
                       let certs = try? CertificateUtils.loadCertificates(from: data) {
                        additional.append(contentsOf: certs)
                    }
                }
                
                let result = CertificateUtils.buildCertificateChain(from: certificates, additional: additional)
                let chainData = result.chain.map { $0.pemRepresentation }.joined(separator: "\n")
                let chainPath = saveDir.appendingPathComponent("FullChain.cer")
                try chainData.write(to: chainPath, atomically: true, encoding: .utf8)
                
                let domain = result.chain.first?.subject
                let count = result.chain.count
                
                await MainActor.run {
                    self.fullChainCreated = true
                    self.isBuilding = false
                    self.hasError = false
                    self.loadWorkingDirectoryFiles()
                    self.archiveFiles([chainPath], domain: domain)
                    
                    if result.complete {
                        self.statusMessage = "Full chain saved: FullChain.cer (\(count) certificate\(count == 1 ? "" : "s"))"
                        self.showSuccess("Full chain saved: FullChain.cer (\(count) certificate\(count == 1 ? "" : "s"))")
                    } else {
                        self.statusMessage = "Chain saved (incomplete): FullChain.cer"
                        self.showSuccess("Chain saved with \(count) certificate\(count == 1 ? "" : "s"), but a root CA was not found. The chain may be incomplete — add intermediate certificates to the working directory and rebuild.")
                    }
                }
            } catch {
                await MainActor.run {
                    self.showError("Failed to build chain: \(error.localizedDescription)")
                    self.isBuilding = false
                }
            }
        }
    }
    
    func createPFX(chainFile: URL? = nil, options: PFXOptions = PFXOptions()) {
        guard let privateKey = privateKeyFile,
              let saveDir = saveDirectory,
              !pfxPassphrase.isEmpty else {
            showError("Missing private key, save location, or PFX password")
            return
        }
        
        let chainPath = chainFile ?? saveDir.appendingPathComponent("FullChain.cer")
        guard FileManager.default.fileExists(atPath: chainPath.path) else {
            showError("Certificate chain file not found. Build a chain or select a chain file first.")
            return
        }
        
        let keyPass = keyPassphrase
        let pfxPass = pfxPassphrase
        
        Task.detached {
            do {
                let chainData = try Data(contentsOf: chainPath)
                let certificates = try CertificateUtils.loadCertificates(from: chainData)
                let keyData = try Data(contentsOf: privateKey)
                
                let pfxData = try CertificateUtils.createPFX(
                    certificates: certificates,
                    privateKeyData: keyData,
                    keyPassword: keyPass.isEmpty ? nil : keyPass,
                    pfxPassword: pfxPass,
                    options: options
                )
                
                let pfxPath = saveDir.appendingPathComponent("FullChain-pfx.pfx")
                try pfxData.write(to: pfxPath, options: .atomic)
                CertificateUtils.setSecurePermissions(at: pfxPath.path)
                
                let domain = certificates.first?.subject
                
                await MainActor.run {
                    self.pfxCreated = true
                    self.statusMessage = "PFX created: FullChain-pfx.pfx"
                    self.archiveFiles([pfxPath], domain: domain)
                    self.loadWorkingDirectoryFiles()
                    self.showSuccess("PFX file created successfully!")
                }
            } catch {
                await MainActor.run {
                    self.showError("Failed to create PFX: \(error.localizedDescription)")
                }
            }
        }
    }
    
    func generateCSR(details: CSRDetails) {
        guard let saveDir = saveDirectory else {
            showError("Save directory not set")
            return
        }
        
        let csrPath = saveDir.appendingPathComponent("csr.pem")
        let keyPath = saveDir.appendingPathComponent("private_key.pem")
        
        Task.detached {
            do {
                let (csr, privateKeyPEM) = try CertificateUtils.generateCSR(details: details)
                
                do {
                    try csr.write(to: csrPath, atomically: true, encoding: .utf8)
                    try privateKeyPEM.write(to: keyPath, atomically: true, encoding: .utf8)
                    CertificateUtils.setSecurePermissions(at: keyPath.path)
                } catch {
                    try? FileManager.default.removeItem(at: csrPath)
                    try? FileManager.default.removeItem(at: keyPath)
                    throw error
                }
                
                let domain = details.commonName.isEmpty ? nil : details.commonName
                
                await MainActor.run {
                    self.privateKeyFile = keyPath
                    self.keyPassphrase = details.keyPassword ?? ""
                    self.statusMessage = "CSR + Key generated"
                    self.archiveFiles([csrPath, keyPath], domain: domain)
                    self.refreshChainStatus()
                    self.loadWorkingDirectoryFiles()
                    self.showSuccess("CSR and private key generated successfully!")
                }
            } catch {
                await MainActor.run {
                    self.showError("Failed to generate CSR: \(error.localizedDescription)")
                }
            }
        }
    }
    
    func showError(_ message: String) {
        errorMessage = message
        statusMessage = "Error"
        hasError = true
        showingError = true
    }
    
    func showSuccess(_ message: String) {
        successMessage = message
        showingSuccess = true
    }
    
    // MARK: - Certificate Archive
    
    /// Archives generated files to .archive/{domain}/{timestamp}/ inside the working directory.
    /// Subdomains are nested under their root domain (e.g., .archive/example.com/sub.example.com/2026-02-21_143022/).
    func archiveFiles(_ filePaths: [URL], domain: String?) {
        guard let saveDir = saveDirectory,
              UserDefaults.standard.bool(forKey: "EnableCertificateArchive") else { return }
        
        let fileManager = FileManager.default
        let timestamp = Self.archiveTimestamp()
        let domainPath = CertificateUtils.archiveDomainPath(for: domain)
        
        let folderName = (UserDefaults.standard.object(forKey: "HideArchiveFolder") as? Bool ?? true) ? ".archive" : "archive"
        let archiveDir = saveDir
            .appendingPathComponent(folderName)
            .appendingPathComponent(domainPath)
            .appendingPathComponent(timestamp)
        
        do {
            try fileManager.createDirectory(at: archiveDir, withIntermediateDirectories: true)
            
            for file in filePaths where fileManager.fileExists(atPath: file.path) {
                let dest = archiveDir.appendingPathComponent(file.lastPathComponent)
                try fileManager.copyItem(at: file, to: dest)
            }
        } catch {
            print("Archive error: \(error.localizedDescription)")
        }
    }
    
    /// Returns a timestamp string for archive folder names (e.g., "2026-02-21_143022").
    static func archiveTimestamp() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd_HHmmss"
        return formatter.string(from: Date())
    }
    
    static func archiveDomainPath(for domain: String?) -> String {
        CertificateUtils.archiveDomainPath(for: domain)
    }
}
