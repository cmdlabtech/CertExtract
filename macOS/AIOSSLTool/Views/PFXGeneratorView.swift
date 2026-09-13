//
//  PFXGeneratorView.swift
//  AIO SSL Tool
//

import SwiftUI
import AIOSSLToolCore

struct PFXGeneratorView: View {
    @ObservedObject var viewModel: SSLToolViewModel
    @EnvironmentObject private var updaterViewModel: UpdaterViewModel
    @State private var isVerifyingPassword = false
    @State private var passwordVerified = false
    @State private var passwordVerificationFailed = false
    @State private var certificateChainFile: URL?
    @State private var pfxOptions = PFXOptions()
    @State private var showLegacyWarning = false
    @State private var showAdvancedOptions = false
    
    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                VStack(alignment: .leading) {
                    Text("PFX Generator")
                        .font(.largeTitle)
                        .fontWeight(.bold)
                    Text("Create PFX/P12 files from certificate chains and private keys")
                        .foregroundColor(.secondary)
                }
                Spacer()
            }
            .padding()
            .background(.thinMaterial)
            
            ScrollView {
                VStack(spacing: 30) {
                    
                    if viewModel.saveDirectory == nil {
                        ContentUnavailableView {
                            Label("Select working directory", systemImage: "folder.badge.plus")
                        } description: {
                            Text("Go to Home and set your working directory first.")
                        }
                        .frame(height: 300)
                    } else {
                        // Main Workflow Cards
                        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 20) {
                            
                            // Certificate Chain Card
                            WorkflowCard(title: "Certificate Chain", icon: "link.circle.fill", color: .blue) {
                                VStack(alignment: .leading, spacing: 10) {
                                    if let chainFile = certificateChainFile {
                                        HStack {
                                            Image(systemName: "checkmark.circle.fill")
                                                .foregroundColor(.green)
                                            VStack(alignment: .leading) {
                                                Text(chainFile.lastPathComponent)
                                                    .font(.headline)
                                                Text("Selected")
                                                    .font(.caption)
                                                    .foregroundColor(.secondary)
                                            }
                                            Spacer()
                                            Button("Change") {
                                                browseCertificateChain()
                                            }
                                            .buttonStyle(.link)
                                            .font(.caption)
                                        }
                                    } else {
                                        VStack(spacing: 12) {
                                            if viewModel.fullChainFileExists {
                                                VStack(spacing: 8) {
                                                    Image(systemName: "doc.badge.plus")
                                                        .font(.largeTitle)
                                                        .foregroundColor(.blue)
                                                    Text("FullChain.cer available")
                                                        .font(.caption)
                                                        .foregroundColor(.secondary)
                                                    
                                                    HStack(spacing: 12) {
                                                        Button(action: autofillChain) {
                                                            Label("Autofill", systemImage: "wand.and.stars")
                                                        }
                                                        .buttonStyle(.borderedProminent)
                                                        
                                                        Text("or")
                                                            .foregroundColor(.secondary)
                                                        
                                                        Button(action: browseCertificateChain) {
                                                            Text("Browse...")
                                                        }
                                                        .buttonStyle(.bordered)
                                                    }
                                                }
                                            } else {
                                                Button(action: browseCertificateChain) {
                                                    VStack {
                                                        Image(systemName: "doc.badge.plus")
                                                            .font(.largeTitle)
                                                        Text("Select Certificate Chain")
                                                    }
                                                    .frame(maxWidth: .infinity, minHeight: 80)
                                                    .background(Color.secondary.opacity(0.1))
                                                    .cornerRadius(8)
                                                }
                                                .buttonStyle(.plain)
                                            }
                                        }
                                        .frame(maxWidth: .infinity, minHeight: 100)
                                    }
                                }
                            }
                            
                            // Private Key Card
                            WorkflowCard(title: "Private Key", icon: "key", color: .purple) {
                                VStack(alignment: .leading, spacing: 12) {
                                    if let key = viewModel.privateKeyFile {
                                        HStack {
                                            Image(systemName: "checkmark.circle.fill")
                                                .foregroundColor(.green)
                                            Text(key.lastPathComponent)
                                                .font(.headline)
                                        }
                                        
                                        HStack {
                                            SecureField("Key Passphrase (Optional)", text: $viewModel.keyPassphrase)
                                                .textFieldStyle(.roundedBorder)
                                                .onChange(of: viewModel.keyPassphrase) {
                                                    passwordVerified = false
                                                    passwordVerificationFailed = false
                                                }
                                            
                                            Button(action: verifyPassword) {
                                                if isVerifyingPassword {
                                                    ProgressView()
                                                        .scaleEffect(0.7)
                                                        .frame(width: 20, height: 20)
                                                } else if passwordVerified {
                                                    Image(systemName: "checkmark.circle.fill")
                                                        .foregroundColor(.green)
                                                } else if passwordVerificationFailed {
                                                    Image(systemName: "xmark.circle.fill")
                                                        .foregroundColor(.red)
                                                } else {
                                                    Text("Verify")
                                                }
                                            }
                                            .buttonStyle(.bordered)
                                            .disabled(isVerifyingPassword)
                                        }
                                        
                                        if passwordVerified {
                                            HStack {
                                                Image(systemName: "checkmark.shield.fill")
                                                    .foregroundColor(.green)
                                                    .font(.caption)
                                                Text("Password verified")
                                                    .font(.caption)
                                                    .foregroundColor(.green)
                                            }
                                        } else if passwordVerificationFailed {
                                            HStack {
                                                Image(systemName: "exclamationmark.triangle.fill")
                                                    .foregroundColor(.orange)
                                                    .font(.caption)
                                                Text("Password verification failed")
                                                    .font(.caption)
                                                    .foregroundColor(.orange)
                                            }
                                        }
                                    } else {
                                        Button(action: { viewModel.browsePrivateKey() }) {
                                            VStack {
                                                Image(systemName: "lock.doc")
                                                    .font(.largeTitle)
                                                Text("Select Private Key")
                                            }
                                            .frame(maxWidth: .infinity, minHeight: 80)
                                            .background(Color.secondary.opacity(0.1))
                                            .cornerRadius(8)
                                        }
                                        .buttonStyle(.plain)
                                    }
                                    
                                    if viewModel.privateKeyFile != nil {
                                        Button("Change") { 
                                            viewModel.browsePrivateKey()
                                            passwordVerified = false
                                            passwordVerificationFailed = false
                                        }
                                        .font(.caption)
                                        .buttonStyle(.link)
                                    }
                                }
                            }
                        }
                        
                        // PFX Creation Section
                        VStack(spacing: 20) {
                            Image(systemName: "arrow.down.circle.fill")
                                .font(.system(size: 32))
                                .foregroundColor(.secondary)
                            
                            VStack(spacing: 16) {
                                Image(systemName: "shippingbox.fill")
                                    .font(.system(size: 48))
                                    .foregroundColor(.pink)
                                
                                Text("Create PFX File")
                                    .font(.title2)
                                    .fontWeight(.semibold)
                                
                                VStack(spacing: 12) {
                                    SecureField("PFX Password (Required)", text: $viewModel.pfxPassphrase)
                                        .textFieldStyle(.roundedBorder)
                                        .frame(maxWidth: 400)
                                    
                                    // Advanced Options
                                    DisclosureGroup(isExpanded: $showAdvancedOptions) {
                                        VStack(spacing: 16) {
                                            Divider().padding(.bottom, 4)
                                            
                                            // MAC Algorithm
                                            VStack(alignment: .leading, spacing: 8) {
                                                HStack {
                                                    Text("MAC Algorithm")
                                                        .font(.subheadline).fontWeight(.medium)
                                                    if pfxOptions.macAlgorithm.isLegacy {
                                                        Image(systemName: "exclamationmark.triangle.fill")
                                                            .foregroundColor(.orange).font(.caption)
                                                    }
                                                }
                                                Picker("", selection: $pfxOptions.macAlgorithm) {
                                                    ForEach(PFXOptions.MACAlgorithm.allCases) { algo in
                                                        Text(algo.rawValue).tag(algo)
                                                    }
                                                }
                                                .pickerStyle(.segmented)
                                                .onChange(of: pfxOptions.macAlgorithm) { _, newValue in
                                                    if newValue.isLegacy && !updaterViewModel.neverShowAdvancedOptionsWarning {
                                                        showLegacyWarning = true
                                                    }
                                                }
                                            }
                                            
                                            // Encryption Algorithm
                                            VStack(alignment: .leading, spacing: 8) {
                                                HStack {
                                                    Text("Encryption Algorithm")
                                                        .font(.subheadline).fontWeight(.medium)
                                                    if pfxOptions.encryptionAlgorithm.isLegacy {
                                                        Image(systemName: "exclamationmark.triangle.fill")
                                                            .foregroundColor(.orange).font(.caption)
                                                    }
                                                }
                                                Picker("", selection: $pfxOptions.encryptionAlgorithm) {
                                                    ForEach(PFXOptions.EncryptionAlgorithm.allCases) { algo in
                                                        Text(algo.rawValue).tag(algo)
                                                    }
                                                }
                                                .pickerStyle(.segmented)
                                                .onChange(of: pfxOptions.encryptionAlgorithm) { _, newValue in
                                                    if newValue.isLegacy && !updaterViewModel.neverShowAdvancedOptionsWarning {
                                                        showLegacyWarning = true
                                                    }
                                                }
                                            }
                                            
                                            // Warning
                                            if let warning = pfxOptions.warningMessage {
                                                HStack(spacing: 8) {
                                                    Image(systemName: "exclamationmark.triangle.fill")
                                                        .foregroundColor(.orange).font(.caption)
                                                    Text(warning).font(.caption).foregroundColor(.orange)
                                                }
                                                .padding(8).frame(maxWidth: .infinity)
                                                .background(Color.orange.opacity(0.1)).cornerRadius(6)
                                            }
                                        }
                                        .padding(.top, 8)
                                    } label: {
                                        HStack {
                                            Image(systemName: "gearshape.fill")
                                                .foregroundColor(.secondary).font(.caption)
                                            Text("Advanced Options")
                                                .font(.subheadline).fontWeight(.medium)
                                            if pfxOptions.isUsingLegacyOptions {
                                                Image(systemName: "exclamationmark.triangle.fill")
                                                    .foregroundColor(.orange).font(.caption)
                                            }
                                        }
                                    }
                                    .padding(.vertical, 4)
                                    .onChange(of: showAdvancedOptions) { _, isOpen in
                                        if isOpen && !updaterViewModel.neverShowAdvancedOptionsWarning {
                                            showLegacyWarning = true
                                        }
                                    }
                                    
                                    Button(action: createPFX) {
                                        Label("Create PFX File", systemImage: "sparkles")
                                            .font(.title3)
                                            .padding(.horizontal, 20)
                                            .padding(.vertical, 8)
                                    }
                                    .buttonStyle(.borderedProminent)
                                    .controlSize(.large)
                                    .disabled(certificateChainFile == nil || viewModel.privateKeyFile == nil || viewModel.pfxPassphrase.isEmpty)
                                    
                                    if viewModel.pfxCreated {
                                        HStack {
                                            Image(systemName: "checkmark.circle.fill")
                                                .foregroundColor(.green)
                                            Text("PFX Created Successfully!")
                                                .foregroundColor(.green)
                                                .font(.headline)
                                        }
                                        .padding()
                                        .background(Color.green.opacity(0.1))
                                        .cornerRadius(8)
                                    }
                                }
                            }
                            .padding(30)
                            .background(Color(NSColor.controlBackgroundColor))
                            .cornerRadius(12)
                            .shadow(radius: 2)
                        }
                        .padding(.top, 20)
                    }
                }
                .padding(40)
            }
        }
        .alert("Error", isPresented: $viewModel.showingError) {
            Button("OK") { }
        } message: {
            Text(viewModel.errorMessage)
        }
        .alert("Success", isPresented: $viewModel.showingSuccess) {
            Button("OK") { }
        } message: {
            Text(viewModel.successMessage)
        }
        .alert("Advanced Options - Caution", isPresented: $showLegacyWarning) {
            Button("I Understand", role: .none) { }
            Button("Go Back", role: .cancel) {
                showAdvancedOptions = false
                pfxOptions.macAlgorithm = .sha256
                pfxOptions.encryptionAlgorithm = .default_
            }
        } message: {
            Text("These advanced options allow customization of cryptographic algorithms used in PFX file generation.\n\nModifying these settings requires knowledge of cryptographic standards and compatibility requirements.\n\nPlease ensure you understand the implications before changing from the recommended defaults.\n\n(Tired of this warning? You can disable it in Settings → Advanced Options)")
        }
    }
    
    private func verifyPassword() {
        guard let keyFile = viewModel.privateKeyFile else { return }
        
        isVerifyingPassword = true
        passwordVerified = false
        passwordVerificationFailed = false
        
        let passphrase = viewModel.keyPassphrase
        
        Task.detached {
            do {
                let keyData = try Data(contentsOf: keyFile)
                
                let tempDir = FileManager.default.temporaryDirectory.path
                let uuid = UUID().uuidString
                let keyPath = (tempDir as NSString).appendingPathComponent("temp_\(uuid).key")
                let passFilePath = (tempDir as NSString).appendingPathComponent("temp_\(uuid).pass")
                
                defer {
                    try? FileManager.default.removeItem(atPath: keyPath)
                    try? FileManager.default.removeItem(atPath: passFilePath)
                }
                
                try keyData.write(to: URL(fileURLWithPath: keyPath), options: .atomic)
                CertificateUtils.setSecurePermissions(at: keyPath)
                
                var arguments = ["pkey", "-in", keyPath, "-noout"]
                
                if !passphrase.isEmpty {
                    try CertificateUtils.writeSecure(passphrase, to: passFilePath)
                    arguments.append(contentsOf: ["-passin", "file:\(passFilePath)"])
                } else {
                    arguments.append(contentsOf: ["-passin", "pass:"])
                }
                
                try CertificateUtils.runOpenSSL(arguments)
                
                await MainActor.run {
                    isVerifyingPassword = false
                    passwordVerified = true
                    passwordVerificationFailed = false
                }
            } catch {
                await MainActor.run {
                    isVerifyingPassword = false
                    passwordVerified = false
                    passwordVerificationFailed = true
                }
            }
        }
    }
    
    private func browseCertificateChain() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Select Certificate Chain"
        panel.allowedContentTypes = [.x509Certificate, .data]
        panel.allowsOtherFileTypes = true
        panel.message = "Select a certificate chain file (PEM or DER format)"
        
        if let saveDir = viewModel.saveDirectory {
            panel.directoryURL = saveDir
        }
        
        if panel.runModal() == .OK {
            certificateChainFile = panel.url
            viewModel.pfxCreated = false
        }
    }
    
    private func autofillChain() {
        guard let saveDir = viewModel.saveDirectory else { return }
        let chainPath = saveDir.appendingPathComponent("FullChain.cer")
        if FileManager.default.fileExists(atPath: chainPath.path) {
            certificateChainFile = chainPath
        }
    }
    
    private func createPFX() {
        guard let chainFile = certificateChainFile else {
            viewModel.showError("Missing certificate chain, private key, save location, or PFX password")
            return
        }
        viewModel.createPFX(chainFile: chainFile, options: pfxOptions)
    }
}
