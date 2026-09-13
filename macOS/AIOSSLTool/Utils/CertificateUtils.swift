//
//  CertificateUtils.swift
//  AIO SSL Tool
//
//  Certificate management utilities using Security framework + OpenSSL
//

import Foundation
import Security
import Darwin

public struct Certificate {
    public let secCertificate: SecCertificate
    public let data: Data
    
    public var pemRepresentation: String {
        let base64 = data.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN CERTIFICATE-----\n\(base64)\n-----END CERTIFICATE-----"
    }
    
    public var subject: String {
        if let summary = SecCertificateCopySubjectSummary(secCertificate) as String? {
            return summary
        }
        return ""
    }
}

public enum CertificateUtils {
    
    public static let openSSLTimeout: TimeInterval = 30
    
    // MARK: - Certificate Loading
    
    public static func loadCertificates(from data: Data) throws -> [Certificate] {
        var certificates: [Certificate] = []
        
        if let pemString = String(data: data, encoding: .utf8) {
            certificates = loadPEMCertificates(pemString)
        }
        
        if certificates.isEmpty {
            if let cert = loadDERCertificate(data) {
                certificates.append(cert)
            }
        }
        
        if certificates.isEmpty {
            throw SSLError.noCertificateFound
        }
        
        return certificates
    }
    
    private static func loadPEMCertificates(_ pemString: String) -> [Certificate] {
        var certificates: [Certificate] = []
        let pattern = "-----BEGIN CERTIFICATE-----([^-]+)-----END CERTIFICATE-----"
        
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators]) else {
            return []
        }
        
        let range = NSRange(pemString.startIndex..., in: pemString)
        let matches = regex.matches(in: pemString, range: range)
        
        for match in matches {
            if match.numberOfRanges >= 2,
               let base64Range = Range(match.range(at: 1), in: pemString) {
                let base64String = String(pemString[base64Range])
                    .replacingOccurrences(of: "\n", with: "")
                    .replacingOccurrences(of: "\r", with: "")
                    .replacingOccurrences(of: " ", with: "")
                
                if let certData = Data(base64Encoded: base64String),
                   let secCert = SecCertificateCreateWithData(nil, certData as CFData) {
                    certificates.append(Certificate(secCertificate: secCert, data: certData))
                }
            }
        }
        
        return certificates
    }
    
    private static func loadDERCertificate(_ data: Data) -> Certificate? {
        if let secCert = SecCertificateCreateWithData(nil, data as CFData) {
            return Certificate(secCertificate: secCert, data: data)
        }
        return nil
    }
    
    // MARK: - Distinguished Names
    
    /// Serializes a certificate name (subject or issuer) from SecCertificateCopyValues.
    public static func distinguishedName(_ certificate: SecCertificate, oid: CFString) -> String? {
        guard let values = SecCertificateCopyValues(certificate, [oid] as CFArray, nil) as? [String: Any],
              let entry = values[oid as String] as? [String: Any],
              let items = entry[kSecPropertyKeyValue as String] as? [[String: Any]] else {
            return nil
        }
        
        let parts = items.compactMap { item -> String? in
            guard let label = item[kSecPropertyKeyLabel as String] as? String,
                  let value = item[kSecPropertyKeyValue as String] as? String else {
                return nil
            }
            return "\(label)=\(value)"
        }
        return parts.isEmpty ? nil : parts.joined(separator: ",")
    }
    
    public static func subjectDistinguishedName(_ certificate: Certificate) -> String? {
        distinguishedName(certificate.secCertificate, oid: kSecOIDX509V1SubjectName)
    }
    
    public static func issuerDistinguishedName(_ certificate: Certificate) -> String? {
        distinguishedName(certificate.secCertificate, oid: kSecOIDX509V1IssuerName)
    }
    
    // MARK: - Certificate Chain Building
    
    public static func isSelfSigned(_ certificate: Certificate) -> Bool {
        if let subject = subjectDistinguishedName(certificate),
           let issuer = issuerDistinguishedName(certificate),
           !subject.isEmpty {
            return subject == issuer
        }
        
        // Fallback: compare subject summary vs issuer CN
        if let subject = SecCertificateCopySubjectSummary(certificate.secCertificate) as String?,
           let issuer = getIssuerSummary(certificate.secCertificate) {
            return subject == issuer
        }
        
        return false
    }
    
    private static func getIssuerSummary(_ certificate: SecCertificate) -> String? {
        var error: Unmanaged<CFError>?
        guard let values = SecCertificateCopyValues(certificate, nil, &error) as? [String: Any] else {
            return nil
        }
        
        if let issuerDict = values[kSecOIDX509V1IssuerName as String] as? [String: Any],
           let issuerValue = issuerDict[kSecPropertyKeyValue as String] as? [[String: Any]] {
            for item in issuerValue {
                if let label = item[kSecPropertyKeyLabel as String] as? String,
                   label.contains("CN") || label.contains("Common"),
                   let value = item[kSecPropertyKeyValue as String] as? String {
                    return value
                }
            }
        }
        
        return nil
    }
    
    /// Builds a chain using the system trust store, plus any extra intermediates supplied by the caller.
    public static func buildCertificateChain(from certificates: [Certificate], additional: [Certificate] = []) -> (chain: [Certificate], complete: Bool) {
        guard let leaf = certificates.first else {
            return ([], false)
        }
        
        var unique: [Certificate] = []
        for cert in certificates + additional {
            if !unique.contains(where: { certificatesMatch($0, cert) }) {
                unique.append(cert)
            }
        }
        
        var built: [Certificate] = []
        
        var trust: SecTrust?
        let certRefs = unique.map(\.secCertificate) as CFArray
        let policy = SecPolicyCreateBasicX509()
        if SecTrustCreateWithCertificates(certRefs, policy, &trust) == errSecSuccess, let trust {
            var error: CFError?
            _ = SecTrustEvaluateWithError(trust, &error)
            if let chainRefs = SecTrustCopyCertificateChain(trust) as? [SecCertificate] {
                built = chainRefs.compactMap { secCert in
                    let data = SecCertificateCopyData(secCert) as Data
                    return Certificate(secCertificate: secCert, data: data)
                }
            }
        }
        
        if built.isEmpty {
            built = unique
        }
        
        // Ensure the original leaf stays first
        if let first = built.first, !certificatesMatch(first, leaf) {
            built.removeAll { certificatesMatch($0, leaf) }
            built.insert(leaf, at: 0)
        }
        
        // Fallback: walk the keychain for missing issuers
        var current = built.last ?? leaf
        let maxChainDepth = 15
        while !isSelfSigned(current) && built.count < maxChainDepth {
            if let issuer = try? fetchIssuerFromKeychain(for: current) {
                if built.contains(where: { certificatesMatch($0, issuer) }) {
                    break
                }
                built.append(issuer)
                current = issuer
            } else {
                break
            }
        }
        
        let complete = built.last.map { isSelfSigned($0) } ?? false
        return (built, complete)
    }
    
    public static func fetchIssuerFromKeychain(for certificate: Certificate) throws -> Certificate? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true
        ]
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let certificates = result as? [SecCertificate] else {
            return nil
        }
        
        for secCert in certificates {
            let certData = SecCertificateCopyData(secCert) as Data
            let candidate = Certificate(secCertificate: secCert, data: certData)
            
            if isIssuerOf(candidate, for: certificate) {
                return candidate
            }
        }
        
        return nil
    }
    
    public static func isIssuerOf(_ issuer: Certificate, for certificate: Certificate) -> Bool {
        if certificatesMatch(issuer, certificate) {
            return isSelfSigned(certificate)
        }
        
        guard let certIssuer = issuerDistinguishedName(certificate),
              let issuerSubject = subjectDistinguishedName(issuer),
              !certIssuer.isEmpty,
              certIssuer == issuerSubject else {
            return false
        }
        
        return true
    }
    
    public static func certificatesMatch(_ cert1: Certificate, _ cert2: Certificate) -> Bool {
        return cert1.data == cert2.data
    }
    
    // MARK: - CSR Generation
    
    /// Generate a Certificate Signing Request (CSR) and private key
    public static func generateCSR(details: CSRDetails) throws -> (csr: String, privateKey: String) {
        let tempDir = FileManager.default.temporaryDirectory.path
        let uuid = UUID().uuidString
        let keyPath = (tempDir as NSString).appendingPathComponent("temp_\(uuid).key")
        let csrPath = (tempDir as NSString).appendingPathComponent("temp_\(uuid).csr")
        let configPath = (tempDir as NSString).appendingPathComponent("temp_\(uuid).conf")
        
        defer {
            try? FileManager.default.removeItem(atPath: keyPath)
            try? FileManager.default.removeItem(atPath: csrPath)
            try? FileManager.default.removeItem(atPath: configPath)
        }
        
        let config = createOpenSSLConfig(details: details)
        try writeSecure(config, to: configPath)
        
        if details.keyType == .rsa {
            try generateRSAKeyAndCSR(details: details, keyPath: keyPath, csrPath: csrPath, configPath: configPath)
        } else {
            try generateECCKeyAndCSR(details: details, keyPath: keyPath, csrPath: csrPath, configPath: configPath)
        }
        
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyPath)
        
        guard let csrData = try? Data(contentsOf: URL(fileURLWithPath: csrPath)),
              let csrPEM = String(data: csrData, encoding: .utf8) else {
            throw openSSLError("Failed to read generated CSR")
        }
        
        guard let keyData = try? Data(contentsOf: URL(fileURLWithPath: keyPath)),
              var keyPEM = String(data: keyData, encoding: .utf8) else {
            throw openSSLError("Failed to read generated private key")
        }
        
        if let password = details.keyPassword, !password.isEmpty {
            keyPEM = try encryptPrivateKey(keyPEM: keyPEM, password: password, keyType: details.keyType)
        }
        
        return (csrPEM, keyPEM)
    }
    
    /// Escapes special characters in a DN field value per RFC 2253.
    public static func escapeDNValue(_ value: String) -> String {
        let escaped = value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "/", with: "\\/")
            .replacingOccurrences(of: ",", with: "\\,")
            .replacingOccurrences(of: "+", with: "\\+")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "<", with: "\\<")
            .replacingOccurrences(of: ">", with: "\\>")
            .replacingOccurrences(of: ";", with: "\\;")
        return escaped
    }
    
    /// Escapes OpenSSL config values (SANs, DN fields in the config file).
    public static func escapeConfigValue(_ value: String) -> String {
        value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "\r", with: "")
    }
    
    private static func subjectString(from details: CSRDetails) -> String {
        var subject = ""
        if !details.country.isEmpty { subject += "/C=\(escapeDNValue(details.country))" }
        if !details.state.isEmpty { subject += "/ST=\(escapeDNValue(details.state))" }
        if !details.locality.isEmpty { subject += "/L=\(escapeDNValue(details.locality))" }
        if !details.organization.isEmpty { subject += "/O=\(escapeDNValue(details.organization))" }
        if !details.organizationalUnit.isEmpty { subject += "/OU=\(escapeDNValue(details.organizationalUnit))" }
        if !details.commonName.isEmpty { subject += "/CN=\(escapeDNValue(details.commonName))" }
        if !details.email.isEmpty { subject += "/emailAddress=\(escapeDNValue(details.email))" }
        return subject
    }
    
    private static func generateRSAKeyAndCSR(details: CSRDetails, keyPath: String, csrPath: String, configPath: String) throws {
        let arguments = [
            "req",
            "-new",
            "-newkey", "rsa:\(details.keySize)",
            "-nodes",
            "-sha256",
            "-utf8",
            "-keyout", keyPath,
            "-out", csrPath,
            "-subj", subjectString(from: details),
            "-config", configPath
        ]
        
        try runOpenSSL(arguments)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyPath)
    }
    
    private static func generateECCKeyAndCSR(details: CSRDetails, keyPath: String, csrPath: String, configPath: String) throws {
        try runOpenSSL([
            "ecparam",
            "-name", details.eccCurve.rawValue,
            "-genkey",
            "-noout",
            "-out", keyPath
        ])
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyPath)
        
        try runOpenSSL([
            "req",
            "-new",
            "-key", keyPath,
            "-sha256",
            "-utf8",
            "-out", csrPath,
            "-subj", subjectString(from: details),
            "-config", configPath
        ])
    }
    
    public static func createOpenSSLConfig(details: CSRDetails) -> String {
        var config = """
        [ req ]
        default_bits = \(details.keySize)
        distinguished_name = req_distinguished_name
        req_extensions = v3_req
        prompt = no
        utf8 = yes
        
        [ req_distinguished_name ]
        """
        
        if !details.country.isEmpty { config += "\nC = \(escapeConfigValue(details.country))" }
        if !details.state.isEmpty { config += "\nST = \(escapeConfigValue(details.state))" }
        if !details.locality.isEmpty { config += "\nL = \(escapeConfigValue(details.locality))" }
        if !details.organization.isEmpty { config += "\nO = \(escapeConfigValue(details.organization))" }
        if !details.organizationalUnit.isEmpty { config += "\nOU = \(escapeConfigValue(details.organizationalUnit))" }
        if !details.commonName.isEmpty { config += "\nCN = \(escapeConfigValue(details.commonName))" }
        if !details.email.isEmpty { config += "\nemailAddress = \(escapeConfigValue(details.email))" }
        
        let keyUsage = details.keyType == .rsa
            ? "digitalSignature, keyEncipherment"
            : "digitalSignature"
        
        config += """
        
        
        [ v3_req ]
        basicConstraints = CA:FALSE
        keyUsage = critical, \(keyUsage)
        extendedKeyUsage = serverAuth, clientAuth
        """
        
        if !details.sans.isEmpty {
            config += "\nsubjectAltName = @alt_names\n\n[ alt_names ]\n"
            for (index, san) in details.sans.enumerated() {
                let prefix = isIPAddress(san) ? "IP" : "DNS"
                config += "\(prefix).\(index + 1) = \(escapeConfigValue(san))\n"
            }
        }
        
        return config
    }
    
    public static func isIPAddress(_ san: String) -> Bool {
        let trimmed = san.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return false }
        
        var ipv4Addr = in_addr()
        if trimmed.withCString({ inet_pton(AF_INET, $0, &ipv4Addr) }) == 1 {
            return true
        }
        
        var ipv6Addr = in6_addr()
        if trimmed.withCString({ inet_pton(AF_INET6, $0, &ipv6Addr) }) == 1 {
            return true
        }
        
        return false
    }
    
    private static func encryptPrivateKey(keyPEM: String, password: String, keyType: KeyType) throws -> String {
        let tempDir = FileManager.default.temporaryDirectory.path
        let uuid = UUID().uuidString
        let unencryptedKeyPath = (tempDir as NSString).appendingPathComponent("temp_\(uuid)_unenc.key")
        let encryptedKeyPath = (tempDir as NSString).appendingPathComponent("temp_\(uuid)_enc.key")
        let passFilePath = (tempDir as NSString).appendingPathComponent("temp_\(uuid)_pass.txt")
        
        defer {
            try? FileManager.default.removeItem(atPath: unencryptedKeyPath)
            try? FileManager.default.removeItem(atPath: encryptedKeyPath)
            try? FileManager.default.removeItem(atPath: passFilePath)
        }
        
        try writeSecure(keyPEM, to: unencryptedKeyPath)
        try writeSecure(password, to: passFilePath)
        
        let algorithm = keyType == .rsa ? "rsa" : "ec"
        try runOpenSSL([
            algorithm,
            "-in", unencryptedKeyPath,
            "-out", encryptedKeyPath,
            "-aes256",
            "-passout", "file:\(passFilePath)"
        ])
        
        guard let encryptedData = try? Data(contentsOf: URL(fileURLWithPath: encryptedKeyPath)),
              let encryptedPEM = String(data: encryptedData, encoding: .utf8) else {
            throw openSSLError("Failed to read encrypted private key")
        }
        
        return encryptedPEM
    }
    
    // MARK: - PFX Operations
    
    public static func createPFX(certificates: [Certificate], privateKeyData: Data, keyPassword: String?, pfxPassword: String, options: PFXOptions = PFXOptions()) throws -> Data {
        let tempDir = FileManager.default.temporaryDirectory.path
        let uuid = UUID().uuidString
        let certPath = (tempDir as NSString).appendingPathComponent("temp_\(uuid).crt")
        let keyPath = (tempDir as NSString).appendingPathComponent("temp_\(uuid).key")
        let pfxPath = (tempDir as NSString).appendingPathComponent("temp_\(uuid).pfx")
        let keyPassFilePath = (tempDir as NSString).appendingPathComponent("temp_\(uuid)_keypass.txt")
        let pfxPassFilePath = (tempDir as NSString).appendingPathComponent("temp_\(uuid)_pfxpass.txt")
        
        defer {
            try? FileManager.default.removeItem(atPath: certPath)
            try? FileManager.default.removeItem(atPath: keyPath)
            try? FileManager.default.removeItem(atPath: pfxPath)
            try? FileManager.default.removeItem(atPath: keyPassFilePath)
            try? FileManager.default.removeItem(atPath: pfxPassFilePath)
        }
        
        let chainPEM = certificates.map { $0.pemRepresentation }.joined(separator: "\n")
        try writeSecure(chainPEM, to: certPath)
        try privateKeyData.write(to: URL(fileURLWithPath: keyPath), options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyPath)
        try writeSecure(pfxPassword, to: pfxPassFilePath)
        
        var arguments = [
            "pkcs12",
            "-export",
            "-out", pfxPath,
            "-inkey", keyPath,
            "-in", certPath,
            "-passout", "file:\(pfxPassFilePath)"
        ]
        
        arguments.append(contentsOf: options.opensslArguments)
        
        if let keyPass = keyPassword, !keyPass.isEmpty {
            try writeSecure(keyPass, to: keyPassFilePath)
            arguments.append(contentsOf: ["-passin", "file:\(keyPassFilePath)"])
        } else {
            arguments.append(contentsOf: ["-passin", "pass:"])
        }
        
        try runOpenSSL(arguments)
        
        guard FileManager.default.fileExists(atPath: pfxPath),
              let pfxData = try? Data(contentsOf: URL(fileURLWithPath: pfxPath)) else {
            throw openSSLError("Failed to read created PFX file.")
        }
        
        return pfxData
    }
    
    // MARK: - Archive Path
    
    /// Determines archive path from a domain string.
    /// - "example.com" → "example.com"
    /// - "sub.example.com" → "example.com/sub.example.com"
    public static func archiveDomainPath(for domain: String?) -> String {
        guard var clean = domain?.trimmingCharacters(in: .whitespaces),
              !clean.isEmpty else { return "unknown" }
        
        if clean.hasPrefix("*.") {
            clean = String(clean.dropFirst(2))
        }
        
        let parts = clean.lowercased().split(separator: ".")
        
        if parts.count <= 2 {
            return clean.lowercased()
        }
        
        let root = parts.suffix(2).joined(separator: ".")
        return "\(root)/\(clean.lowercased())"
    }
    
    // MARK: - OpenSSL process helper
    
    public static func writeSecure(_ string: String, to path: String) throws {
        try string.write(to: URL(fileURLWithPath: path), atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
    }
    
    public static func setSecurePermissions(at path: String) {
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
    }
    
    @discardableResult
    public static func runOpenSSL(_ arguments: [String], timeout: TimeInterval = openSSLTimeout) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = arguments
        
        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe
        
        do {
            try process.run()
        } catch {
            throw openSSLError("Failed to execute OpenSSL: \(error.localizedDescription)")
        }
        
        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }
        
        if process.isRunning {
            process.terminate()
            Thread.sleep(forTimeInterval: 0.2)
            if process.isRunning {
                kill(process.processIdentifier, SIGKILL)
            }
            throw openSSLError("OpenSSL timed out after \(Int(timeout)) seconds")
        }
        
        let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
        let errString = String(data: errData, encoding: .utf8) ?? ""
        
        if process.terminationStatus != 0 {
            let trimmed = errString.trimmingCharacters(in: .whitespacesAndNewlines)
            throw openSSLError(trimmed.isEmpty ? "OpenSSL failed with status \(process.terminationStatus)" : trimmed)
        }
        
        let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: outData, encoding: .utf8) ?? ""
    }
    
    private static func openSSLError(_ message: String) -> NSError {
        NSError(
            domain: "CertificateUtils",
            code: -1,
            userInfo: [NSLocalizedDescriptionKey: message]
        )
    }
}

public enum SSLError: LocalizedError {
    case noCertificateFound
    case invalidCertificate
    case chainBuildFailed
    case pfxCreationFailed
    
    public var errorDescription: String? {
        switch self {
        case .noCertificateFound:
            return "No valid certificate found in file"
        case .invalidCertificate:
            return "Invalid or corrupted certificate"
        case .chainBuildFailed:
            return "Failed to build certificate chain"
        case .pfxCreationFailed:
            return "Failed to create PFX file"
        }
    }
}
