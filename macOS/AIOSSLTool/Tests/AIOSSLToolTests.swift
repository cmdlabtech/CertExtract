import XCTest
import Foundation
@testable import AIOSSLToolCore

final class AIOSSLToolTests: XCTestCase {
    
    func testArchiveDomainPath() {
        XCTAssertEqual(CertificateUtils.archiveDomainPath(for: nil), "unknown")
        XCTAssertEqual(CertificateUtils.archiveDomainPath(for: ""), "unknown")
        XCTAssertEqual(CertificateUtils.archiveDomainPath(for: "   "), "unknown")
        XCTAssertEqual(CertificateUtils.archiveDomainPath(for: "example.com"), "example.com")
        XCTAssertEqual(CertificateUtils.archiveDomainPath(for: "*.example.com"), "example.com")
        XCTAssertEqual(CertificateUtils.archiveDomainPath(for: "www.example.com"), "example.com/www.example.com")
        XCTAssertEqual(CertificateUtils.archiveDomainPath(for: "Deep.Sub.Example.COM"), "example.com/deep.sub.example.com")
    }
    
    func testIsIPAddress() {
        XCTAssertTrue(CertificateUtils.isIPAddress("127.0.0.1"))
        XCTAssertTrue(CertificateUtils.isIPAddress("192.168.1.10"))
        XCTAssertTrue(CertificateUtils.isIPAddress("::1"))
        XCTAssertTrue(CertificateUtils.isIPAddress("2001:db8::1"))
        XCTAssertFalse(CertificateUtils.isIPAddress("example.com"))
        XCTAssertFalse(CertificateUtils.isIPAddress("999.999.999.999"))
        XCTAssertFalse(CertificateUtils.isIPAddress(""))
    }
    
    func testEscapeDNValue() {
        XCTAssertEqual(CertificateUtils.escapeDNValue("example.com"), "example.com")
        XCTAssertEqual(CertificateUtils.escapeDNValue("Acme/Corp"), "Acme\\/Corp")
        XCTAssertTrue(CertificateUtils.escapeDNValue("a/b").contains("\\/"))
        XCTAssertTrue(CertificateUtils.escapeDNValue("a,b").contains("\\,"))
        XCTAssertTrue(CertificateUtils.escapeDNValue("a+b").contains("\\+"))
    }
    
    func testPFXDefaultArgsAreStrongAndLibreSSLCompatible() {
        let options = PFXOptions()
        let args = options.opensslArguments
        XCTAssertFalse(args.contains("-legacy"), "LibreSSL rejects OpenSSL 3's -legacy flag")
        XCTAssertTrue(args.contains("AES-256-CBC"))
        XCTAssertTrue(args.contains("-macalg"))
        XCTAssertTrue(args.contains("sha256"))
    }
    
    func testPFXLegacyArgsAvoidDashLegacyFlag() {
        var options = PFXOptions()
        options.encryptionAlgorithm = .legacy
        options.macAlgorithm = .sha1
        let args = options.opensslArguments
        XCTAssertFalse(args.contains("-legacy"))
        XCTAssertTrue(args.contains("PBE-SHA1-RC2-40"))
        XCTAssertTrue(args.contains("sha1"))
        XCTAssertTrue(options.isUsingLegacyOptions)
        XCTAssertTrue(PFXOptions.EncryptionAlgorithm.tripledes.isLegacy)
    }
    
    func testOpenSSLConfigMarksIPSansAndOmitsKeyEnciphermentForECC() {
        var rsa = CSRDetails()
        rsa.commonName = "example.com"
        rsa.keyType = .rsa
        rsa.sans = ["www.example.com", "127.0.0.1"]
        let rsaConfig = CertificateUtils.createOpenSSLConfig(details: rsa)
        XCTAssertTrue(rsaConfig.contains("DNS.1 = www.example.com"))
        XCTAssertTrue(rsaConfig.contains("IP.2 = 127.0.0.1"))
        XCTAssertTrue(rsaConfig.contains("keyEncipherment"))
        XCTAssertTrue(rsaConfig.contains("basicConstraints = CA:FALSE"))
        
        var ecc = CSRDetails()
        ecc.commonName = "example.com"
        ecc.keyType = .ecc
        let eccConfig = CertificateUtils.createOpenSSLConfig(details: ecc)
        XCTAssertFalse(eccConfig.contains("keyEncipherment"))
        XCTAssertTrue(eccConfig.contains("digitalSignature"))
    }
    
    func testLoadPEMCertificates() throws {
        let pem = try generateSelfSignedPEM()
        let certs = try CertificateUtils.loadCertificates(from: Data(pem.utf8))
        XCTAssertEqual(certs.count, 1)
        XCTAssertTrue(CertificateUtils.isSelfSigned(certs[0]))
    }
    
    func testGenerateCSRRoundTrip() throws {
        var details = CSRDetails()
        details.commonName = "test.example.com"
        details.country = "US"
        details.organization = "CMDLAB"
        details.sans = ["www.test.example.com", "127.0.0.1"]
        details.keyType = .rsa
        details.keySize = 2048
        
        let result = try CertificateUtils.generateCSR(details: details)
        XCTAssertTrue(result.csr.contains("BEGIN CERTIFICATE REQUEST"))
        XCTAssertTrue(result.privateKey.contains("BEGIN") && result.privateKey.contains("PRIVATE KEY"))
        XCTAssertFalse(result.privateKey.contains("ENCRYPTED"))
    }
    
    func testCreatePFXWithDefaultOptions() throws {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }
        
        let keyPath = tmp.appendingPathComponent("key.pem").path
        let certPath = tmp.appendingPathComponent("cert.pem").path
        try CertificateUtils.runOpenSSL([
            "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", keyPath, "-out", certPath,
            "-days", "1", "-subj", "/CN=pfx.test"
        ])
        
        let certData = try Data(contentsOf: URL(fileURLWithPath: certPath))
        let keyData = try Data(contentsOf: URL(fileURLWithPath: keyPath))
        let certs = try CertificateUtils.loadCertificates(from: certData)
        
        let pfx = try CertificateUtils.createPFX(
            certificates: certs,
            privateKeyData: keyData,
            keyPassword: nil,
            pfxPassword: "test-password"
        )
        XCTAssertGreaterThan(pfx.count, 0)
    }
    
    private func generateSelfSignedPEM() throws -> String {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }
        
        let keyPath = tmp.appendingPathComponent("key.pem").path
        let certPath = tmp.appendingPathComponent("cert.pem").path
        try CertificateUtils.runOpenSSL([
            "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", keyPath, "-out", certPath,
            "-days", "1", "-subj", "/CN=test.example.com"
        ])
        return try String(contentsOfFile: certPath, encoding: .utf8)
    }
}
