//
//  CSRDetails.swift
//  AIO SSL Tool
//
//  CSR generation model following industry standards:
//  - RFC 2986 (PKCS #10: Certification Request Syntax)
//  - RFC 5280 (X.509 Public Key Infrastructure Certificate and CRL Profile)
//  - NIST SP 800-57 (Recommendation for Key Management)
//  - FIPS 186-4 (Digital Signature Standard)
//

import Foundation

public enum KeyType: String, CaseIterable {
    case rsa = "RSA"
    case ecc = "ECC"
    
    public var minKeySize: Int {
        switch self {
        case .rsa: return 2048  // NIST SP 800-57: minimum 2048 bits for RSA
        case .ecc: return 256   // NIST SP 800-57: P-256 minimum
        }
    }
}

public enum ECCCurve: String, CaseIterable {
    case prime256v1 = "prime256v1"  // P-256 (NIST: FIPS 186-4, SECG: secp256r1)
    case secp384r1 = "secp384r1"    // P-384 (NIST: FIPS 186-4)
    case secp521r1 = "secp521r1"    // P-521 (NIST: FIPS 186-4)
    
    public var displayName: String {
        switch self {
        case .prime256v1: return "P-256 (prime256v1)"
        case .secp384r1: return "P-384 (secp384r1)"
        case .secp521r1: return "P-521 (secp521r1)"
        }
    }
    
    // Security strength in bits (per NIST SP 800-57)
    public var securityStrength: Int {
        switch self {
        case .prime256v1: return 128
        case .secp384r1: return 192
        case .secp521r1: return 256
        }
    }
}

public struct CSRDetails {
    public var commonName: String = ""
    public var country: String = ""
    public var state: String = ""
    public var locality: String = ""
    public var organization: String = ""
    public var organizationalUnit: String = ""
    public var email: String = ""
    public var sans: [String] = []
    public var keyType: KeyType = .rsa
    public var keySize: Int = 2048
    public var eccCurve: ECCCurve = .prime256v1
    public var keyPassword: String? = nil
    
    public init(
        commonName: String = "",
        country: String = "",
        state: String = "",
        locality: String = "",
        organization: String = "",
        organizationalUnit: String = "",
        email: String = "",
        sans: [String] = [],
        keyType: KeyType = .rsa,
        keySize: Int = 2048,
        eccCurve: ECCCurve = .prime256v1,
        keyPassword: String? = nil
    ) {
        self.commonName = commonName
        self.country = country
        self.state = state
        self.locality = locality
        self.organization = organization
        self.organizationalUnit = organizationalUnit
        self.email = email
        self.sans = sans
        self.keyType = keyType
        self.keySize = keySize
        self.eccCurve = eccCurve
        self.keyPassword = keyPassword
    }
}
