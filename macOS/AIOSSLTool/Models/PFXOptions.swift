//
//  PFXOptions.swift
//  AIO SSL Tool
//

import Foundation

public struct PFXOptions {
    public enum MACAlgorithm: String, CaseIterable, Identifiable {
        case sha256 = "SHA-256"
        case sha512 = "SHA-512"
        case sha1 = "SHA-1"
        
        public var id: String { rawValue }
        
        public var opensslArg: String {
            switch self {
            case .sha1: return "sha1"
            case .sha256: return "sha256"
            case .sha512: return "sha512"
            }
        }
        
        public var isLegacy: Bool {
            self == .sha1
        }
    }
    
    public enum EncryptionAlgorithm: String, CaseIterable, Identifiable {
        case default_ = "Default"
        case aes256 = "AES-256"
        case aes128 = "AES-128"
        case tripledes = "3DES"
        case legacy = "Legacy"
        
        public var id: String { rawValue }
        
        public var opensslArgs: [String] {
            // Always pass explicit PBE algorithms. macOS ships LibreSSL, whose
            // pkcs12 defaults are RC2-40 + 3DES + SHA-1 — not AES-256.
            // OpenSSL 3's `-legacy` flag is not accepted by LibreSSL.
            switch self {
            case .default_, .aes256:
                return ["-certpbe", "AES-256-CBC", "-keypbe", "AES-256-CBC"]
            case .aes128:
                return ["-certpbe", "AES-128-CBC", "-keypbe", "AES-128-CBC"]
            case .tripledes:
                return ["-certpbe", "PBE-SHA1-3DES", "-keypbe", "PBE-SHA1-3DES"]
            case .legacy:
                return ["-certpbe", "PBE-SHA1-RC2-40", "-keypbe", "PBE-SHA1-3DES"]
            }
        }
        
        public var isLegacy: Bool {
            self == .legacy || self == .tripledes
        }
    }
    
    public var macAlgorithm: MACAlgorithm = .sha256
    public var encryptionAlgorithm: EncryptionAlgorithm = .default_
    public var useAdvancedOptions: Bool = false
    
    public init(
        macAlgorithm: MACAlgorithm = .sha256,
        encryptionAlgorithm: EncryptionAlgorithm = .default_,
        useAdvancedOptions: Bool = false
    ) {
        self.macAlgorithm = macAlgorithm
        self.encryptionAlgorithm = encryptionAlgorithm
        self.useAdvancedOptions = useAdvancedOptions
    }
    
    public var opensslArguments: [String] {
        var args: [String] = []
        args.append(contentsOf: encryptionAlgorithm.opensslArgs)
        // Always set MAC algorithm — LibreSSL defaults to SHA-1.
        args.append(contentsOf: ["-macalg", macAlgorithm.opensslArg])
        return args
    }
    
    public var isUsingLegacyOptions: Bool {
        macAlgorithm.isLegacy || encryptionAlgorithm.isLegacy
    }
    
    public var warningMessage: String? {
        if isUsingLegacyOptions {
            var warnings: [String] = []
            if macAlgorithm.isLegacy {
                warnings.append("SHA-1 MAC algorithm")
            }
            if encryptionAlgorithm.isLegacy {
                warnings.append("weak encryption")
            }
            return "Using " + warnings.joined(separator: " and ")
        }
        return nil
    }
}
