# Changelog

All notable changes to AIO SSL Tool will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [6.4.4] - 2026-09-12

### Fixed
- Windows: Chain Builder crashed (`queue` was never imported)
- Windows: CSRs with SANs crashed (`ipaddress` was never imported)
- Windows: ECDSA issuer verification used RSA-PSS, so ECC chains stayed incomplete
- Windows: DER `.cer` files were not loaded
- Windows: CSR email, archive domain, country validation, and empty-CN handling
- macOS: Automatic-update toggle inverted itself; launch update alerts never appeared
- macOS: Update download opened the repo homepage instead of the release
- macOS: Default PFX used LibreSSL RC2-40/3DES/SHA-1; `-legacy` failed on system OpenSSL
- macOS/Windows: Chain Builder could not rebuild after the first success
- PFX archive, private-key file permissions, and OpenSSL process timeouts on macOS

## [6.2.1] - 2026-02-22

### Fixed
- Sandboxing visual bug — app is now verified to run in macOS sandbox every time

### Added
- Certificate archive feature — automatically save timestamped copies of generated files, organized by domain

### Changed
- General improvements

## [6.1.3] - 2026-02-19

### Fixed
- Windows: Fix CSR Generator form view
- IP support for SANs for CSR generation

## [6.1.2] - 2026-02-19

### Added
- Advanced PFX Options with legacy crypto algorithm selection and caution warnings
- Quality of life improvements
- Unified cross-platform UI consistency
- Image aspect ratio fixes
- Enhanced build systems

## [6.0.0] - 2026-02-08

### Added
- **Native macOS Application**: Complete rewrite in Swift/SwiftUI for modern macOS experience
  - Native macOS 14.0+ (Sonoma/Sequoia) support
  - Dark mode interface with macOS design language
  - Optimized for Apple Silicon and Intel Macs
  - Custom app icon
  - Ad-hoc code signing for easy distribution
  
- **Improved UI/UX**:
  - Streamlined Chain Builder interface
  - Removed redundant buttons for cleaner workflow
  - Better working directory management
  - Visual feedback for all operations
  
- **Build System**:
  - Automated build script for macOS (`build.sh`)
  - Swift Package Manager integration
  - Automatic code signing and quarantine removal
  - DMG creation workflow

### Changed
- **macOS Version**: Minimum system requirement updated to macOS 14.0 (Sonoma)
- **Bundle Structure**: Properly structured .app bundle with Resources and Info.plist
- **Version Numbering**: Updated to v6.0.0 to align with Python version

### Fixed
- App icon aspect ratio (now properly square, not squished)
- Code signing issues preventing app launch on macOS
- "Damaged or incomplete" error on macOS
- Gatekeeper compatibility issues

### Technical Details
- Swift 5.9+
- SwiftUI for native macOS interface
- Targets arm64 and x86_64 architectures
- Uses OpenSSL/Security framework for certificate operations
- Ad-hoc signed for distribution without developer certificate

## [5.0.0] - Previous Release

### Features
- Python-based cross-platform application
- Tkinter GUI interface
- Certificate chain building
- CSR generation
- PFX extraction
- Windows EXE distribution

---

## Download Links

- **Latest Release (v6.0.0)**: [Download Page](https://github.com/cmdlabtech/AIO-SSL-Tool)
- **macOS DMG**: [AIOSSLTool-macOS-v6.0.0.dmg](releases/v6.0.0/AIOSSLTool-macOS-v6.0.0.dmg)
- **Windows EXE**: [AIOSSLTool-Windows-v6.0.0.exe](releases/v6.0.0/AIOSSLTool-Windows-v6.0.0.exe)
