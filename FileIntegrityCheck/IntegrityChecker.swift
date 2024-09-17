//
//  IntegrityChecker.swift
//  FileIntegrityCheck
//
//  Created by APPLE on 16/09/24.
//

import Foundation
import CommonCrypto
import MachO

class IntegrityChecker: ObservableObject {
    @Published var appSourceCodeIntegrity: Bool?
    @Published var provisionFileIntegrity: Bool?
    
    private var knownTextSectionHash: String?
    private var knownProvisionFileHash: String?
    
    func performChecks(completion: @escaping () -> Void) {
        fetchKnownHashValues { [weak self] success in
            if success {
                print("✅ Successfully fetched known hash values")
                self?.checkAppSourceCodeIntegrity()
                self?.checkProvisionFileIntegrity()
            } else {
                print("❌ Failed to fetch known hash values")
                DispatchQueue.main.async {
                    self?.appSourceCodeIntegrity = false
                    self?.provisionFileIntegrity = false
                }
            }
            DispatchQueue.main.async {
                completion()
            }
        }
    }
    
    private func fetchKnownHashValues(completion: @escaping (Bool) -> Void) {
        print("📡 Fetching known hash values from server...")
        let group = DispatchGroup()
        var success = true
        
        group.enter()
        fetchHash(from: "https://raw.githubusercontent.com/Xplo8E/IOSSecuritySuiteAPP/master/Values/MainBinaryHash") { [weak self] result in
            switch result {
            case .success(let hash):
                self?.knownTextSectionHash = hash
                print("📥 Received MainBinaryHash: \(hash)")
            case .failure(let error):
                print("❌ Failed to fetch MainBinaryHash: \(error)")
                success = false
            }
            group.leave()
        }
        
        group.enter()
        fetchHash(from: "https://raw.githubusercontent.com/Xplo8E/IOSSecuritySuiteAPP/master/Values/ProvisionHash") { [weak self] result in
            switch result {
            case .success(let hash):
                self?.knownProvisionFileHash = hash
                print("📥 Received ProvisionHash: \(hash)")
            case .failure(let error):
                print("❌ Failed to fetch ProvisionHash: \(error)")
                success = false
            }
            group.leave()
        }
        
        group.notify(queue: .main) {
            completion(success)
        }
    }
    
    private func fetchHash(from urlString: String, completion: @escaping (Result<String, Error>) -> Void) {
        guard let url = URL(string: urlString) else {
            print("❌ Invalid URL: \(urlString)")
            completion(.failure(NSError(domain: "Invalid URL", code: 0, userInfo: nil)))
            return
        }
        
        print("🌐 Fetching hash from: \(urlString)")
        URLSession.shared.dataTask(with: url) { data, response, error in
            if let error = error {
                print("❌ Network error: \(error)")
                completion(.failure(error))
                return
            }
            
            guard let data = data, let hash = String(data: data, encoding: .utf8) else {
                print("❌ Invalid data received from server")
                completion(.failure(NSError(domain: "Invalid data", code: 0, userInfo: nil)))
                return
            }
            
            completion(.success(hash.trimmingCharacters(in: .whitespacesAndNewlines)))
        }.resume()
    }
    
    private func checkAppSourceCodeIntegrity() {
        print("🔍 Checking app source code integrity...")
        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.verifyTextSection()
            DispatchQueue.main.async {
                self.appSourceCodeIntegrity = result
                print(result ? "✅ App source code integrity check passed" : "❌ App source code integrity check failed")
            }
        }
    }
    
    private func checkProvisionFileIntegrity() {
        print("🔍 Checking provision file integrity...")
        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.verifyProvisionFile()
            DispatchQueue.main.async {
                self.provisionFileIntegrity = result
                print(result ? "✅ Provision file integrity check passed" : "❌ Provision file integrity check failed")
            }
        }
    }
    
    private func verifyTextSection() -> Bool {
        print("📊 Verifying text section...")
        guard let slide = getAslrSlide() else {
            print("❌ Failed to get ASLR slide")
            return false
        }
        
        var textSectionAddress: UnsafeRawPointer?
        var textSectionSize: Int = 0
        
        for i in 0..<_dyld_image_count() {
            if let imageName = _dyld_get_image_name(i) {
                let name = String(cString: imageName)
                if name.contains(Bundle.main.executablePath ?? "") {
                    let machHeader = _dyld_get_image_header(i)
                    if let textSection = findTextSection(machHeader) {
                        let startAddress = slide + UInt(textSection.pointee.addr)
                        textSectionSize = Int(textSection.pointee.size)
                        textSectionAddress = UnsafeRawPointer(bitPattern: startAddress)
                        print("📦 Found text section: startAddress=\(startAddress), size=\(textSectionSize)")
                        break
                    }
                }
            }
        }
        
        guard let address = textSectionAddress else {
            print("❌ Failed to get text section address")
            return false
        }
        
        let hash = sha256(data: address, size: textSectionSize)
        print("🔢 Calculated text section hash: \(hash)")
        print("🔢 Known text section hash: \(knownTextSectionHash ?? "N/A")")
        
        return hash == knownTextSectionHash
        
        // Previous implementation (commented out for backup)
        /*
        var textSectionData: Data?
        
        for i in 0..<_dyld_image_count() {
            if let imageName = _dyld_get_image_name(i) {
                let name = String(cString: imageName)
                if name.contains(Bundle.main.executablePath ?? "") {
                    let machHeader = _dyld_get_image_header(i)
                    if let textSection = findTextSection(machHeader) {
                        let startAddress = slide + UInt(textSection.pointee.addr)
                        let size = Int(textSection.pointee.size)
                        textSectionData = Data(bytes: UnsafeRawPointer(bitPattern: startAddress)!, count: size)
                        print("📦 Found text section: startAddress=\(startAddress), size=\(size)")
                        break
                    }
                }
            }
        }
        
        guard let data = textSectionData else {
            print("❌ Failed to extract text section data")
            return false
        }
        
        let hash = sha256(data: data)
        print("🔢 Calculated text section hash: \(hash)")
        print("🔢 Known text section hash: \(knownTextSectionHash ?? "N/A")")
        
        return hash == knownTextSectionHash
        */
    }
    
    private func sha256(data: UnsafeRawPointer, size: Int) -> String {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CC_SHA256(data, CC_LONG(size), &hash)
        return hash.map { String(format: "%02x", $0) }.joined()
    }
    
    // Previous sha256 implementation (commented out for backup)
    /*
    private func sha256(data: Data) -> String {
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
    */
    
    private func verifyProvisionFile() -> Bool {
        print("📄 Verifying provision file...")
        guard let provisionURL = Bundle.main.url(forResource: "embedded", withExtension: "mobileprovision") else {
            print("❌ Provision file not found")
            return false
        }
        
        do {
            let provisionData = try Data(contentsOf: provisionURL)
            let hash = provisionData.withUnsafeBytes { bytes in
                return sha256(data: bytes.baseAddress!, size: provisionData.count)
            }
            print("🔢 Calculated provision file hash: \(hash)")
            print("🔢 Known provision file hash: \(knownProvisionFileHash ?? "N/A")")
            
            return hash == knownProvisionFileHash
        } catch {
            print("❌ Error reading provision file: \(error)")
            return false
        }
    }
    
    private func getAslrSlide() -> UInt? {
        print("🔍 Getting ASLR slide...")
        for i in 0..<_dyld_image_count() {
            if let imageName = _dyld_get_image_name(i) {
                let name = String(cString: imageName)
                if name.contains(Bundle.main.executablePath ?? "") {
                    let slide = _dyld_get_image_vmaddr_slide(i)
                    print("📊 ASLR slide: \(slide)")
                    return UInt(slide)
                }
            }
        }
        print("❌ Failed to get ASLR slide")
        return nil
    }
    
    private func findTextSection(_ machHeader: UnsafePointer<mach_header>?) -> UnsafePointer<section_64>? {
        guard let header = machHeader else {
            print("❌ Mach-O header is nil")
            return nil
        }
        
        let is64Bit = header.pointee.magic == MH_MAGIC_64 || header.pointee.magic == MH_CIGAM_64
        let headerSize = is64Bit ? MemoryLayout<mach_header_64>.size : MemoryLayout<mach_header>.size
        
        var curCmd = UnsafeRawPointer(header).advanced(by: headerSize)
        
        for _ in 0..<header.pointee.ncmds {
            let loadCmd = curCmd.assumingMemoryBound(to: load_command.self)
            if loadCmd.pointee.cmd == LC_SEGMENT_64 {
                let segCmd = curCmd.assumingMemoryBound(to: segment_command_64.self)
                if segCmd.pointee.segname.0 == UInt8(ascii: "_") &&
                   segCmd.pointee.segname.1 == UInt8(ascii: "_") &&
                   segCmd.pointee.segname.2 == UInt8(ascii: "T") &&
                   segCmd.pointee.segname.3 == UInt8(ascii: "E") &&
                   segCmd.pointee.segname.4 == UInt8(ascii: "X") &&
                   segCmd.pointee.segname.5 == UInt8(ascii: "T") {
                    let sectionPtr = UnsafeRawPointer(segCmd).advanced(by: MemoryLayout<segment_command_64>.size)
                    for _ in 0..<segCmd.pointee.nsects {
                        let section = sectionPtr.assumingMemoryBound(to: section_64.self)
                        if section.pointee.sectname.0 == UInt8(ascii: "_") &&
                           section.pointee.sectname.1 == UInt8(ascii: "_") &&
                           section.pointee.sectname.2 == UInt8(ascii: "t") &&
                           section.pointee.sectname.3 == UInt8(ascii: "e") &&
                           section.pointee.sectname.4 == UInt8(ascii: "x") &&
                           section.pointee.sectname.5 == UInt8(ascii: "t") {
                            return section
                        }
                    }
                }
            }
            curCmd = curCmd.advanced(by: Int(loadCmd.pointee.cmdsize))
        }
        
        print("❌ __TEXT __text section not found")
        return nil
    }
}
