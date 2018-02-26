
import Foundation
import Security

@objcMembers
public class SecTools : NSObject {
    
    // MARK: Public Instance methods
    
    public class func certificate(with data: Data?) -> Any? {
        guard let data = data
            else { return nil }
        
        return SecCertificateCreateWithData(kCFAllocatorDefault,
                                            data as CFData)
    }
    
    public class func certificate(withIdentity identity: NWIdentityRef?) throws -> NWCertificateRef {
        var cert: SecCertificate?
        var status: OSStatus
        
        if let id = identity {
            status = SecIdentityCopyCertificate(id as! SecIdentity, &cert)
        } else {
            status = errSecParam
        }

        guard
            let certificate = cert,
            status == errSecSuccess
            else { throw ErrorUtil.errorWithErrorCode(.identityCopyCertificate,
                                                      reason: Int(status)) }

        return certificate
    }
    
    public class func environmentOptions(forCertificate certificate: NWCertificateRef) -> NWEnvironmentOptions {
        
        switch (self.type(withCertificate: certificate,
                          summary: nil) ) {
        case .iosDevelopment,
             .macDevelopment:
            return .sandbox
            
        case .iosProduction,
             .macProduction:
            return .production
            
        case .passes,
             .simplified,
             .voIPServices,
             .watchKitServices,
             .webProduction:
            return .any
            
        default:
            return .none
        }
    }
    
    public class func environmentOptions(forIdentity identity: Any) -> NWEnvironmentOptions {
        
        guard
            let certificate: NWCertificateRef = try? self.certificate(withIdentity: identity as NWIdentityRef) as NWCertificateRef
            else { return .none }
        
        return self.environmentOptions(forCertificate: certificate)
    }
    
    #if os(macOS)
    public class func expiration(withCertificate certificate: Any) -> Date? {
        
        return self.value(withCertificate: certificate as NWCertificateRef,
                          key: kSecOIDInvalidityDate) as? Date
    }
    #endif

    public class func identities(withPKCS12Data pkcs12: Data,
                                 password: String) throws -> [Any] {
        
        guard
            !pkcs12.isEmpty
            else { throw ErrorUtil.errorWithErrorCode(.pkcs12EmptyData,
                                                      reason: 0) }

        guard
            let dicts = try self.allIdentitities(withPKCS12Data: pkcs12,
                                                 password: password)
            else { return [] }

        var ids: [NWIdentityRef] = []

        for dict in dicts {
            guard
                let identity = dict[kSecImportItemIdentity]
                else { continue }

            let certificate = try self.certificate(withIdentity: identity as NWIdentityRef)

            if isPushCertificate(certificate) {
                _ = try self.key(withIdentity: identity)

                ids.append(identity as NWIdentityRef)
            }
        }

        return ids
    }
    
    public class func identity(withPKCS12Data pkcs12: Data,
                               password: String) throws -> Any {
        
        let identities = try self.identities(withPKCS12Data: pkcs12,
                                             password: password)

        if identities.count == 0 {
            throw ErrorUtil.errorWithErrorCode(.pkcs12NoItems, reason: 0)
        }
        
        if identities.count > 1 {
            throw ErrorUtil.errorWithErrorCode(.pkcs12MultipleItems, reason: 0)
        }
        
        return identities.last as Any
    }
    
    public class func inspectIdentity(_ identity: Any?) -> [AnyHashable : Any]? {
        
        guard let id = identity
            else { return nil }
        
        var result: [AnyHashable: Any] = [:]
        var certificate: SecCertificate?

        let certstat: OSStatus = SecIdentityCopyCertificate(id as! SecIdentity,
                                                            &certificate)

        result["has_certificate"] = certificate != nil

        if certstat != 0 {
            result["certificate_error"] = certstat
        }

        if let certificate = certificate {
            result["subject_summary"] = SecCertificateCopySubjectSummary(certificate)
            result["der_data"] = SecCertificateCopyData(certificate)
        }

        var key: SecKey?

        let keystat: OSStatus = SecIdentityCopyPrivateKey(identity as! SecIdentity,
                                                          &key)

        result["has_key"] = key != nil

        if keystat != 0 {
            result["key_error"] = keystat
        }

        if let key = key {
            result["block_size"] = SecKeyGetBlockSize(key)
        }

        return result
    }
    
    public class func isPushCertificate(_ certificate: NWCertificateRef) -> Bool {

        print("Checking certificate \(certificate)")
        
        switch (self.type(withCertificate: certificate,
                          summary: nil)) {
        case .iosDevelopment,
             .iosProduction,
             .macDevelopment,
             .macProduction,
             .passes,
             .simplified,
             .voIPServices,
             .watchKitServices,
             .webProduction:
            return true
            
        default:
            return false
        }
    }
    
    public class func key(withIdentity identity: Any?) throws -> Any? {
        var key: SecKey?
        var status: OSStatus
        
        if let id = identity {
            status = SecIdentityCopyPrivateKey(id as! SecIdentity, &key)
        } else {
            status = errSecParam
        }
        
        if status != errSecSuccess {
            throw ErrorUtil.errorWithErrorCode(.identityCopyPrivateKey, reason: Int(status))
        }
        
        guard let keyRef: NWKeyRef = key
            else { throw ErrorUtil.errorWithErrorCode(.identityCopyPrivateKey,
                                                      reason: Int(status)) }
        
        return keyRef
    }

    @objc(keychainCertificatesWithError:)
    public class func keychainCertificates() throws -> [NWCertificateRef] {
        
        let candidates = try self.allKeychainCertificates()
        
        var certificates: [NWCertificateRef] = []
        
        certificates = candidates.filter {
            self.isPushCertificate($0)
        }
        
        return certificates
    }

    #if os(macOS)
    public class func keychainIdentity(withCertificate certificate: Any?) throws -> Any {
        var ident: SecIdentity?

        var status : OSStatus

        if let cert = certificate {
            status = SecIdentityCreateWithCertificate(nil,
                                                      cert as! SecCertificate,
                                                      &ident)
        } else {
            status = errSecParam
        }

        if status !=  errSecSuccess {
            throw ErrorUtil.errorWithErrorCode(.keychainItemNotFound, reason: 0)
        }

        guard let id = ident  else {
            throw ErrorUtil.errorWithErrorCode(.keychainCreateIdentity, reason: 0)
        }

        return id
    }
    #endif

    public class func summary(withCertificate certificate: NWCertificateRef) -> String {
        var result: NSString?
        
        _ = self.type(withCertificate: certificate,
                      summary: &result)
        
        guard let resultValue = result else {
            return ""
        }
        return resultValue as String
    }
    
    public class func type(withCertificate certificate: NWCertificateRef,
                           summary: AutoreleasingUnsafeMutablePointer<NSString?>?) -> NWCertType {
     
        if summary != nil {
            summary?.pointee = nil
        }
        
        let name: String? = self.plainSummary(withCertificate: certificate)
    
        
        for type in NWCertType.none.rawValue...NWCertType.unknown.rawValue {
            guard
                let certType = NWCertType(rawValue: type),
                let prefix = self.prefix(withCertType: certType),
                let name = name,
                name.hasPrefix(prefix)
                else { continue }
            
            if summary != nil {
                summary?.pointee = name as NSString
            }
            return  certType
            
        }
        if summary != nil,
           let name = name {
            summary?.pointee = name as NSString
        }
        
        return .unknown
    }
    
    #if os(macOS)
    public class func values(withCertificate certificate: Any,
                             keys: [Any]) -> [AnyHashable: [AnyHashable: Any]]? {
        var error: Unmanaged<CFError>?
        
        let result = SecCertificateCopyValues(certificate as! SecCertificate,
                                              keys as CFArray, &error) as? [AnyHashable: [AnyHashable : Any]]
        
        return result
    }
    #endif

    // MARK: Private Instance Methods
    
    private class func allIdentitities(withPKCS12Data pkc12: Data?,
                                       password: String?) throws -> [[AnyHashable: Any]]? {
        var options:[AnyHashable: Any] = [:]
        
        if let password = password {
            options[kSecImportExportPassphrase] = password
        }

        var items: CFArray?
        var status: OSStatus
        
        if let pkc12Data = pkc12 {
            status = SecPKCS12Import(pkc12Data as CFData,
                                     options as CFDictionary,
                                     &items)
        } else {
            status = errSecParam
        }

        if let dicts = items as? [[AnyHashable: Any]],
            status == errSecSuccess {
            return dicts
        }

        switch status {
            
        case errSecDecode:
            throw ErrorUtil.errorWithErrorCode(.pkcs12Decode,
                                               reason: Int(status))

        case errSecAuthFailed:
            throw ErrorUtil.errorWithErrorCode(.pkcs12AuthFailed,
                                               reason: Int(status))

        case errSecPkcs12VerifyFailure:
            throw ErrorUtil.errorWithErrorCode(.pkcs12Password,
                                               reason: Int(status))

        case errSecPassphraseRequired:
            throw ErrorUtil.errorWithErrorCode(.pkcs12PasswordRequired,
                                               reason: Int(status))

        default:
            throw ErrorUtil.errorWithErrorCode(.pkcs12Import,
                                               reason: Int(status))
        }
    }
    
    private class func allKeychainCertificates() throws -> [NWCertificateRef] {
        
        let options = [kSecClass: kSecClassCertificate,
                       kSecMatchLimit: kSecMatchLimitAll]
        
        var certs: CFTypeRef? = nil

        var status: OSStatus
        
        status = SecItemCopyMatching(options as CFDictionary, &certs)
        
        guard
            let certificates = certs as? [NWCertificateRef],
            status == errSecSuccess
            else {
                throw ErrorUtil.errorWithErrorCode(.keychainCopyMatching, reason: Int(status))
        }
        
        return certificates
    }
    
    private class func plainSummary(withCertificate certificate:NWCertificateRef?) -> String? {
        guard
            let cert = certificate,
            let summary = SecCertificateCopySubjectSummary(cert as! SecCertificate) as String?
            else { return nil }
        return summary
    }
    
    private class func prefix(withCertType certType: NWCertType) -> String? {
        switch certType {
        case .iosDevelopment:
            return "Apple Development IOS Push Services: "

        case .iosProduction:
            return "Apple Production IOS Push Services: "

        case .macDevelopment:
            return "Apple Development Mac Push Services: "

        case .macProduction:
            return "Apple Production Mac Push Services: "

        case .simplified:
            return "Apple Push Services: "

        case .webProduction:
            return "Website Push ID: "

        case .voIPServices:
            return "VoIP Services: "

        case .watchKitServices:
            return "WatchKit Services: "

        case .passes:
            return "Pass Type ID: "

        default:
            return nil
        }
    }

    #if os(macOS)
    private class func value(withCertificate certificate: NWCertificateRef,
                             key: AnyHashable) -> Any? {
        let values = self.values(withCertificate: certificate,
                                 keys: [key])
        
        return values?[key]?[kSecPropertyKeyValue]
    }
    #endif
}
