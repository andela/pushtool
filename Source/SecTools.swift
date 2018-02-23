
import Foundation

public class SecTools : NSObject {
    
    // MARK: Public Instance methods
    
    public class func certificate(with data: Data?) -> Any? {
        guard let data = data
            else { return nil }
        
        return SecCertificateCreateWithData(kCFAllocatorDefault, data as CFData)
    }
    
    public class func certificate(withIdentity identity: NWIdentityRef?,
                                  error: NSErrorPointer)throws -> Any {
        var cert: SecCertificate?
        var status: OSStatus
        
        if let id = identity {
            status = SecIdentityCopyCertificate(id as! SecIdentity, &cert)
        } else {
            status = errSecParam
        }
    
        if status != errSecSuccess {
            throw ErrorUtil.errorWithErrorCode(.identityCopyCertificate, reason: Int(status))
        }
        guard let certificate = cert else {
            throw ErrorUtil.errorWithErrorCode(.identityCopyCertificate, reason: 0)
        }
        return certificate
    }
    
    public class func environmentOptions(forCertificate certificate: Any) -> NWEnvironmentOptions {
        
        switch (self.type(withCertificate: certificate, summary: nil) ) {
            
        case .iosDevelopment,
             .macDevelopment:
            return NWEnvironmentOptions.sandbox
            
        case .iosProduction,
             .macProduction:
            return NWEnvironmentOptions.production
            
        case .passes,
             .simplified,
             .voIPServices,
             .watchKitServices,
             .webProduction:
            return NWEnvironmentOptions.any
            
        default:
            return NWEnvironmentOptions.none
        }
    }
    
    public class func environmentOptions(forIdentity identity: Any)throws  -> NWEnvironmentOptions {
        
        let certificate: NWCertificateRef = try self.certificate(withIdentity: identity as NWIdentityRef,
                                                             error: nil) as NWCertificateRef
        
        return self.environmentOptions(forCertificate: certificate)
    }
    
    
    
    public class func expiration(withCertificate certificate: Any) -> Date {
        
        return self.value(withCertificate: certificate as NWCertificateRef,
                          key: kSecOIDInvalidityDate) as! Date
    }
    
    public class func identities(withPKCS12Data pkcs12: Data,
                                 password: String) throws -> [Any]? {
        
        if pkcs12.isEmpty {
            throw ErrorUtil.errorWithErrorCode(.pkcs12EmptyData, reason: 0)
        }
        let dicts = try self.allIdentitities(withPKCS12Data: pkcs12, password: password)
        
        //        guard let dict = dicts
        //            else { return nil }
        //
        //        var ids:[Any] = []
        
        //        for item:[AnyHashable: Any] in dict {
        //            let identity = item[kSecImportItemIdentity]
        //        }
        return []
    }
    
    public class func identity(withPKCS12Data pkcs12: Data,
                               password: String) throws -> Any? {
        
        let identitiesCollection = try self.identities(withPKCS12Data: pkcs12, password: password)
        
        guard let identities = identitiesCollection
            else { return nil }
        
        if identities.count == 0 {
            throw ErrorUtil.errorWithErrorCode(.pkcs12NoItems, reason: 0)
        }
        
        if identities.count > 1 {
            throw ErrorUtil.errorWithErrorCode(.pkcs12MultipleItems, reason: 0)
        }
        
        return identities.last
    }
    
    public class func inspectIdentity(_ identity: Any?) -> [AnyHashable : Any]? {
        
        guard let id = identity
            else { return nil }
        
        var result: [AnyHashable: Any] = [:]
        var certificate: SecCertificate?
        
        var certstat: OSStatus = SecIdentityCopyCertificate(id as! SecIdentity, &certificate)
        // TO DO Later Some confusion !!
        return [:]
    }
    
    public class func isPushCertificate(_ certificate: Any) -> Bool {
        
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
    
    public class func key(withIdentity identity: Any? )throws -> Any? {
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
    
    public class func keychainCertificatesWithError()throws -> [Any]? {
        
        let candidatesCollection = try self.keychainCertificatesWithError()
        
        guard let candidates = candidatesCollection
            else { return nil }
        var certificates: [Any] = []
        
        certificates = candidates.filter {
            self.isPushCertificate($0)
        }
        
        return certificates
    }

    public class func keychainIdentity(withCertificate certificate: Any?,
                                       error: NSErrorPointer) throws -> Any {
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
    
    public class func summary(withCertificate certificate: Any) -> String {
        var result: NSString?
        
        self.type(withCertificate: certificate, summary: &result)
        
        guard let resultValue = result else {
            return ""
        }
        return resultValue as String
    }
    
    public class func type(withCertificate certificate: Any,
                           summary: AutoreleasingUnsafeMutablePointer<NSString?>?) -> NWCertType {
        
        return NWCertType.iosDevelopment
    }
    
    
  
    public class func values(withCertificate certificate: Any,
                             keys: [Any], error: NSErrorPointer) -> [AnyHashable : Any] {
        return [:]
    }
    // MARK: Private Instance Methods
    
    private class func allIdentitities(withPKCS12Data pkc12: Data?,
                                       password: String?) throws -> [Any]? {
        var options:[AnyHashable: Any] = [:]
        
        if let password = password {
            options[kSecImportExportPassphrase] = password
        }
        var items: CFArray?
        
        var status: OSStatus
        
        if let pkc12Data = pkc12 {
            status = SecPKCS12Import(pkc12Data as CFData, options as CFDictionary, &items)
        } else {
            status = errSecParam
        }
        
        switch status {
            
        case errSecDecode:
            throw ErrorUtil.errorWithErrorCode(.pkcs12Decode, reason: Int(status))
        case errSecAuthFailed:
            throw ErrorUtil.errorWithErrorCode(.pkcs12AuthFailed, reason: Int(status))
        case errSecPkcs12VerifyFailure:
            throw ErrorUtil.errorWithErrorCode(.pkcs12Password, reason: Int(status))
        case errSecPassphraseRequired:
            throw ErrorUtil.errorWithErrorCode(.pkcs12PasswordRequired, reason: Int(status))
        default:
            throw ErrorUtil.errorWithErrorCode(.pkcs12Import, reason: Int(status))
        }
        
        return []
    }
    
    private func allKeyChainCertificates() throws -> [Any] {
        
        var options = [kSecClass : kSecClassCertificate, kSecMatchLimit: kSecMatchLimitAll]
        
        var certs: CFArray?
//
//        var status: OSStatus
//        status = SecItemCopyMatching(options as CFDictionary, certs! as CFTypeRef as! UnsafeMutablePointer<CFTypeRef?>)
        
        
        return []
    }
    
    private func prefix(withCertType certType: CertType) -> String? {
        switch certType {
        case .iosDevelopment:
            return "Apple Development IOS Push services"
        case .iosProduction:
            return "Apple Production IOS Push services"
        case .macDevelopment:
            return "Apple Development Mac Push services"
        case .macProduction:
            return "Apple Production Mac Push services"
        case .simplified:
            return "Apple Push Services"
        case .webProduction:
            return "Website Push ID"
        case .voIPServices:
            return "VoIP Services"
        case .watchKitServices:
            return "Watch Kit Services"
        case .passes:
            return "Pass Type ID"
        default:
            return nil
        }
    }
    
    private class func value(withCertificate certificate: NWCertificateRef,
                             key: AnyHashable) -> Any {
        //        return self.values(withCertificate: certificate, keys: [key], error: nil)[key]![kSecPropertyKeyValue as? Any ]
        return 1
    }
    
    
    
    
}

