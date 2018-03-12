import Foundation
import Security

public class SecTools {

    // MARK: Public Instance methods

    public class func certificate(with data: Data?) -> Any? {
        guard let data = data
            else { return nil }

        return SecCertificateCreateWithData(kCFAllocatorDefault,
                                            data as CFData)
    }

    public class func certificate(with identity: IdentityRef?) throws -> CertificateRef {
        var cert: SecCertificate?
        var status: OSStatus

        if case let id as SecIdentity = identity {
            status = SecIdentityCopyCertificate(id, &cert)
        } else {
            status = errSecParam
        }

        guard
            let certificate = cert,
            status == errSecSuccess
            else { throw PushError.identityCopyCertificate }

        return certificate
    }

    public class func environmentOptions(for certificate: CertificateRef) -> EnvironmentOptions {
        let result = self.type(with: certificate)

        switch result.certType {
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
            return .sandbox
        }
    }

    public class func environmentOptions(forIdentity identity: IdentityRef) -> EnvironmentOptions {
        guard
            let certificate: CertificateRef = try? self.certificate(with: identity) as CertificateRef
            else { return .sandbox }

        return self.environmentOptions(for: certificate)
    }

    public class func expiration(with certificate: Any) -> Date? {
        return self.value(withCertificate: certificate as CertificateRef,
                          key: kSecOIDInvalidityDate) as? Date
    }

    public class func identities(with pkcs12: Data,
                                 password: String?) throws -> [Any] {
        guard
            !pkcs12.isEmpty
            else { throw PushError.pkcs12EmptyData }

        guard
            let dicts = try self.allIdentitities(with: pkcs12,
                                                 password: password)
            else { return [] }

        var ids: [IdentityRef] = []

        for dict in dicts {
            guard
                let identity = dict[kSecImportItemIdentity]
                else { continue }

            let certificate = try self.certificate(with: identity as IdentityRef)

            if isPushCertificate(certificate) {
                _ = try self.key(withIdentity: identity)

                ids.append(identity as IdentityRef)
            }
        }

        return ids
    }

    public class func identity(withPKCS12Data pkcs12: Data,
                               password: String) throws -> Any {
        let identities = try self.identities(with: pkcs12,
                                             password: password)

        if identities.isEmpty {
            throw PushError.pkcs12NoItems
        }

        if identities.count > 1 {
            throw PushError.pkcs12MultipleItems
        }

        return identities.last as Any
    }

    public class func inspectIdentity(_ identity: Any?) -> [AnyHashable: Any]? {
        guard
            case let id as SecIdentity = identity
            else { return nil }

        var result: [AnyHashable: Any] = [:]
        var certificate: SecCertificate?

        let certstat: OSStatus = SecIdentityCopyCertificate(id,
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
        let keystat: OSStatus = SecIdentityCopyPrivateKey(id, &key)

        result["has_key"] = key != nil

        if keystat != 0 {
            result["key_error"] = keystat
        }

        if let key = key {
            result["block_size"] = SecKeyGetBlockSize(key)
        }

        return result
    }

    public class func isPushCertificate(_ certificate: CertificateRef) -> Bool {
         let result = self.type(with: certificate)

        switch result.certType {
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

        if case let id as SecIdentity = identity {
            status = SecIdentityCopyPrivateKey(id, &key)
        } else {
            status = errSecParam
        }

        if status != errSecSuccess {
            throw PushError.identityCopyPrivateKey
        }

        guard let keyRef: KeyRef = key
            else { throw PushError.identityCopyPrivateKey }

        return keyRef
    }

    public class func keychainCertificates() throws -> [CertificateRef] {
        let candidates = try self.allKeychainCertificates()

        var certificates: [CertificateRef] = []

        certificates = candidates.filter {
            self.isPushCertificate($0)
        }

        return certificates
    }

    public class func keychainIdentity(with certificate: Any?) throws -> Any {
        var ident: SecIdentity?

        var status: OSStatus

        if case let cert as SecCertificate = certificate {
            status = SecIdentityCreateWithCertificate(nil,
                                                      cert,
                                                      &ident)
        } else {
            status = errSecParam
        }

        if status != errSecSuccess {
            throw PushError.keychainItemNotFound
        }

        guard let id = ident  else {
            throw PushError.keychainCreateIdentity
        }

        return id
    }

    public class func summary(with certificate: CertificateRef) -> String {
        let result = self.type(with: certificate)

        guard let resultValue = result.summary else {
            return ""
        }

        return resultValue
    }

    public class func type(with certificate: CertificateRef) -> (certType: CertType, summary: String? ) {
        var summary: String?

        let name: String? = self.plainSummary(with: certificate)

        for certType in CertType.allTypes {
            guard
                let prefix = self.prefix(with: certType),
                let name = name,
                name.hasPrefix(prefix)
                else { continue }

                summary = String(name.dropFirst(prefix.count) )

            return  (certType, summary)
        }

        if let name = name {
            summary = name
        }

        return (.unknown, summary)
    }

    public class func values(with certificate: Any,
                             keys: [Any]) -> [AnyHashable: [AnyHashable: Any]]? {
        guard
            case let cert as SecCertificate = certificate
            else { return nil }

        var error: Unmanaged<CFError>?

        return SecCertificateCopyValues(cert,
                                        keys as CFArray,
                                        &error) as? [AnyHashable: [AnyHashable: Any]]
    }

    // MARK: Private Instance Methods

    private class func allIdentitities(with pkc12: Data?,
                                       password: String?) throws -> [[AnyHashable: Any]]? {
        var options: [AnyHashable: Any] = [:]

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
            throw PushError.pkcs12Decode

        case errSecAuthFailed:
            throw PushError.pkcs12AuthFailed

        case errSecPkcs12VerifyFailure:
            throw PushError.pkcs12Password

        case errSecPassphraseRequired:
            throw PushError.pkcs12PasswordRequired
        default:
            throw PushError.pkcs12Import
        }
    }

    private class func allKeychainCertificates() throws -> [CertificateRef] {
        let options = [kSecClass: kSecClassCertificate,
                       kSecMatchLimit: kSecMatchLimitAll]

        var certs: CFTypeRef?

        var status: OSStatus

        status = SecItemCopyMatching(options as CFDictionary, &certs)

        guard
            let certificates = certs as? [CertificateRef],
            status == errSecSuccess
            else {
                throw PushError.keychainCopyMatching
        }

        return certificates
    }

    public class func plainSummary(with certificate: CertificateRef?) -> String? {
        guard
            case let cert as SecCertificate = certificate,
            let summary = SecCertificateCopySubjectSummary(cert) as String?
            else { return nil }

        return summary
    }

    private class func prefix(with certType: CertType) -> String? {
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

    private class func value(withCertificate certificate: CertificateRef,
                             key: AnyHashable) -> Any? {
        let values = self.values(with: certificate,
                                 keys: [key])

        return values?[key]?[kSecPropertyKeyValue]
    }
}
