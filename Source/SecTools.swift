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

    public class func environmentOptions(forIdentity identity: Any) -> EnvironmentOptions {
        guard
            let certificate: CertificateRef = try? self.certificate(with: identity as IdentityRef) as CertificateRef
            else { return .sandbox }

        return self.environmentOptions(for: certificate)
    }

    public class func expiration(with certificate: Any) -> Date? {
        return self.value(withCertificate: certificate as CertificateRef,
                          key: kSecOIDInvalidityDate) as? Date
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
                let prefix = certType.prefix,
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

    private class func value(withCertificate certificate: CertificateRef,
                             key: AnyHashable) -> Any? {
        let values = self.values(with: certificate,
                                 keys: [key])

        return values?[key]?[kSecPropertyKeyValue]
    }
}
