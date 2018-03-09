import Foundation

public struct SecIdentityTools {
    private static func allIdentitities(withPKCS12Data pkc12: Data?,
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

    public static func identity(withPKCS12Data pkcs12: Data,
                                password: String) throws -> Any {
        let identities = try self.identities(withPKCS12Data: pkcs12,
                                             password: password)

        if identities.isEmpty {
            throw PushError.pkcs12NoItems
        }

        if identities.count > 1 {
            throw PushError.pkcs12MultipleItems
        }

        return identities.last as Any
    }

    public static func identities(withPKCS12Data pkcs12: Data,
                                  password: String?) throws -> [Any] {
        guard
            !pkcs12.isEmpty
            else { throw PushError.pkcs12EmptyData }

        guard
            let dicts = try self.allIdentitities(withPKCS12Data: pkcs12,
                                                 password: password)
            else { return [] }

        var ids: [IdentityRef] = []

        for dict in dicts {
            guard
                let identity = dict[kSecImportItemIdentity]
                else { continue }

            let certificate = try SecTools.certificate(withIdentity: identity as IdentityRef)

            if SecTools.isPushCertificate(certificate) {
                _ = try SecTools.key(withIdentity: identity)

                ids.append(identity as IdentityRef)
            }
        }

        return ids
    }
}
