import Foundation

public class SSLError {
    public class func throwIfHandshakeSSLError(_ status: OSStatus) throws {
        switch status {
        case errSecAuthFailed:
            throw PushError.sslAuthFailed

        case errSecInDarkWake:
            throw PushError.sslInDarkWake

        case errSecIO:
            throw PushError.sslDroppedByServer

        case errSecSuccess:
            break

        case errSSLCertExpired:
            throw PushError.sslHandshakeCertExpired

        case errSSLClientCertRequested:
            throw PushError.sslHandshakeClientCertRequested

        case errSSLClosedAbort:
            throw PushError.sslHandshakeClosedAbort

        case errSSLInternal:
            throw PushError.sslHandshakeInternalError

        case errSSLNoRootCert:
            throw PushError.sslHandshakeNoRootCert

        case errSSLPeerAuthCompleted:
            throw PushError.sslHandshakeServerAuthCompleted

        case errSSLPeerCertExpired:
            throw PushError.sslHandshakePeerCertExpired

        case errSSLPeerCertRevoked:
            throw PushError.sslHandshakePeerCertRevoked

        case errSSLPeerCertUnknown:
            throw PushError.sslHandshakePeerCertUnknown

        case errSSLUnknownRootCert:
            throw PushError.sslHandshakeUnknownRootCert

        case errSSLWouldBlock:
            throw PushError.sslHandshakeTimeout

        case errSSLXCertChainInvalid:
            throw PushError.sslHandshakeXCertChainInvalid

        default:
            throw PushError.sslHandshakeFail
        }
    }
}
