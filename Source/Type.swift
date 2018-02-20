import Foundation

public let errorReasonCodeKey: String = "NWErrorReasonCodeKey"

public typealias identityRef = Any
public typealias certificateRef = Any
public typealias keyRef = Any

@objcMembers
public class ErrorUtil: NSObject {
    
    // MARK: Public Type Methods
    
    public static func descriptionForCertType(_ type: NWCertType) -> String {
        switch type {
        case .none:
            return "none";
            
        case .iosDevelopment,
             .iosProduction:
            return "iOS";
            
        case .macDevelopment,
             .macProduction:
            return "macOS";
            
        case .simplified:
            return "All";
            
        case .webProduction:
            return "Website";
            
        case .voIPServices:
            return "VoIP";
            
        case .watchKitServices:
            return "WatchKit";
            
        case .passes:
            return "Pass";
            
        case .unknown:
            return "unknown";
        }
    }
    
    public static func descriptionForEnvironment(_ environment: NWEnvironment) -> String {
        switch environment {
        case .none:
            return "none";
            
        case .production:
            return "production";
            
        case .sandbox:
            return "sandbox";
            
        case .auto:
            return "auto";
        }
    }
    
    public static func descriptionForEnvironmentOptions(_ environmentOptions: NWEnvironmentOptions) -> String {
        switch environmentOptions {
        case .none:
            return "No environment";
            
        case .sandbox:
            return "Sandbox";
            
        case .production:
            return "Production";
            
        case .any:
            return "Sandbox|Production";
        }
    }
    
    public static func errorWithErrorCode(_ code: PushError,
                                          reason: Int) -> NSError {
        var description: String = self.string(code)
        
        if reason != 0 {
            description = "\(description) (\(Int(reason)))"
        }
        
        var info = [NSLocalizedDescriptionKey: description]
        
        if reason != 0 {
            info[NWErrorReasonCodeKey] = "\(reason)"
        }
        
        return NSError(domain: "PusherErrorDomain",
                       code: code.rawValue,
                       userInfo: info)
    }
    
    // MARK: Private Type Methods
    
    private static func string(_ code: PushError) -> String {
        switch code {
        case .none:
            return "No error, that's odd";
            
        case .apnProcessing :
            return "APN processing error";
            
        case .apnMissingDeviceToken:
            return "APN missing device token";
            
        case .apnMissingTopic:
            return "APN missing topic";
            
        case .apnMissingPayload:
            return "APN missing payload";
            
        case .apnInvalidTokenSize:
            return "APN invalid token size";
            
        case .apnInvalidTopicSize:
            return "APN invalid topic size";
            
        case .apnInvalidPayloadSize:
            return "APN invalid payload size";
            
        case .apnInvalidTokenContent:
            return "APN invalid token";
            
        case .apnUnknownReason:
            return "APN unknown reason";
            
        case .apnShutdown:
            return "APN shutdown";
            
        case .apnUnknownErrorCode:
            return "APN unknown error code";
            
        case .pushResponseCommand:
            return "Push response command unknown";
            
        case .pushNotConnected:
            return "Push reconnect requires connection";
            
        case .pushWriteFail:
            return "Push not fully sent";
            
        case .feedbackLength:
            return "Feedback data length unexpected";
            
        case .feedbackTokenLength:
            return "Feedback token length unexpected";
            
        case .socketCreate:
            return "Socket cannot be created";
            
        case .socketConnect:
            return "Socket connecting failed";
            
        case .socketResolveHostName:
            return "Socket host cannot be resolved";
            
        case .socketFileControl:
            return "Socket file control failed";
            
        case .socketOptions:
            return "Socket options cannot be set";
            
        case .sslConnection:
            return "SSL connection cannot be set";
            
        case .sslContext:
            return "SSL context cannot be created";
            
        case .sslIOFuncs:
            return "SSL callbacks cannot be set";
            
        case .sslPeerDomainName:
            return "SSL peer domain name cannot be set";
            
        case .sslCertificate:
            return "SSL certificate cannot be set";
            
        case .sslDroppedByServer:
            return "SSL handshake dropped by server";
            
        case .sslAuthFailed:
            return "SSL handshake authentication failed";
            
        case .sslHandshakeFail:
            return "SSL handshake failed";
            
        case .sslHandshakeUnknownRootCert:
            return "SSL handshake root not a known anchor";
            
        case .sslHandshakeNoRootCert:
            return "SSL handshake chain not verifiable to root";
            
        case .sslHandshakeCertExpired:
            return "SSL handshake expired certificates";
            
        case .sslHandshakeXCertChainInvalid:
            return "SSL handshake invalid certificate chain";
            
        case .sslHandshakeClientCertRequested:
            return "SSL handshake expecting client cert";
            
        case .sslHandshakeServerAuthCompleted:
            return "SSL handshake auth interrupted";
            
        case .sslHandshakePeerCertExpired:
            return "SSL handshake certificate expired";
            
        case .sslHandshakePeerCertRevoked:
            return"SSL handshake certificate revoked";
            
        case .sslHandshakePeerCertUnknown:
            return "SSL handshake certificate unknown";
            
        case .sslHandshakeInternalError:
            return "SSL handshake internal error";
            
        case .sslInDarkWake:
            return "SSL handshake in dark wake";
            
        case .sslHandshakeClosedAbort:
            return "SSL handshake connection closed via error";
            
        case .sslHandshakeTimeout:
            return "SSL handshake timeout";
            
        case .readDroppedByServer:
            return "Read connection dropped by server";
            
        case .readClosedAbort:
            return "Read connection error";
            
        case .readClosedGraceful:
            return "Read connection closed";
            
        case .readFail:
            return "Read failed";
            
        case .writeDroppedByServer:
            return "Write connection dropped by server";
            
        case .writeClosedAbort:
            return "Write connection error";
            
        case .writeClosedGraceful:
            return "Write connection closed";
            
        case .writeFail:
            return "Write failed";
            
        case .identityCopyCertificate:
            return "Identity does not contain certificate";
            
        case .identityCopyPrivateKey:
            return "Identity does not contain private key";
            
        case .pkcs12Import:
            return "PKCS12 data cannot be imported";
            
        case .pkcs12EmptyData:
            return "PKCS12 data is empty";
            
        case .pkcs12Decode:
            return "PKCS12 data cannot be read or is malformed";
            
        case .pkcs12AuthFailed:
            return "PKCS12 data password incorrect";
            
        case .pkcs12Password:
            return "PKCS12 data wrong password";
            
        case .pkcs12PasswordRequired:
            return "PKCS12 data password required";
            
        case .pkcs12NoItems:
            return "PKCS12 data contains no identities";
            
        case .pkcs12MultipleItems:
            return "PKCS12 data contains multiple identities";
            
        case .keychainCopyMatching:
            return "Keychain cannot be searched";
            
        case .keychainItemNotFound:
            return "Keychain does not contain private key";
            
        case .keychainCreateIdentity:
            return "Keychain does not contain certificate";
        }
    }
}
