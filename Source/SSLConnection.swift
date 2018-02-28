import Foundation
import Security

@objcMembers
public class SSLConnection : NSObject {
    
    // MARK: Public Initializers

    public override convenience init() {
        self.init(host: nil,
                  port: 0,
                  identity: nil)
    }

    public init(host: String?,
                port: UInt,
                identity: NWIdentityRef?) {
        self.identity = identity
        self.host = host
        self.port = port
        self.socket = -1
    }

    // MARK: Public Instance Properties
    
    public var host: String?
    public var identity: NWIdentityRef?
    public var port: UInt

    // MARK: Public Instance Methods
    
    public func connect() throws {
        disconnect()

        do {
            try connectSocket()
            try connectSSL()
            try handshakeSSL()
        } catch {
            disconnect()
            throw error
        }
    }
    
    public func disconnect() {
        if let context = self.context {
            SSLClose(context)
        }

        if socket >= 0 {
            close(socket)

            socket = -1
        }
    }
    
    public func read(_ data: NSMutableData,
                     length: UnsafeMutablePointer<UInt>) throws {
        guard
            let context = self.context
            else { return }
        
        var processed = Int(0)

        let status = SSLRead(context,
                             data.mutableBytes,
                             data.length,
                             &processed)
        
        length.pointee = UInt(processed)
        
        switch (status) {
        case errSecIO:
            throw ErrorUtil.errorWithErrorCode(.readDroppedByServer,
                                               reason: Int(status))

        case errSecSuccess,
             errSSLWouldBlock:
            break

        case errSSLClosedAbort:
            throw ErrorUtil.errorWithErrorCode(.readClosedAbort,
                                               reason: Int(status))

        case errSSLClosedGraceful:
            throw ErrorUtil.errorWithErrorCode(.readClosedGraceful,
                                               reason: Int(status))

        default:
            throw ErrorUtil.errorWithErrorCode(.readFail,
                                               reason: Int(status))
        }
    }
    
    public func write(_ data: NSData,
                      length: UnsafeMutablePointer<UInt>) throws {
        guard
            let context = self.context
            else { return }
        
        var processed = Int(0)

        let status = SSLWrite(context,
                              data.bytes,
                              data.length,
                              &processed)
        
        length.pointee = UInt(processed)

        switch (status) {
        case errSecIO:
            throw ErrorUtil.errorWithErrorCode(.writeDroppedByServer,
                                               reason: Int(status))
            
        case errSecSuccess,
             errSSLWouldBlock:
            break

        case errSSLClosedAbort:
            throw ErrorUtil.errorWithErrorCode(.writeClosedAbort,
                                               reason: Int(status))
            
        case errSSLClosedGraceful:
            throw ErrorUtil.errorWithErrorCode(.writeClosedGraceful,
                                               reason: Int(status))
            
        default:
            throw ErrorUtil.errorWithErrorCode(.writeFail,
                                               reason: Int(status))
        }
    }
    
    // MARK: Deinitializer

    deinit {
        disconnect()
    }

    // MARK: Private Instance Properties
    
    private let sslHandshakeTryCount = 1 << 26

    private var context: SSLContext?
    private var socket: Int32
    
    // MARK: Private Instance Methods
    
    private func connectSocket() throws {
//        int sock = socket(AF_INET, SOCK_STREAM, 0);
//        if (sock < 0) {
//            return [NWErrorUtil noWithErrorCode:kNWErrorSocketCreate reason:sock error:error];
//        }
//        struct sockaddr_in addr;
//        memset(&addr, 0, sizeof(struct sockaddr_in));
//        struct hostent *entr = gethostbyname(_host.UTF8String);
//        if (!entr) {
//            return [NWErrorUtil noWithErrorCode:kNWErrorSocketResolveHostName error:error];
//        }
//        struct in_addr host;
//        memcpy(&host, entr->h_addr, sizeof(struct in_addr));
//        addr.sin_addr = host;
//        addr.sin_port = htons((u_short)_port);
//        addr.sin_family = AF_INET;
//        int conn = connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
//        if (conn < 0) {
//            return [NWErrorUtil noWithErrorCode:kNWErrorSocketConnect reason:conn error:error];
//        }
//        int cntl = fcntl(sock, F_SETFL, O_NONBLOCK);
//        if (cntl < 0) {
//            return [NWErrorUtil noWithErrorCode:kNWErrorSocketFileControl reason:cntl error:error];
//        }
//        int set = 1, sopt = setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int));
//        if (sopt < 0) {
//            return [NWErrorUtil noWithErrorCode:kNWErrorSocketOptions reason:sopt error:error];
//        }
//        _socket = sock;
    }
    
    private func connectSSL() throws {
        guard
            let context = SSLCreateContext(nil,
                                           .clientSide,
                                           .streamType)
            else { throw ErrorUtil.errorWithErrorCode(.sslContext,
                                                      reason: 0) }

        let setio = SSLSetIOFuncs(context,
                                  readSSL,
                                  writeSSL)

        guard
            setio == errSecSuccess
            else { throw ErrorUtil.errorWithErrorCode(.sslIOFuncs,
                                                      reason: Int(setio)) }

        var connection = socket

        let setconn = SSLSetConnection(context,
                                       &connection)
        
        guard
            setconn == errSecSuccess
            else { throw ErrorUtil.errorWithErrorCode(.sslConnection,
                                                      reason: Int(setconn)) }

        if let host = host?.cString(using: .utf8) {
            let setpeer = SSLSetPeerDomainName(context,
                                               host,
                                               host.count)

            guard
                setpeer == errSecSuccess
                else { throw ErrorUtil.errorWithErrorCode(.sslPeerDomainName,
                                                          reason: Int(setpeer)) }
        }

        let setcert = SSLSetCertificate(context,
                                        [identity] as CFArray)

        guard
            setcert == errSecSuccess
            else { throw ErrorUtil.errorWithErrorCode(.sslCertificate,
                                                      reason: Int(setcert)) }

        self.context = context
    }

    private func handshakeSSL() throws {
        
        var status = errSSLWouldBlock
        
        for _ in 0..<sslHandshakeTryCount
            where status == errSSLWouldBlock {
                status = SSLHandshake(context!)
        }
        
        switch status {
        case errSecAuthFailed:
            throw ErrorUtil.errorWithErrorCode(.sslAuthFailed,
                                               reason: Int(status))

        case errSecInDarkWake:
            throw ErrorUtil.errorWithErrorCode(.sslInDarkWake,
                                               reason: Int(status))

        case errSecIO:
            throw ErrorUtil.errorWithErrorCode(.sslDroppedByServer,
                                               reason: Int(status))

        case errSecSuccess:
            break

        case errSSLCertExpired:
            throw ErrorUtil.errorWithErrorCode(.sslHandshakeCertExpired,
                                               reason: Int(status))

        case errSSLClientCertRequested:
            throw ErrorUtil.errorWithErrorCode(.sslHandshakeClientCertRequested,
                                               reason: Int(status))

        case errSSLClosedAbort:
            throw ErrorUtil.errorWithErrorCode(.sslHandshakeClosedAbort,
                                               reason: Int(status))

        case errSSLInternal:
            throw ErrorUtil.errorWithErrorCode(.sslHandshakeInternalError,
                                               reason: Int(status))

        case errSSLNoRootCert:
            throw ErrorUtil.errorWithErrorCode(.sslHandshakeNoRootCert,
                                               reason: Int(status))

        case errSSLPeerCertExpired:
            throw ErrorUtil.errorWithErrorCode(.sslHandshakePeerCertExpired,
                                               reason: Int(status))

        case errSSLPeerCertRevoked:
            throw ErrorUtil.errorWithErrorCode(.sslHandshakePeerCertRevoked,
                                               reason: Int(status))

        case errSSLPeerCertUnknown:
            throw ErrorUtil.errorWithErrorCode(.sslHandshakePeerCertUnknown,
                                               reason: Int(status))

            //case errSSLServerAuthCompleted:
            //    throw ErrorUtil.errorWithErrorCode(.sslHandshakeServerAuthCompleted,
            //                                       reason: Int(status))

        case errSSLUnknownRootCert:
            throw ErrorUtil.errorWithErrorCode(.sslHandshakeUnknownRootCert,
                                               reason: Int(status))

        case errSSLWouldBlock:
            throw ErrorUtil.errorWithErrorCode(.sslHandshakeTimeout,
                                               reason: Int(status))

        case errSSLXCertChainInvalid:
            throw ErrorUtil.errorWithErrorCode(.sslHandshakeXCertChainInvalid,
                                               reason: Int(status))


        default:
            throw ErrorUtil.errorWithErrorCode(.sslHandshakeFail,
                                               reason: Int(status))
        }
    }
}

private func readSSL(_ connection: SSLConnectionRef,
                     _ data: UnsafeMutableRawPointer,
                     _ length: UnsafeMutablePointer<Int>) -> OSStatus {
    return errSecSuccess
}

private func writeSSL(_ connection: SSLConnectionRef,
                      _ data: UnsafeRawPointer,
                      _ length: UnsafeMutablePointer<Int>) -> OSStatus {
    return errSecSuccess
}
