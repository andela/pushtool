import Foundation
import Security

@objcMembers
public class SSLConnection: NSObject {

    // MARK: Public Initializers

    public override convenience init() {
        self.init(host: nil,
                  port: 0,
                  identity: nil)
    }

    public init(host: String?,
                port: UInt,
                identity: IdentityRef?) {
        self.identity = identity
        self.host = host
        self.port = port
        self.socket = -1
    }

    // MARK: Public Instance Properties

    public var host: String?
    public var identity: IdentityRef?
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

            self.context = nil
        }

        if let connection = rawConnection {
            connection.deallocate(bytes: 4,
                                  alignedTo: 4)

            rawConnection = nil
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
    private var rawConnection: UnsafeMutableRawPointer?
    private var socket: Int32

    // MARK: Private Instance Methods

    private func connectSocket() throws {
        let sock = Darwin.socket(AF_INET, SOCK_STREAM, 0)

        guard
            sock >= 0
            else { throw ErrorUtil.errorWithErrorCode(.socketCreate,
                                                      reason: Int(sock)) }

        guard
            let hostName = host?.cString(using: .utf8),
            let hostEntry = gethostbyname(hostName)?.pointee,
            let hostAddressList = hostEntry.h_addr_list?.pointee
            else { throw ErrorUtil.errorWithErrorCode(.socketResolveHostName,
                                                      reason: 0) }

        let hostAddress = hostAddressList.withMemoryRebound(to: in_addr.self,
                                                            capacity: 1) { $0.pointee }
        let sinLength = MemoryLayout<sockaddr_in>.size

        var sin = sockaddr_in(sin_len: UInt8(sinLength),
                              sin_family: sa_family_t(AF_INET),
                              sin_port: in_port_t(port).bigEndian,
                              sin_addr: hostAddress,
                              sin_zero: (0, 0, 0, 0, 0, 0, 0, 0))

        let conn = withUnsafePointer(to: &sin) {
            $0.withMemoryRebound(to: sockaddr.self,
                                 capacity: 1) {
                                    Darwin.connect(sock, $0, socklen_t(sinLength))
            }
        }

        guard
            conn >= 0
            else { throw ErrorUtil.errorWithErrorCode(.socketConnect,
                                                      reason: Int(conn)) }

        let cntl = Darwin.fcntl(sock, F_SETFL, O_NONBLOCK)

        guard
            cntl >= 0
            else { throw ErrorUtil.errorWithErrorCode(.socketFileControl,
                                                      reason: Int(cntl)) }

        var set = 1
        let sopt = Darwin.setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &set, 4)

        guard
            sopt >= 0
            else { throw ErrorUtil.errorWithErrorCode(.socketOptions,
                                                      reason: Int(sopt)) }

        self.socket = sock
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

        let connection = UnsafeMutableRawPointer.allocate(bytes: 4,
                                                          alignedTo: 4)

        connection.storeBytes(of: socket,
                              as: Int32.self)

        rawConnection = connection

        let setconn = SSLSetConnection(context,
                                       connection)

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
        guard
            let context = self.context
            else { throw ErrorUtil.errorWithErrorCode(.sslHandshakeFail,
                                                      reason: 0) }

        var status = errSSLWouldBlock

        for _ in 0..<sslHandshakeTryCount {
            status = SSLHandshake(context)

            guard
                status == errSSLWouldBlock
                else { break }
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

        case errSSLPeerAuthCompleted:
            throw ErrorUtil.errorWithErrorCode(.sslHandshakeServerAuthCompleted,
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
    let socket = connection.load(as: Int32.self)
    let dataLength = length.pointee

    length.pointee = 0

    var rcvdLength = 0
    var rcvdTotal = 0

    while rcvdTotal < dataLength {
        rcvdLength = Darwin.recv(socket,
                           data.advanced(by: rcvdTotal),
                           dataLength - rcvdTotal,
                           0)

        guard
            rcvdLength > 0
            else { break }

        rcvdTotal += rcvdLength
    }

    length.pointee = rcvdTotal

    if rcvdLength > 0 || dataLength == 0 {
        return errSecSuccess
    }

    if rcvdLength == 0 {
        return errSSLClosedGraceful
    }

    switch errno {
    case EAGAIN:
        return errSSLWouldBlock

    case ECONNRESET:
        return errSSLClosedAbort

    default:
        return errSecIO
    }
}

private func writeSSL(_ connection: SSLConnectionRef,
                      _ data: UnsafeRawPointer,
                      _ length: UnsafeMutablePointer<Int>) -> OSStatus {
    let socket = connection.load(as: Int32.self)
    let dataLength = length.pointee

    length.pointee = 0

    var sentLength = 0
    var sentTotal = 0

    while sentTotal < dataLength {
        sentLength = Darwin.send(socket,
                                 data.advanced(by: sentTotal),
                                 dataLength - sentTotal,
                                 0)

        guard
            sentLength > 0
            else { break }

        sentTotal += sentLength
    }

    length.pointee = sentTotal

    if sentLength > 0 || dataLength == 0 {
        return errSecSuccess
    }

    switch errno {
    case EAGAIN:
        return errSSLWouldBlock

    case EPIPE:
        return errSSLClosedAbort

    default:
        return errSecIO
    }
}
