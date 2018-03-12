import Foundation

public class SSLConnection {

    // MARK: Public Initializers

    public convenience init() {
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

    public func read(_ data: NSMutableData) throws -> UInt {
        guard
            let context = self.context
            else { return 0 }

        var processed = Int(0)

        let status = SSLRead(context,
                             data.mutableBytes,
                             data.length,
                             &processed)

        let length = UInt(processed)

        switch status {
        case errSecIO:
            throw PushError.readDroppedByServer

        case errSecSuccess,
             errSSLWouldBlock:
            return length

        case errSSLClosedAbort:
            throw PushError.readClosedAbort

        case errSSLClosedGraceful:
            throw PushError.readClosedGraceful

        default:
            throw PushError.readFail
        }
    }

    public func write(_ data: NSData) throws -> UInt? {
        guard
            let context = self.context
            else { return nil }

        var length: UInt?
        var processed = Int(0)

        let status = SSLWrite(context,
                              data.bytes,
                              data.length,
                              &processed)

        length = UInt(processed)

        switch status {
        case errSecIO:
            throw PushError.writeDroppedByServer

        case errSecSuccess,
             errSSLWouldBlock:
            return length

        case errSSLClosedAbort:
            throw PushError.writeClosedAbort

        case errSSLClosedGraceful:
            throw PushError.writeClosedGraceful
        default:
            throw PushError.writeFail
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
            else { throw PushError.socketCreate }

        guard
            let hostName = host?.cString(using: .utf8),
            let hostEntry = gethostbyname(hostName)?.pointee,
            let hostAddressList = hostEntry.h_addr_list?.pointee
            else { throw PushError.socketResolveHostName }

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
            else { throw PushError.socketConnect }

        let cntl = Darwin.fcntl(sock, F_SETFL, O_NONBLOCK)

        guard
            cntl >= 0
            else { throw PushError.socketFileControl }

        var set = 1
        let sopt = Darwin.setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &set, 4)

        guard
            sopt >= 0
            else { throw PushError.socketOptions }

        self.socket = sock
    }

    private func connectSSL() throws {
        guard
            let context = SSLCreateContext(nil,
                                           .clientSide,
                                           .streamType)
            else { throw PushError.sslContext }

        let setio = SSLSetIOFuncs(context,
                                  readSSL,
                                  writeSSL)

        guard
            setio == errSecSuccess
            else { throw PushError.sslIOFuncs }

        let connection = UnsafeMutableRawPointer.allocate(bytes: 4,
                                                          alignedTo: 4)

        connection.storeBytes(of: socket,
                              as: Int32.self)

        rawConnection = connection

        let setconn = SSLSetConnection(context,
                                       connection)

        guard
            setconn == errSecSuccess
            else { throw PushError.sslConnection }

        if let host = host?.cString(using: .utf8) {
            let setpeer = SSLSetPeerDomainName(context,
                                               host,
                                               host.count)

            guard
                setpeer == errSecSuccess
                else { throw PushError.sslPeerDomainName }
        }

        let setcert = SSLSetCertificate(context,
                                        [identity] as CFArray)

        guard
            setcert == errSecSuccess
            else { throw PushError.sslCertificate }

        self.context = context
    }

    private func handshakeSSL() throws {
        guard
            let context = self.context
            else { throw PushError.sslHandshakeFail }

        var status = errSSLWouldBlock

        for _ in 0..<sslHandshakeTryCount {
            status = SSLHandshake(context)

            guard
                status == errSSLWouldBlock
                else { break }
        }

        try SSLError.throwIfHandshakeSSLError(status)
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
