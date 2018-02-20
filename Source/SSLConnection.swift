import Foundation
import Security

@objcMembers

public class SSLConnection : NSObject {
    
    // MARK: Public Instance Properties
    
    public var host: String?
    public var port: UInt
    public var identity: NWIdentityRef?

    //MARK:- Public Instance Initializers
    
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
    
    // MARK: Public Instance De-initializer
    
    deinit {
        self.disconnect()
    }
    
    // MARK: Private Instance Methods
    
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
            close(Int32(socket))
            socket = -1
        }
    }
    
    public func read(_ data: NSMutableData,
                     length: UnsafeMutablePointer<UInt>) throws {

        guard let context = self.context
            else { return }
        
        var processed: Int = 0

        let status: OSStatus = SSLRead(context,
                                       data.mutableBytes,
                                       data.length,
                                       &processed)
        
        length.pointee = UInt(processed)
        
        switch (status) {
        case errSecSuccess:
            break
            
        case errSSLWouldBlock:
            break
            
        case errSecIO:
            throw NWErrorUtil.errorWithErrorCode(.readDroppedByServer,
                                                 reason: Int(status))
            
        case errSSLClosedAbort:
            throw NWErrorUtil.errorWithErrorCode(.readClosedAbort,
                                                 reason: Int(status))
            
        case errSSLClosedGraceful:
            throw NWErrorUtil.errorWithErrorCode(.readClosedGraceful,
                                                 reason: Int(status))
            
        default:
            throw NWErrorUtil.errorWithErrorCode(.readFail,
                                                 reason: Int(status))
        }
    }
    
    public func write(_ data: NSData,
                      length: UnsafeMutablePointer<UInt>) throws {
        
        var processed = 0
        
        guard let context = self.context
            else { return }
        
        let status: OSStatus = SSLWrite(context,
                                        data.bytes,
                                        data.length,
                                        &processed)
        
        length.pointee = UInt(processed)

        switch (status) {
            
        case errSecSuccess:
            break
            
        case errSSLWouldBlock:
            break
            
        case errSecIO:
            throw NWErrorUtil.errorWithErrorCode(.writeDroppedByServer,
                                                 reason: Int(status))
            
        case errSSLClosedAbort:
            throw NWErrorUtil.errorWithErrorCode(.writeClosedAbort,
                                                 reason: Int(status))
            
        case errSSLClosedGraceful:
            throw NWErrorUtil.errorWithErrorCode(.writeClosedGraceful,
                                                 reason: Int(status))
            
        default:
            throw NWErrorUtil.errorWithErrorCode(.writeFail,
                                                 reason: Int(status))
        }
    }
    
    // MARK: Private Instance Properties
    
    private let SSL_HANDSHAKE_TRY_COUNT = 1 << 26

    private var context: SSLContext?
    private var socket: Int
    
    // MARK:- Private Instance Methods
    
    private func connectSocket() throws {
        
        //        let sock: Int = socket(AF_INET, SOCK_STREAM, 0)
        //        if sock < 0 {
        //             throw NWErrorUtil.errorWithErrorCode(.socketCreate, reason: sock)
        //        }
    }
    
    private func connectSSL() throws {
        
        guard let context: SSLContext = SSLCreateContext(nil, .clientSide, .streamType)
            else { throw NWErrorUtil.errorWithErrorCode(.sslContext, reason: Int()) }
        
        let setio: OSStatus = SSLSetIOFuncs(context, SSLRead, SSLWrite)
        
        if setio != errSecSuccess {
            throw NWErrorUtil.errorWithErrorCode(.sslioFuncs, reason: Int(setio))
        }
        
        let setconn: OSStatus = SSLSetConnection(context, (Int(socket) as? SSLConnectionRef))
        
        if setconn != errSecSuccess {
            throw NWErrorUtil.errorWithErrorCode(.sslConnection, reason: Int(setconn))
        }
        
        let setpeer: OSStatus = SSLSetPeerDomainName(context, host?.utf8CString, strlen(host.utf8CString))
        
        if setpeer != errSecSuccess {
            throw NWErrorUtil.errorWithErrorCode(.sslPeerDomainName, reason: Int(setpeer))
        }
        
    }
    private func handshakeSSL() throws {
        
        var status: OSStatus = errSSLWouldBlock
        
        for _ in 0..<SSL_HANDSHAKE_TRY_COUNT {
            status = SSLHandshake(context!)
        }
        
        switch status {
            
        case errSSLWouldBlock:
            throw NWErrorUtil.errorWithErrorCode(.sslHandshakeTimeout,
                                                 reason: Int(status))
            
        case errSecIO:
            throw NWErrorUtil.errorWithErrorCode(.sslDroppedByServer,
                                                 reason: Int(status))
            
        case errSecAuthFailed:
            throw NWErrorUtil.errorWithErrorCode(.sslAuthFailed,
                                                 reason: Int(status))
            
        case errSSLUnknownRootCert:
            throw NWErrorUtil.errorWithErrorCode(.sslHandshakeUnknownRootCert,
                                                 reason: Int(status))
            
        case errSSLNoRootCert:
            throw NWErrorUtil.errorWithErrorCode(.sslHandshakeNoRootCert,
                                                 reason: Int(status))
            
        case errSSLCertExpired:
            throw NWErrorUtil.errorWithErrorCode(.sslHandshakeCertExpired,
                                                 reason: Int(status))
            
        case errSecSuccess:
            break
            
        default:
            break
        }
    }
    
}
