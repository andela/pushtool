import Foundation

@objcMembers
public class PushFeedback : NSObject {

    public var connection: NWSSLConnection?
    public let pushHost = "feedback.push.apple.com"
    public let pushPort = 2196
    public let sandboxPushHost = "feedback.sandbox.push.apple.com"
    public let tokenMaxSize = 32

    public class func connect(withIdentity identity: NWIdentityRef,
                              environment: NWEnvironment) throws -> PushFeedback {
        let feedback = PushFeedback()

        try feedback.connect(withIdentity: identity,
                             environment: environment)

        return feedback
    }

    public class func connect(withPKCS12Data data: Data,
                              password: String?,
                              environment: NWEnvironment) throws -> PushFeedback {
        let feedback = PushFeedback()

        try feedback.connect(withPKCS12Data: data,
                             password: password,
                             environment: environment)

        return feedback
    }

    public func connect(withIdentity identity: NWIdentityRef,
                        environment: NWEnvironment) throws {

        self.connection?.disconnect()

        var environment = environment

        if environment == .auto {
            environment = NWSecTools.environment(forIdentity: identity)
        }

        let host = (environment == .sandbox) ? sandboxPushHost : pushHost

        if let connection = NWSSLConnection(host: host,
                                            port: UInt(pushPort),
                                            identity: identity) {

            try connection.connect()
            self.connection = connection
        }
    }


    public func connect(withPKCS12Data data: Data,
                        password: String?,
                        environment: NWEnvironment) throws {

        guard let identity = try NWSecTools.identity(withPKCS12Data: data,
                                                     password: password) as NWIdentityRef?
            else { return }

        try connect(withIdentity: identity,
                    environment: environment)
    }

    public func disconnect() {
        connection = NWSSLConnection()
        connection?.disconnect()
    }

    public func readTokenData(_ token: Data?, date: Date?) throws {

        let data = NSMutableData(length: (UInt8.bitWidth*2 + UInt32.bitWidth + tokenMaxSize))
        let length = 0

        try connection?.read(data, length:length)
        if (length != data?.length) {
            NWErrorUtil.errorWithErrorCode(.feedbackLength, reason: Int(length))
        }
        var time : UnsafeMutablePointer<UInt8>? = nil
        time?.pointee = 0
        data?.getBytes(&time, range: NSMakeRange(0, 4))
        var l: UInt16 = 0
        data?.getBytes(&l, range: NSMakeRange(4, 2))
        let tokenLength = Int(l)
        if tokenLength != tokenMaxSize {
            NWErrorUtil.errorWithErrorCode(.feedbackTokenLength, reason: tokenLength)
        }
    }

    public func readToken(_ token: String?, date: Date?) throws {

        var data: Data?
        try self.readTokenData(data, date: date)
        if data != nil, let data = data  {
            NWNotification.hex(from: data)
        }

    }

    public func readTokenDatePairs(withMax max: Int) throws -> [Any] {
        var pairs = [Any]()
        for _ in 0..<max {
            var token: String?
            var date: Date?
            try self.readToken(token, date: date)

            if token != nil && date != nil {
                if let token = token, let date = date {
                    pairs.append(contentsOf: [token, date])
                }
            }
        }
        return pairs
    }
}
