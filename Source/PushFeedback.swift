import Foundation

public class PushFeedback {
    public var connection: SSLConnection?
    public let pushHost = "feedback.push.apple.com"
    public let pushPort = 2_196
    public let sandboxPushHost = "feedback.sandbox.push.apple.com"
    public let tokenMaxSize = 32

    public class func connect(with identity: IdentityRef,
                              environment: Environment) throws -> PushFeedback {
        let feedback = PushFeedback()

        try feedback.connect(with: identity,
                             environment: environment)

        return feedback
    }

    public class func connect(with data: Data,
                              password: String?,
                              environment: Environment) throws -> PushFeedback {
        let feedback = PushFeedback()

        try feedback.connect(with: data,
                             password: password,
                             environment: environment)

        return feedback
    }

    public func connect(with identity: IdentityRef,
                        environment: Environment) throws {
        self.connection?.disconnect()

        var environment = environment

        if environment == .auto {
            let options = SecTools.environmentOptions(forIdentity: identity)

            environment = options != .production ? .sandbox : .production
        }

        let host = (environment == .sandbox) ? sandboxPushHost : pushHost

        let connection = SSLConnection(host: host,
                                       port: UInt(pushPort),
                                       identity: identity)

        try connection.connect()

        self.connection = connection
    }

    public func connect(with data: Data,
                        password: String?,
                        environment: Environment) throws {
        guard
            let password = password,
            let identity = try SecIdentityTools.identity(with: data,
                                                         password: password) as IdentityRef?
            else { return }

        try connect(with: identity,
                    environment: environment)
    }

    public func disconnect() {
        connection?.disconnect()
        connection = nil
    }

    public func readTokenDatePairs(withMax max: Int) throws -> [[Any]] {
        var pairs: [[Any]] = []

        for _ in 0..<max {
            let (token, date) = try readToken()

            pairs.append([token, date])
        }

        return pairs
    }

    private func readTokenData() throws -> (Data, Date) {
        let dataSize = (UInt8.bitWidth * 2 + UInt32.bitWidth + tokenMaxSize) / 8

        guard
            let data = NSMutableData(length: dataSize)
            else { return (Data(), Date()) }

        let length = try connection?.read(data)

        guard let dataLength = length,
            dataLength != data.length
        else { throw PushError.feedbackLength }

        var time: UInt32 = 0

        data.getBytes(&time, range: NSRange(location: 0, length: 4))

        let date = Date(timeIntervalSince1970: TimeInterval(UInt32(bigEndian: time)))

        var len: UInt16 = 0

        data.getBytes(&len, range: NSRange(location: 4, length: 2))

        let tokenLength = Int(UInt16(bigEndian: len))

        if tokenLength != tokenMaxSize {
            throw PushError.feedbackTokenLength
        }

        let token = data.subdata(with: NSRange(location: 6,
                                               length: Int(dataLength - 6)))

        return (token, date)
    }

    private func readToken() throws -> (String, Date) {
        let (data, date) = try readTokenData()

        return (data.hexEncodedString(), date)
    }
}
