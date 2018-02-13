import Foundation

public class Notification: NSObject {

    public var payload: String?
    public var payloadData: Data?
    public var token: String?
    public var tokenData: Data?
    public var identifier: UInt
    public var expiration: Date?
    public var expirationStamp: UInt
    public var priority: UInt
    public var addExpiration: Bool

    public init(payload: String,
                token: String,
                identifier: UInt,
                expiration: Date?,
                priority: UInt) {
        self.payload = payload
        self.token = token
        self.identifier = identifier
        self.expiration = expiration
        self.expirationStamp = 0
        self.priority = priority
        self.addExpiration = false
    }

    public init(payloadData: Data,
                tokenData: Data,
                identifier: UInt,
                expirationStamp: UInt,
                addExpiration: Bool,
                priority: UInt) {
        self.payloadData = payloadData
        self.tokenData = tokenData
        self.identifier = identifier
        self.expirationStamp = expirationStamp
        self.addExpiration = addExpiration
        self.priority = priority
    }

    public func data(with type: NWNotificationType) -> Data {
        return Data()
    }

    public class func data(fromHex hex: String) -> Data {
        return Data()
    }

    public class func hex(from data: Data) -> String {
        return ""
    }

    private let deviceTokenSize: UInt = 32
    private let payloadMaxSize: UInt = 256
}
