import Foundation

public class Notification {
    public let addExpiration: Bool
    public let expirationStamp: UInt
    public let priority: UInt
    public let payload: String
    public let token: String
    public let expires: Date?

    public var identifier: UInt

    private let deviceTokenSize: UInt = 32
    private let payloadMaxSize: UInt = 256

    public init(payload: String,
                token: String,
                identifier: UInt,
                expiration: Date?,
                priority: UInt) {
        if let expiration = expiration {
            self.addExpiration = true
            self.expirationStamp = UInt(expiration.timeIntervalSince1970)
        } else {
            self.addExpiration = false
            self.expirationStamp = 0
        }

        self.identifier = identifier
        self.priority = priority
        self.payload = payload
        self.token = token
        self.expires = expiration
    }

    private static func data(from hex: String) -> Data {
        return Data(hexEncoded: hex) ?? Data()
    }

    public func data() -> Data {
        var expires: UInt32 = UInt32(expirationStamp).bigEndian
        var identifier: UInt32 = UInt32(self.identifier).bigEndian
        var priority = self.priority
        let normal = Notification.filter(token)
        let result = NSMutableData()
        let trunk = normal.count >= 64 ? String(normal.prefix(64)) : ""

        var command: UInt8 = 2
        var length: UInt32 = 0

        result.append(&command, length: 1)
        result.append(&length, length: 4)

        let tokenData = Notification.data(from: trunk) as NSData
        append(to: result,
               identifier: 1,
               bytes: tokenData.bytes,
               length: tokenData.length)

        let payloadData = (payload.data(using: .utf8) ?? Data()) as NSData
        append(to: result,
               identifier: 2,
               bytes: payloadData.bytes,
               length: payloadData.length)

        if identifier != 0 {
            append(to: result,
                   identifier: 3,
                   bytes: &identifier,
                   length: 4)
        }

        if addExpiration {
            append(to: result,
                   identifier: 4,
                   bytes: &expires,
                   length: 4)
        }

        if priority != 0 {
            append(to: result,
                   identifier: 5 ,
                   bytes: &priority,
                   length: 1)
        }

        length = UInt32(result.length - 5).bigEndian

        result.replaceBytes(in: NSRange(location: 1, length: 4),
                            withBytes: &length,
                            length: 4)

        return result as Data
    }

    private func append(to buffer: NSMutableData,
                        identifier: UInt,
                        bytes: UnsafeRawPointer,
                        length: Int) {
        var id = UInt8(identifier)
        var len = UInt16(length).bigEndian

        buffer.append(&id, length: 1)
        buffer.append(&len, length: 2)
        buffer.append(bytes, length: length)
    }

    private static func filter(_ hex: String) -> String {
        return hex.lowercased().filter { "0123456789abcdef".contains($0) }
    }
}
