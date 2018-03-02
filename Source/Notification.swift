import Foundation

@objcMembers
public class Notification: NSObject {

    public let addExpiration: Bool
    public let expirationStamp: UInt
    public let payloadData: Data
    public let priority: UInt
    public let tokenData: Data
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
        self.payloadData = payload.data(using: .utf8) ?? Data()
        self.priority = priority
        self.payload = payload
        self.token = token
        self.expires = expiration

        let normal = Notification.filter(token)
        let trunk = normal.count >= 64 ? String(normal.prefix(64)) : ""

        self.tokenData = Notification.data(fromHex: trunk)
    }

    public class func data(fromHex hex: String) -> Data {
        return Data(hexEncoded: hex) ?? Data()
    }

    public class func hex(from data: Data) -> String {

        guard let stringValue = data.utf8String
            else { return "" }

        return stringValue
    }

    public func data() -> Data {
        var expires: UInt32 = UInt32(expirationStamp).bigEndian
        var identifier: UInt32 = UInt32(self.identifier).bigEndian
        var priority = self.priority
        let result = NSMutableData()

        var command: UInt8 = 2
        var length: UInt32 = 0

        result.append(&command, length: 1)
        result.append(&length, length: 4)

        let tokenData = self.tokenData as NSData

        append(to: result,
               identifier: 1,
               bytes: tokenData.bytes,
               length: tokenData.length)

        let payloadData = self.payloadData as NSData

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

        if (addExpiration) {
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

extension Data {

    var utf8String: String? {
        return string(as: .utf8)
    }

    func string(as encoding: String.Encoding) -> String? {
        return String(data: self, encoding: encoding)
    }

    public init?(hexEncoded hexData: Data) {

        // Convert 0 ... 9, a ... f, A ...F to their decimal value,
        // return nil for all other input characters
        func decodeDigit(_ digit: UInt8) -> UInt8? {

            switch digit {

            case 0x30 ... 0x39:
                return UInt8(digit - 0x30)

            case 0x41 ... 0x46:
                return UInt8(digit - 0x41 + 10)

            case 0x61 ... 0x66:
                return UInt8(digit - 0x61 + 10)

            default:
                return nil

            }

        }

        let inCount = hexData.count

        guard (inCount & 1) == 0    // must be even
            else { return nil }

        self.init(capacity: inCount >> 1)

        var index = 0

        while index < inCount {

            guard let digitHi = decodeDigit(hexData[index]),
                let digitLo = decodeDigit(hexData[index + 1])
                else { return nil }

            append(UInt8((digitHi << 4) | digitLo))

            index += 2
        }
    }

    public init?(hexEncoded hexString: String) {
        guard let hexData: Data = hexString.data(using: .utf8)
            else { return nil }

        self.init(hexEncoded: hexData)
    }

    public func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}
