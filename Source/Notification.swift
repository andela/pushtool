import Foundation

@objcMembers
public class Notification: NSObject {

    public var addExpiration: Bool
    //public var expiration: Date?        // should be computed property (if needed)
    public var expirationStamp: UInt
    public var identifier: UInt
    //public var payload: String          // should be computed property (if needed)
    public var payloadData: Data
    public var priority: UInt
    //public var token: String            // should be computed property (if needed)
    public var tokenData: Data

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

        let normal = Notification.filter(token)
        let trunk = normal.count >= 64 ? String(normal.prefix(64)) : ""

        self.tokenData = Notification.data(fromHex: trunk)
    }

    public class func data(fromHex hex: String) -> Data {

        var result = Data()

        hex.utf8.forEach { (scalarValue) in
            var scalarUInt8 = UInt8(scalarValue)
            result.append(&scalarUInt8, count: 1)
        }
        return result
    }

    public class func hex(from data: Data) -> String {

        guard let stringValue = data.utf8String
            else { return ""}

        return stringValue
    }

    public func data(with type: NWNotificationType) -> Data {
        return dataWithType2()
    }

    private func dataWithType2() -> Data {

        var expires: UInt32 = UInt32(expirationStamp)
        var identifier: UInt32 = UInt32(self.identifier)
        var priority = self.priority
        let result = NSMutableData()

        var command: UInt8 = 2
        var length: UInt32 = 0

        result.append(&command, length: 1)

        let tokenData = self.tokenData as NSData

        length += UInt32(tokenData.length)
        append(to: result,
               identifier: 1,
               bytes: tokenData.bytes,
               length: tokenData.length)

        let payloadData = self.payloadData as NSData

        length += UInt32(payloadData.length)
        append(to: result,
               identifier: 2,
               bytes: payloadData.bytes,
               length: payloadData.length)

        if identifier != 0 {
            length += UInt32(4)
            append(to: result,
                   identifier: 3,
                   bytes: &identifier,
                   length: 4)
        }

        if (addExpiration) {
            length += UInt32(4)
            append(to: result,
                   identifier:4,
                   bytes:&expires,
                   length: 4)

        }

        if priority != 0 {
            length += UInt32(1)
            append(to:result,
                   identifier:5 ,
                   bytes:&priority,
                   length:1)
        }

        result.append(&length, length: 4)

        return result as Data
    }

    private func append(to buffer: NSMutableData,
                        identifier: UInt,
                        bytes: UnsafeRawPointer,
                        length: Int) {
        var id = UInt8(identifier)
        var len = UInt16(length)

        buffer.append(&id, length: 1)
        buffer.append(&len, length: 2)
        buffer.append(bytes, length: length)
    }

    private static func filter(_ hex: String) -> String {

        let hexToLowerCase = hex.lowercased()
        var result = String()

        for index in 0..<hex.count {
            let charIndex = hexToLowerCase.index(hexToLowerCase.startIndex,
                                                 offsetBy: index)
            let char = hexToLowerCase[charIndex]
            if (char == "a" && char <= "f") || (char >= "0" && char <= "9") {

                result.append(char)
            }
        }

        return result
    }
}

extension Data {

    var utf8String: String? {
        return string(as: .utf8)
    }

    func string(as encoding: String.Encoding) -> String? {
        return String(data: self, encoding: encoding)
    }
}
