import Foundation

public class Notification: NSObject {

    public var addExpiration: Bool
    public var expiration: Date?
    public var expirationStamp: UInt
    public var identifier: UInt
    public var payload: String?
    public var payloadData: Data?
    public var priority: UInt
    public var token: String?
    public var tokenData: Data?

    private let deviceTokenSize: UInt = 32
    private let payloadMaxSize: UInt = 256


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

    public func data(with type: NotificationType) -> Data {

//        switch type {
//        case .type0:
//            return
//        default:
//            <#code#>
//        }
        return Data()
    }

    private func filter(_ hex: String) -> String {

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

    private func getPayload() -> String? {
        guard let payload = payloadData else {
            return nil
        }

        let string = String(data: payload, encoding: .utf8)

        return string
    }

    private func setPayload(_ payload: String) {


    }


    private func dataWithType0() -> Data {

        var size = (UInt8.bitWidth / 8)
        size += (UInt32.bitWidth / 8) * 2
        size += (UInt16.bitWidth / 8)
        size += Int((deviceTokenSize))
        size += (UInt16.bitWidth / 8)
        size += Int((payloadMaxSize))

        let command: UInt8 = 0


        return Data()
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
