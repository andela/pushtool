import Foundation

@objcMembers
public class Pusher: NSObject {

    // MARK: Public Type Methods

    public class func connect(withIdentity identity: IdentityRef,
                              environment: Environment) throws -> Pusher {
        let pusher = Pusher()

        try pusher.connect(withIdentity: identity,
                           environment: environment)

        return pusher
    }

    public class func connect(withPKCS12Data data: Data,
                              password: String,
                              environment: Environment) throws -> Pusher {
        let pusher = Pusher()

        try pusher.connect(withPKCS12Data: data,
                           password: password,
                           environment: environment)

        return pusher
    }

    // MARK: Public Instance Properties

    public var connection: SSLConnection?

    // MARK: Public Instance Methods

    public func connect(withIdentity identity: IdentityRef,
                        environment: Environment) throws {
        self.connection?.disconnect()

        var environment = environment

        if environment == .auto {
            let options = SecTools.environmentOptions(forIdentity: identity)

            environment = options != .production ? .sandbox : .production
        }

        let host = (environment == .sandbox) ? sandboxPushHost : pushHost

        let connection = SSLConnection(host: host,
                                       port: pushPort,
                                       identity: identity)
        try connection.connect()

        self.connection = connection
    }

    public func connect(withPKCS12Data data: Data,
                        password: String,
                        environment: Environment) throws {
        let identity: IdentityRef = try SecTools.identities(withPKCS12Data: data,
                                                            password: password) as IdentityRef

        try connect(withIdentity: identity,
                    environment: environment)
    }

    public func disconnect() {
        self.connection?.disconnect()
        self.connection = nil
    }

    public func pushNotification(_ notification: Notification) throws {
        let data = notification.data()

        guard let connection = self.connection
            else { return }

        var length: UInt = 0

        try connection.write(data as NSData,
                             length: &length)

        if length != data.count {
            throw ErrorUtil.errorWithErrorCode(.pushWriteFail,
                                               reason: Int(length))
        }
    }

    public func pushPayload(_ payload: String,
                            token: String,
                            identifier: UInt) throws {
        let notification = Notification(payload: payload,
                                        token: token,
                                        identifier: identifier,
                                        expiration: nil,
                                        priority: 0)

        try self.pushNotification(notification)
    }

    public func readFailedIdentifier(_ identifier: UnsafeMutablePointer<Int>,
                                     apnError: NSErrorPointer) throws {

        identifier.pointee = 0
        apnError?.pointee = nil

        let length = UInt((UInt8.bitWidth * 2) / 8 + (UInt32.bitWidth) / 8 )
        let data = NSMutableData(length: Int(length))

        if let data = data {
            var len: UInt = 0
            try self.connection?.read(data,
                                      length: &len)

            if len == 0 {
                return
            }
        }

        var command: UInt8 = 0

        data?.getBytes(&command,
                       range: NSRange(location: 0, length: 1))

        if command != 8 {
            throw ErrorUtil.errorWithErrorCode(.pushResponseCommand,
                                               reason: Int(command))
        }

        var status: UInt8 = 0

        data?.getBytes(&status,
                       range: NSRange(location: 1, length: 1))

        var ident: UInt32 = 0

        data?.getBytes(&ident,
                       range: NSRange(location: 2, length: 4))

        identifier.pointee = Int(UInt32(bigEndian: ident))

        apnError?.pointee = error(for: Int(status))
    }

    public func reconnect() throws {
        try self.connection?.connect()
    }

    // MARK: Private Instance Properties

    private let pushHost = "gateway.push.apple.com"
    private let pushPort: UInt = 2_195
    private let sandboxPushHost = "gateway.sandbox.push.apple.com"

    // MARK: Private Instance Methods

    private func error(for status: Int) -> NSError {
        switch status {
        case 1:
            return ErrorUtil.errorWithErrorCode(.apnProcessing,
                                                reason: status)

        case 2:
            return ErrorUtil.errorWithErrorCode(.apnMissingDeviceToken,
                                                reason: status)

        case 3:
            return ErrorUtil.errorWithErrorCode(.apnMissingTopic,
                                                reason: status)

        case 4:
            return ErrorUtil.errorWithErrorCode(.apnMissingPayload,
                                                reason: status)

        case 5:
            return ErrorUtil.errorWithErrorCode(.apnInvalidTokenSize,
                                                reason: status)

        case 6:
            return ErrorUtil.errorWithErrorCode(.apnInvalidTopicSize,
                                                reason: status)

        case 7:
            return ErrorUtil.errorWithErrorCode(.apnInvalidPayloadSize,
                                                reason: status)

        case 8:
            return ErrorUtil.errorWithErrorCode(.apnInvalidTokenContent,
                                                reason: status)

        case 10:
            return ErrorUtil.errorWithErrorCode(.apnShutdown,
                                                reason: status)

        default:
            return ErrorUtil.errorWithErrorCode(.apnUnknownErrorCode,
                                                reason: status)
        }
    }
}
