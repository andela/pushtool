import Foundation

public class Pusher {

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
        let identity: IdentityRef = try SecTools.identities(with: data,
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
            throw PushError.pushWriteFail
        }
    }

    public func pushPayload(_ payload: String,
                            token: String,
                            identifier: UInt) throws {
        let notification = Notification(payload: payload,
                                        token: token,
                                        identifier: identifier,
                                        expires: nil,
                                        priority: 0)

        try self.pushNotification(notification)
    }

    // TODO: refactor to have signature:
    //
    //      public func readFailedIdentifier() throws -> (Int, Error) {}
    
    public func readFailedIdentifier(_ identifier: Int,
                                     apnError: Error) throws -> (Int, Error) {
        
        let length = UInt((UInt8.bitWidth * 2) / 8 + (UInt32.bitWidth) / 8 )
        let data = NSMutableData(length: Int(length))
        
        if let data = data {
            var len: UInt = 0
            try self.connection?.read(data as Data,
                                      length: &len)
            
            if len == 0 {
                return (0, apnError)
            }
        }
        
        var command: UInt8 = 0
        
        data?.getBytes(&command,
                       range: NSRange(location: 0, length: 1))
        
        if command != 8 {
            throw PushError.pushResponseCommand
        }
        
        var status: UInt8 = 0
        
        data?.getBytes(&status,
                       range: NSRange(location: 1, length: 1))
        
        var ident: UInt32 = 0
        
        data?.getBytes(&ident,
                       range: NSRange(location: 2, length: 4))
        
        return (Int(UInt32(bigEndian: ident)), error(for: Int(status)) as NSError)
    }
//
//    public func readFailedIdentifier(_ identifier: UnsafeMutablePointer<Int>,
//                                     apnError: ErrorPointer) throws {
//        identifier.pointee = 0
//        apnError?.pointee = nil
//
//        let length = UInt((UInt8.bitWidth * 2) / 8 + (UInt32.bitWidth) / 8 )
//        let data = NSMutableData(length: Int(length))
//
//        if let data = data {
//            var len: UInt = 0
//            try self.connection?.read(data,
//                                      length: &len)
//
//            if len == 0 {
//                return
//            }
//        }
//
//        var command: UInt8 = 0
//
//        data?.getBytes(&command,
//                       range: NSRange(location: 0, length: 1))
//
//        if command != 8 {
//            throw PushError.pushResponseCommand
//        }
//
//        var status: UInt8 = 0
//
//        data?.getBytes(&status,
//                       range: NSRange(location: 1, length: 1))
//
//        var ident: UInt32 = 0
//
//        data?.getBytes(&ident,
//                       range: NSRange(location: 2, length: 4))
//
//        identifier.pointee = Int(UInt32(bigEndian: ident))
//
//        apnError?.pointee = error(for: Int(status)) as NSError
//    }

    public func reconnect() throws {
        try self.connection?.connect()
    }

    // MARK: Private Instance Properties

    private let pushHost = "gateway.push.apple.com"
    private let pushPort: UInt = 2_195
    private let sandboxPushHost = "gateway.sandbox.push.apple.com"

    // MARK: Private Instance Methods

    private func error(for status: Int) -> PushError {
        switch status {
        case 1:
            return PushError.apnProcessing

        case 2:
            return PushError.apnMissingDeviceToken

        case 3:
            return PushError.apnMissingTopic

        case 4:
            return PushError.apnMissingPayload

        case 5:
            return PushError.apnInvalidTokenSize

        case 6:
            return PushError.apnInvalidTopicSize

        case 7:
            return PushError.apnInvalidPayloadSize

        case 8:
            return PushError.apnInvalidTokenContent

        case 10:
            return PushError.apnShutdown

        default:
            return PushError.apnUnknownErrorCode
        }
    }
}
