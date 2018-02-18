
import Foundation

@objcMembers
public class Pusher : NSObject {
    
    private let sandboxPushHost = "gateway.sandbox.push.apple.com"
    private let pushHost = "gateway.push.apple.com"
    private let pushPort: UInt = 2195
    
    public var connection: NWSSLConnection?

    public class func connect(withIdentity identity: NWIdentityRef, environment: NWEnvironment) throws -> Pusher {
            let pusher = Pusher()
        
            try pusher.connect(withIdentity: identity,
                               environment: environment)
            return pusher
    }
    
    public class func connect(withPKCS12Data data: Data,
                              password: String,
                              environment: NWEnvironment) throws -> Pusher {
        let pusher = Pusher()
        try pusher.connect(withPKCS12Data: data, password: password, environment: environment)
        return pusher
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
                                            port: pushPort,
                                            identity: identity) {
            try connection.connect()
            self.connection = connection
        }
    }
    
    public func connect(withPKCS12Data data: Data,
                        password: String,
                        environment: NWEnvironment) throws {
        let identity: NWIdentityRef = try NWSecTools.identities(withPKCS12Data: data,
                                                                password: password) as NWIdentityRef

        try connect(withIdentity: identity,
                    environment: environment)
    }
    
    public func reconnect() throws {
        try self.connection?.connect()
    }
    
    public func disconnect() {
        self.connection?.disconnect()
        self.connection = nil
    }
    
    public func pushPayload(_ payload: String, token: String, identifier: UInt) throws {
        let notification = NWNotification(payload: payload,
                                          token: token,
                                          identifier: identifier,
                                          expiration: nil,
                                          priority: 0)
        try self.push(notification, type: .type2)
    }

    public func push(_ notification: NWNotification,
                     type: NWNotificationType) throws {
        var length: UInt = 0
        let data = notification.data(with: .type2)

        guard let SSLConnection = self.connection
            else { return  }

        try SSLConnection.write(data, length: &length)

        if length != data.count {
            throw NWErrorUtil.errorWithErrorCode(.pushWriteFail,
                                                 reason: Int(length))
        }
    }
    
    public func readFailedIdentifier(_ identifier: UnsafeMutablePointer<UInt>) throws {
        
        let identifier = identifier
        
        identifier.pointee = 0
        
        let dataLength = UInt8.bitWidth*2 + UInt32.bitWidth
        
        let data = NSMutableData(length: dataLength)
        
        try self.connection?.read(data, length: identifier)
        
        var command: UInt8 = 0
        data?.getBytes(&command, range: NSMakeRange(0, 1))
        
        if command != 8 {
            throw NWErrorUtil.errorWithErrorCode(.pushResponseCommand, reason: Int(command))
        }
        
        var status: UInt8 = 0
        data?.getBytes(&status, range: NSMakeRange(1, 1))
        
        var ID: UInt32 = 0
        data?.getBytes(&ID, range: NSMakeRange(2, 4))
        
        identifier.pointee = UInt(ID.bigEndian)
        
        try throwStatusError(status: Int(status))
        
    }
    
    private func throwStatusError(status: Int) throws {
        switch status {
        case 1:
            throw NWErrorUtil.errorWithErrorCode(.apnProcessing, reason: status)
        case 2:
            throw NWErrorUtil.errorWithErrorCode(.apnMissingDeviceToken, reason: status)
        case 3:
            throw NWErrorUtil.errorWithErrorCode(.apnMissingTopic, reason: status)
        case 4:
            throw NWErrorUtil.errorWithErrorCode(.apnMissingPayload, reason: status)
        case 5:
            throw NWErrorUtil.errorWithErrorCode(.apnInvalidTokenSize, reason: status)
        case 6:
            throw NWErrorUtil.errorWithErrorCode(.apnInvalidTopicSize, reason: status)
        case 7:
            throw NWErrorUtil.errorWithErrorCode(.apnInvalidPayloadSize, reason: status)
        case 8:
            throw NWErrorUtil.errorWithErrorCode(.apnInvalidTokenContent, reason: status)
        case 10:
            throw NWErrorUtil.errorWithErrorCode(.apnShutdown, reason: status)
        default:
            throw NWErrorUtil.errorWithErrorCode(.apnUnknownErrorCode, reason: status)
        }
    }
}
