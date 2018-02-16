
import Foundation

public class NWPusher : NSObject {
    
    private let sandboxPushHost = "gateway.sandbox.push.apple.com"
    private let pushHost = "gateway.push.apple.com"
    private let pushPort: UInt = 2195
    
    public var connection: NWSSLConnection?

    public init?(withIdentity identity: NWIdentityRef, environment: NWEnvironment) {
        super.init()
        do {
            try self.connect(withIdentity: identity, environment: environment)
        } catch {
            return nil
        }
    }
    
    public init?(withPKCS12Data data: Data, password: String, environment: NWEnvironment) {
       super.init()
        do {
            try self.connect(withPKCS12Data: data, password: password, environment: environment)
        } catch {
            return nil
        }
    }
    public func connect(withIdentity identity: NWIdentityRef, environment: NWEnvironment) throws -> Bool {
        
        var selectedEnvironment = environment

        if let connection =  self.connection {
            connection.disconnect()
        }
        self.connection = nil
        if environment == NWEnvironment.auto {
            selectedEnvironment = NWSecTools.environment(forIdentity: identity)
        }
        let host = ((environment == NWEnvironment.sandbox) ? sandboxPushHost : pushHost)
        let connection = NWSSLConnection(host: host, port: pushPort, identity: identity)
        
        guard let SSLConnection = connection
            else { return false }
        
        let connected: Bool = (try? SSLConnection.connect()) != nil
        if !connected {
            return connected
        }
        self.connection = connection
        return true
    }

    
    public func connect(withPKCS12Data data: Data, password: String, environment: NWEnvironment) throws -> Bool {
        do {
            let identity: NWIdentityRef = try NWSecTools.identities(withPKCS12Data: data, password: password) as NWIdentityRef
            let result: Bool = (try? self.connect(withIdentity: identity, environment: environment)) != nil
            return result
        } catch {
            return false
        }
    }
    
    public func reconnect() throws -> Bool {
        guard let SSLConnection = self.connection else {
            return false
        }
        let result: Bool = (try? SSLConnection.connect()) != nil
        return result
    }
    
    public func disconnect() {
        guard let SSLConnection = self.connection
            else { return }
        SSLConnection.disconnect()
        self.connection = nil
    }
    
    public func pushPayload(_ payload: String, token: String, identifier: UInt) throws {
        let notification = NWNotification(payload: payload,
                                          token: token,
                                          identifier: identifier,
                                          expiration: nil,
                                          priority: 0)
//        return self.push(notification, type: NWNotificationType.type2)
    }

    public func push(_ notification: NWNotification, type: NWNotificationType) throws {
        var length: UInt = 0
        let data = notification.data(with: NWNotificationType.type2)
        guard let SSLConnection = self.connection
            else { return  }
        do {
            try SSLConnection.write(data, length: &length)
            if length != data.count {
                return try NWErrorUtil.noWithErrorCode(NWError.pushWriteFail, reason: Int(length))
            }
        } catch let error as NSError {
            throw error
        }
        
    }
    
    public func readFailedIdentifier(_ identifier: UnsafeMutablePointer<UInt>, apnError: NSErrorPointer) throws {
        
    }
    
    public func readFailedIdentifierErrorPairs(withMax max: UInt, error: NSErrorPointer) -> [Any] {
        return [1]
    }
}
