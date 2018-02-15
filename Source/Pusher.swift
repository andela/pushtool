
import Foundation

public class NWPusher : NSObject {
    
    private let sandboxPushHost = "gateway.sandbox.push.apple.com"
    private let pushHost = "gateway.push.apple.com"
    private let pushPort: UInt = 2195
    
    public var connection: NWSSLConnection?

    public init?(withIdentity identity: Any, environment: NWEnvironment, error: NSErrorPointer) {
        
        var host = ""
        var selectedEnvironment = environment
        
        if let SSLConnection = connection {
            SSLConnection.disconnect()
        }
        
        if (selectedEnvironment == NWEnvironment.auto) {
            selectedEnvironment = NWSecTools.environment(forIdentity: identity)
        }
        
        if (selectedEnvironment == NWEnvironment.sandbox) {
            host = sandboxPushHost
        } else {
            host = pushHost
        }
        
        connection = NWSSLConnection.init(host: host, port: pushPort, identity: identity)

        guard let SSLConnection = connection  else {
            return
        }
//        do {
//            let connected: Bool = try SSLConnection.connect()
//            if (!connected) {
//                return connected
//            }
//        }  catch {
//            return
//        }
    
    }
    
    public init?(withPKCS12Data data: Data, password: String, environment: NWEnvironment, error: NSErrorPointer) {
        do {
            let identity = try NWSecTools.identities(withPKCS12Data: data, password: password)
//            return self.connect(withIdentity: identity, environment: environment)
        } catch {
            
        }
        
       
    }
    
    public func connect(withIdentity identity: Any, environment: NWEnvironment) throws {
        
    }
    
    public func connect(withPKCS12Data data: Data, password: String, environment: NWEnvironment) throws {
        
    }
    
    public func reconnect() throws {
        
    }
    
    public func disconnect() {
        
    }
    
    public func pushPayload(_ payload: String, token: String, identifier: UInt) throws {
        
    }

    public func push(_ notification: NWNotification, type: NWNotificationType) throws {
        
    }
    
    public func readFailedIdentifier(_ identifier: UnsafeMutablePointer<UInt>, apnError: NSErrorPointer) throws {
        
    }
    
    public func readFailedIdentifierErrorPairs(withMax max: UInt, error: NSErrorPointer) -> [Any] {
        return [1]
    }
}
