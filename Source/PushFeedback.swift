import Foundation

@objcMembers
public class PushFeedback : NSObject {

    public var connection: NWSSLConnection?
    public let pushHost = "feedback.push.apple.com"
    public let pushPort = 2196
    public let sandboxPushHost = "feedback.sandbox.push.apple.com"
    public let tokenMaxSize = 32

    public class func connect(withIdentity identity: NWIdentityRef,
                              environment: NWEnvironment) throws -> PushFeedback {
        let feedback = PushFeedback()

        try feedback.connect(withIdentity: identity,
                             environment: environment)

        return feedback
    }

    public class func connect(withPKCS12Data data: Data,
                              password: String?,
                              environment: NWEnvironment) throws -> PushFeedback {
        let feedback = PushFeedback()

        try feedback.connect(withPKCS12Data: data,
                             password: password,
                             environment: environment)

        return feedback
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
                                            port: UInt(pushPort),
                                            identity: identity) {

            try connection.connect()
            self.connection = connection
        }
    }


    /** Connect with feedback service based on PKCS #12 data. */
    public func connect(withPKCS12Data data: Data,
                        password: String?,
                        environment: NWEnvironment) throws {

        guard let identity = try NWSecTools.identity(withPKCS12Data: data,
                                                     password: password) as NWIdentityRef?
            else { return }

        try connect(withIdentity: identity,
                    environment: environment)
    }

    public func disconnect() {
        connection = NWSSLConnection()
        connection?.disconnect()
    }

    public func readTokenData(_ token: Data, date: Date) throws {

//        var data = Data(length: MemoryLayout<UInt32>.size + MemoryLayout<UInt16>.size + tokenMaxSize)



    }

    public func readToken(_ token: Data, date: Date) throws {

    }

    public func readTokenDatePairs(withMax max: UInt) throws -> [Any] {
        return []
    }
}
