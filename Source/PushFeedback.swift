
import Foundation

/** Reads tokens and dates from the APNs feedback service.

 The feedback service is a separate server that provides a list of all device tokens that it tried to deliver a notification to, but was unable to. This usually indicates that this device no longer has the app installed. This way, the feedback service provides reliable way of finding out who uninstalled the app, which can be fed back into your database.

 Apple recommends reading from the service once a day. After a device token has been read, it will not be returned again until the next failed delivery. In practice: connect once a day, read all device tokens, and update your own database accordingly.

 Read more in Apple's documentation under *The Feedback Service*.
 */
public class PushFeedback : NSObject {

    public var connection: NWSSLConnection?
    public let pushHost = "feedback.push.apple.com"
    public let pushPort = 2196
    public let sandboxPushHost = "feedback.sandbox.push.apple.com"
    public let tokenMaxSize = 32


    /** @name Initialization */

    /** Setup connection with feedback service based on identity. */
//    public class func connect(withIdentity identity: NWIdentityRef, environment: NWEnvironment) throws -> Self {
//        let feedback = PushFeedback()
//
//
//    }


    /** Setup connection with feedback service based on PKCS #12 data. */
//    public class func connect(withPKCS12Data data: Data!, password: String!, environment: NWEnvironment) throws -> Self {
//
//    }


    /** @name Connecting */

    /** Connect with feedback service based on identity. */
    public func connect(withIdentity
                           identity: Any?,
                        environment: NWEnvironment) throws {

        guard let connection = connection
            else {return }
        connection.disconnect()
        let environment = NWEnvironment.auto
        if environment == (NWSecTools.environment(forIdentity: identity)) {
            let host = ((environment == NWEnvironment.sandbox) ? sandboxPushHost : pushHost) as String
            self.connection = NWSSLConnection(host: host, port: UInt(pushPort), identity: identity)

        }




    }


    /** Connect with feedback service based on PKCS #12 data. */
    public func connect(withPKCS12Data
                            data: Data?,
                        password: String?,
                        environment: NWEnvironment) throws {

        do {
            let identity = try NWSecTools.identity(withPKCS12Data: data, password: password) as NWIdentityRef
            if (identity.boolValue) {

                do {
                    try connect(withIdentity: identity, environment: environment)
                } catch let error {
                    print("Error \(error)")
                }

            }
        } catch let error {
            print("Error \(error)")
        }
    }


    /** Disconnect from feedback service. The server will automatically drop the connection after all feedback data has been read. */
    public func disconnect() {
        connection = NWSSLConnection()
        connection?.disconnect()
    }


    /** @name Reading */

    /** Read a single token-date pair, where token is data. */
    public func readTokenData(_ token: Data, date: Date) throws {

//        var data = Data(length: MemoryLayout<UInt32>.size + MemoryLayout<UInt16>.size + tokenMaxSize)



    }


    /** Read a single token-date pair, where token is hex string. */
    public func readToken(_ token: Data, date: Date) throws {

    }


    /** Read all (or max) token-date pairs, where token is hex string. */
    public func readTokenDatePairs(withMax max: UInt) throws -> [Any] {
        return []
    }
}

