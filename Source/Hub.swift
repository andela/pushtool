import Foundation

public protocol HubDelegate: class {
    func notification(_ notification: Notification?,
                      didFailWithError error: Error)
}

public class Hub {

    // MARK: Public Class Methods

    public class func connect(with delegate: HubDelegate?,
                              identity: IdentityRef,
                              environment: Environment) throws -> Hub {
                let hub = Hub(delegate: delegate)

        try hub.connect(withIdentity: identity,
                        environment: environment)

        return hub
    }

    public class func connect(with delegate: HubDelegate?,
                              pkcs12Data data: Data,
                              password: String,
                              environment: Environment) throws -> Hub {
                let hub = Hub(delegate: delegate)

        try hub.connect(withPKCS12Data: data,
                        password: password,
                        environment: environment)

        return hub
    }

    // MARK: Public Instance Properties

    public weak var delegate: HubDelegate?
    public var feedbackSpan: TimeInterval
    public var index: UInt
    public var pusher: Pusher

    // MARK: Public Initializers

    public convenience init(delegate: HubDelegate?) {
        self.init(pusher: Pusher(),
                  delegate: delegate)
    }

    public init(pusher: Pusher,
                delegate: HubDelegate?) {
        self.index = 1
        self.feedbackSpan = 30
        self.pusher = pusher
        self.delegate = delegate
    }

    // MARK: Public Instance Methods

    public func connect(withIdentity identity: IdentityRef,
                        environment: Environment) throws {
        try pusher.connect(withIdentity: identity,
                           environment: environment)
    }

    public func connect(withPKCS12Data data: Data,
                        password: String,
                        environment: Environment) throws {
        try pusher.connect(withPKCS12Data: data,
                           password: password,
                           environment: environment)
    }

    public func disconnect() {
        pusher.disconnect()
    }

    public func pushNotification(_ notification: Notification,
                                 autoReconnect reconnect: Bool) throws {
        if notification.identifier == 0 {
            notification.identifier = index

            index += 1
        }

        do {
            try pusher.pushNotification(notification)
        } catch {
            delegate?.notification(notification,
                                   didFailWithError: error)

            if reconnect {
                try self.reconnect()
            }

            throw error
        }

        notificationForIdentifier[notification.identifier] = (notification, Date())
    }

    public func pushNotifications(_ notifications: [Notification]) -> UInt {
        var fails: UInt = 0

        for notification in notifications {
            do {
                try pushNotification(notification,
                                     autoReconnect: true)
            } catch {
                fails += 1
            }
        }

        return fails
    }

    public func pushPayload(_ payload: String,
                            token: String) -> UInt {
        let notification = Notification(payload: payload,
                                        token: token,
                                        identifier: 0,
                                        expiration: nil,
                                        priority: 0)

        return self.pushNotifications([notification])
    }

    public func pushPayload(_ payload: String,
                            tokens: [String]) -> UInt {
        let notifications = tokens.map { Notification(payload: payload,
                                                      token: $0,
                                                      identifier: 0,
                                                      expiration: nil,
                                                      priority: 0)
        }

        return self.pushNotifications(notifications)
    }

    public func pushPayloads(_ payloads: [String],
                             token: String) -> UInt {
        let notifications = payloads.map { Notification(payload: $0,
                                                        token: token,
                                                        identifier: 0,
                                                        expiration: nil,
                                                        priority: 0)
        }

        return pushNotifications(notifications)
    }

    public func readFailed() -> UInt {
        var failed: [Any]?

        do {
            try readFailed(&failed,
                           max: 1_000,
                           autoReconnect: true)
        } catch {
            return 0
        }

        guard let count = failed?.count
            else { return 0 }

        return UInt(count)
    }

    public func readFailed(_ notifications: AutoreleasingUnsafeMutablePointer<Notification?>?,
                           autoReconnect reconnect: Bool) throws {
        let identifier: UInt = 0
        var apnError: NSError?
        var id = Int(identifier)

        try pusher.readFailedIdentifier(&id, apnError: &apnError)

        if let apnError = apnError {
            let notification: Notification? = notificationForIdentifier[identifier]?.0

            delegate?.notification(notification, didFailWithError: apnError)

            if reconnect {
                try self.reconnect()
            }
        }
    }

    public func readFailed(_ notifications: inout [Any]?,
                           max: Int,
                           autoReconnect reconnect: Bool) throws {
        var failed: [Any] = []

        for _ in 0..<max {
            var notification: Notification?
            try readFailed(&notification, autoReconnect: reconnect)

            guard
                let aNotification = notification
                else { break }
            failed.append(aNotification)
        }

        if let nonNilNotifications = notifications, !nonNilNotifications.isEmpty {
            notifications = failed
        }

        _ = trimIdentifiers()
    }

    public func reconnect() throws {
        try pusher.reconnect()
    }

    public func trimIdentifiers() -> Bool {
        let oldBefore = Date(timeIntervalSinceNow: -feedbackSpan)

        let filteredIdentifiers = notificationForIdentifier.filter { element in
            let (_, date) = element.1
            return oldBefore.compare(date) == .orderedDescending
        }

        let old = filteredIdentifiers.values
        for (key, _) in filteredIdentifiers {
            notificationForIdentifier.removeValue(forKey: key)
        }

        return !old.isEmpty
    }

    // MARK: Private Instance Properties

    private var notificationForIdentifier: [UInt: (Notification, Date)] = [:]
}
