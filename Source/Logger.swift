import Foundation

public protocol LoggerDelegate {
    func log(message: String,
             warning: Bool)
}

public class Logger {

    // MARK: Public Type Properties

    public static var delegate: LoggerDelegate?

    // MARK: Public Type Methods

    public static func logInfo(_ message: String) {
        delegate?.log(message: message,
                      warning: false)
    }

    public static func logWarn(_ message: String) {
        delegate?.log(message: message,
                      warning: true)
    }
}
