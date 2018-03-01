import Foundation

public protocol LoggerDelegate {
    func log(message: String,
             warning: Bool)
}

public class Logger {

    // MARK: Public Type Properties

    public static var delegate: LoggerDelegate? {
        didSet {
            if let delegate = delegate {
                buffer.forEach {
                    delegate.log(message: $0.0,
                                 warning: $0.1)
                }
                buffer = []
            }
        }
    }

    // MARK: Public Type Methods

    public static func logInfo(_ message: String) {
        print("[Info] \(message)")

        if let delegate = delegate {
            delegate.log(message: message,
                         warning: false)
        } else {
            buffer.append((message, false))
        }
    }

    public static func logWarn(_ message: String) {
        print("[Warn] \(message)")

        if let delegate = delegate {
            delegate.log(message: message,
                         warning: true)
        } else {
            buffer.append((message, true))
        }
    }

    private static var buffer: [(String, Bool)] = []
}
