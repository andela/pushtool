public enum EnvironmentOptions: Int {
    case none
    case sandbox
    case production
    case any
}

extension EnvironmentOptions: Comparable {
    public static func < (lhs: EnvironmentOptions,
                          rhs: EnvironmentOptions) -> Bool {
        return lhs.rawValue < rhs.rawValue
    }
}

extension EnvironmentOptions: CustomStringConvertible {
    public var description: String {
        switch self {
        case .sandbox:
            return "Sandbox"

        case .production:
            return "Production"

        case .any:
            return "Sandbox|Production"

        default:
            return "No environment"
        }
    }
}
