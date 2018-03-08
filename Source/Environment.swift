public enum Environment: Int {
    case none
    case sandbox
    case production
    case auto
}

extension Environment {
    var description: String {
        switch self {
        case .none:
            return "none"

        case .production:
            return "production"

        case .sandbox:
            return "sandbox"

        case .auto:
            return "auto"
        }
    }
}
