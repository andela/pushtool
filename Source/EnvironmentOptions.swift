public enum EnvironmentOptions: Int {
    case none
    case sandbox
    case production
    case any
}

extension EnvironmentOptions {
    var description: String {
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
