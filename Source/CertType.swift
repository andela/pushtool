public enum CertType: Int {
    case none
    case iosDevelopment
    case iosProduction
    case macDevelopment
    case macProduction
    case simplified
    case webProduction
    case voIPServices
    case watchKitServices
    case passes
    case unknown
}

extension CertType {
    var description: String {
        switch self {
        case .none:
            return "none"

        case .iosDevelopment,
             .iosProduction:
            return "iOS"

        case .macDevelopment,
             .macProduction:
            return "macOS"

        case .simplified:
            return "All"

        case .webProduction:
            return "Website"

        case .voIPServices:
            return "VoIP"

        case .watchKitServices:
            return "WatchKit"

        case .passes:
            return "Pass"

        case .unknown:
            return "unknown"
        }
    }
}
