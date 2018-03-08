public enum CertType {
    case iosDevelopment
    case iosProduction
    case macDevelopment
    case macProduction
    case none
    case passes
    case simplified
    case unknown
    case voIPServices
    case watchKitServices
    case webProduction

    public static var allTypes: [CertType] {
        return [.iosDevelopment,
                .iosProduction,
                .macDevelopment,
                .macProduction,
                .none,
                .passes,
                .simplified,
                .unknown,
                .voIPServices,
                .watchKitServices,
                .webProduction]
    }
}

extension CertType: CustomStringConvertible {
    public var description: String {
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
