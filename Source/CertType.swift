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

    public var prefix: String? {
        switch self {
        case .iosDevelopment:
            return "Apple Development IOS Push Services: "

        case .iosProduction:
            return "Apple Production IOS Push Services: "

        case .macDevelopment:
            return "Apple Development Mac Push Services: "

        case .macProduction:
            return "Apple Production Mac Push Services: "

        case .simplified:
            return "Apple Push Services: "

        case .webProduction:
            return "Website Push ID: "

        case .voIPServices:
            return "VoIP Services: "

        case .watchKitServices:
            return "WatchKit Services: "

        case .passes:
            return "Pass Type ID: "

        default:
            return nil
        }
    }
}
