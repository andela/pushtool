public let NWErrorReasonCodeKey: String

public func descriptionForEnvironentOptions(_ environmentOptions: NWEnvironmentOptions) -> String
public func descriptionForEnvironent(_ environment: NWEnvironment) -> String!
public func descriptionForCertType(_ type: NWCertType) -> String!

public class NWErrorUtil : NSObject {

    public class func noWithErrorCode(_ code: NWError)
    public class func noWithErrorCode(_ code: NWError, reason: Int) throws
    public class func nilWithErrorCode(_ code: NWError) throws -> Any
    
    public class func nilWithErrorCode(_ code: NWError, reason: Int) throws -> Any
}

