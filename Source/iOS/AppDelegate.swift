import UIKit

public var controller: PusherViewController? = nil
public let deviceToken = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
public let pkcs12FileName = "PushTool.p12"
public let pkcs12Password = "pa$$word"

public class AppDelegate : UIResponder, UIApplicationDelegate {
    
    public var window: UIWindow!
    
    public  func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplicationLaunchOptionsKey : Any]? = nil) -> Bool {
        window = UIWindow(frame: UIScreen.main.bounds)
        let controller = PusherViewController()
        
        window.rootViewController = controller
        window.backgroundColor = UIColor.white
        window.makeKeyAndVisible()
        return true
    }
}
