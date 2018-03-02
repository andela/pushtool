import UIKit

@UIApplicationMain
public class AppDelegate: UIResponder, UIApplicationDelegate {

    public var window: UIWindow?

    public  func application(_ application: UIApplication,
                             didFinishLaunchingWithOptions launchOptions: [UIApplicationLaunchOptionsKey: Any]? = nil) -> Bool {
        window = UIWindow(frame: UIScreen.main.bounds)

        window?.rootViewController = PusherViewController()
        window?.backgroundColor = .white
        window?.makeKeyAndVisible()

        return true
    }
}
