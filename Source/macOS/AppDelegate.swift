import Cocoa

public class AppDelegate : NSObject, NSApplicationDelegate {
    
    @IBOutlet var window: NSWindow!
    @IBOutlet var _certificatePopup: NSPopUpButton!
    @IBOutlet var _tokenCombo: NSComboBox!
    @IBOutlet var _payloadField: NSTextView!
    @IBOutlet var _logField: NSTextView!
    @IBOutlet var _countField: NSTextField!
    @IBOutlet var _infoField: NSTextField!
    @IBOutlet var _pushButton: NSButton!
    @IBOutlet var _reconnectButton: NSButton!
    @IBOutlet var _expiryPopup: NSPopUpButton!
    @IBOutlet var _priorityPopup: NSPopUpButton!
    @IBOutlet var _logScroll: NSScrollView!
    @IBOutlet var _sanboxCheckBox: NSButton!
    
    // MARK: Private Instance Properties

    private var certificateIdentityPairs: [Any] = []
    private var config: [AnyHashable: Any] = [:]
    private var hub: NWHub?
    private var lastSelectedIndex: Int = 0
    private var selectedCertificate: NWCertificateRef?
    private var serial: DispatchQueue?
    
    // MARK: Private Instance methods
    
    private func applicationDidFinishLaunching(_ notification: NSNotification) {
        serial = DispatchQueue(label: "NWAppDelegate")
        certificateIdentityPairs = []
        
        loadCertificatesFromKeychain()
        migrateOldConfigurationIfNeeded()
        loadConfig()
        updateCertificatePopup()
        
        let payload = config["payload"] as? String
        
        payloadField.string = payload?.count ? payload : ""
        payloadField.font = NSFont(name: "Monaco", size: 10)
        payloadField.enabledTextCheckingTypes = NSTextCheckingTypes(0)
        logField.enabledTextCheckingTypes = NSTextCheckingTypes(0)
        updatePayloadCounter()
    }
    
}
