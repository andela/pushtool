import AppKit
import Foundation

public class AppDelegate : NSObject, NSApplicationDelegate {
    
    @IBOutlet var window: NSWindow!
    @IBOutlet var certificatePopup: NSPopUpButton!
    @IBOutlet var tokenCombo: NSComboBox!
    @IBOutlet var payloadField: NSTextView!
    @IBOutlet var logField: NSTextView!
    @IBOutlet var countField: NSTextField!
    @IBOutlet var infoField: NSTextField!
    @IBOutlet var pushButton: NSButton!
    @IBOutlet var reconnectButton: NSButton!
    @IBOutlet var expiryPopup: NSPopUpButton!
    @IBOutlet var priorityPopup: NSPopUpButton!
    @IBOutlet var logScroll: NSScrollView!
    @IBOutlet var sanboxCheckBox: NSButton!
    
    // MARK: Private Instance Properties
    
    private var certificateIdentityPairs: [[Any]] = []
    private var config: [AnyHashable: [AnyHashable: Any]] = [:]
    private var hub: Hub?
    private var lastSelectedIndex: Int = 0
    private var selectedCertificate: NWCertificateRef?
    private var serial: DispatchQueue?
    
    
    // MARK: Public Instance methods
    
    public func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }
    
    // MARK: Private Instance methods
    
    private func applicationDidFinishLaunching(_ notification: Notification) {
        //NWLogInfo(@"Application did finish launching");
        serial = DispatchQueue(label: "NWAppDelegate")
        
        certificateIdentityPairs = []
        loadCertificatesFromKeychain()
        //migrateOldConfigurationIfNeeded()
        loadConfig()
        updateCertificatePopup()
        
        guard let payload = config["payload"] as? String
            else { return }
        
        payloadField.string = payload.count > 0 ? payload : ""
        payloadField.font = NSFont(name: "Monaco", size: 10)
        payloadField.enabledTextCheckingTypes = NSTextCheckingTypes(0)
        logField.enabledTextCheckingTypes = NSTextCheckingTypes(0)
        updatePayloadCounter()
    }
    
    private func applicationWillTerminate(_ notification: Notification) {
        saveConfig()
        hub?.disconnect()
        hub?.delegate = nil
        hub = nil
        //NWLogInfo(@"Application will terminate");
    }
    
    @IBAction func certificateSelected(_ sender: NSPopUpButton) {
        connectWithCertificate(at: certificatePopup.indexOfSelectedItem)
    }
    
    @IBAction func tokenSelected(_ sender: NSComboBox) {
        selectTokenAndUpdateCombo()
    }
    
    private func textDidChange(_ notification: Foundation.Notification) {
        if let textField = notification.object as? NSTextField,
            textField == payloadField {
            updatePayloadCounter()
        }
    }
    
    private func controlTextDidChange(_ obj: Notification) {
        //    if (notification.object == _tokenCombo) [self something];
    }
    
    @IBAction func push(_ sender: NSButton) {
        addTokenAndUpdateCombo()
        push()
        upPayloadTextIndex()
    }
    
    @IBAction func reconnect(_ sender: NSButton) {
        reconnect()
    }
    
    @IBAction func sanboxCheckBoxDidPressed(_ sender: NSButton) {
        if (selectedCertificate != nil) {
            reconnect()
        }
    }
    
    private func notification(_ notification: NWNotification) throws {
        DispatchQueue.main.async(execute: {() -> Void in
            //NSLog(@"failed notification: %@ %@ %lu %lu %lu", notification.payload, notification.token, notification.identifier, notification.expires, notification.priority);
            //NWLogWarn(@"Notification error: %@", error.localizedDescription);
        })
    }
    
    @IBAction func selectOutput(_ sender: NSSegmentedControl) {
        logScroll.isHidden = sender.selectedSegment != 1
    }
    
    @IBAction func readFeedback(_ sender: Any) {
        feedback()
    }
    
    private func loadCertificatesFromKeychain() {
        var certs: [Any] = []
        do {
            certs = try NWSecTools.keychainCertificates()
        } catch {
            print(error)
        }
        
        
        if certs.isEmpty {
            //NWLogWarn(@"Unable to access keychain: %@", error.localizedDescription);
        }
        if certs.count == 0 {
            //NWLogWarn(@"No push certificates in keychain.");
        }
        
        certs = certs.sorted(by: {(_ a: CertificateRef, _ b: CertificateRef) -> Bool in
            let envOptionsA: NWEnvironmentOptions = NWSecTools.environmentOptions(forCertificate: a)
            let envOptionsB: NWEnvironmentOptions = NWSecTools.environmentOptions(forCertificate: b)
            if envOptionsA != envOptionsB {
                return envOptionsA.rawValue < envOptionsB.rawValue
            }
            let aname: String = NWSecTools.summary(withCertificate: a)
            let bname: String = NWSecTools.summary(withCertificate: b)
            return aname < bname
        })
        
        var pairs: [[Any]] = []
        for c: CertificateRef in certs {
            pairs.append([c, NSNull()])
        }
        certificateIdentityPairs = certificateIdentityPairs + pairs
    }
    
    private func updateCertificatePopup() {
        var suffix = " "
        certificatePopup.removeAllItems()
        certificatePopup.addItem(withTitle: "Select Push Certificate")
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .short
        
        for pair: [Any] in certificateIdentityPairs {
            let certificate = pair[0] as CertificateRef
            let hasIdentity: Bool = !(pair[1] is NSNull)
            let environmentOptions: NWEnvironmentOptions = NWSecTools.environmentOptions(forCertificate: certificate)
            var summary: NSString? = nil
            let certType: NWCertType = NWSecTools.type(withCertificate: certificate, summary: &summary)
            let type: String = ErrorUtil.descriptionForCertType(certType)
            let date: Date? = NWSecTools.expiration(withCertificate: certificate)
            let expire = "  [\((date != nil) ? formatter.string(from: date!) : "expired")]"
            // summary = @"com.example.app";
            certificatePopup.addItem(withTitle: "\(hasIdentity ? "imported: " : "")\(String(describing: summary)) (\(type) \(ErrorUtil.descriptionForEnvironmentOptions(environmentOptions)))\(expire)\(suffix)")
            suffix += " "
        }
        certificatePopup.addItem(withTitle: "Import PKCS #12 file (.p12)...")
    }
    
    private func importIdentity() {
        var panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = true
        panel.allowedFileTypes = ["p12"]
        panel.begin(completionHandler: { (_ result: NSApplication.ModalResponse) -> Void in
            if result.rawValue != NSFileHandlingPanelOKButton {
                return
            }
            var pairs: [[Any]] = []
            
            for url: URL in panel.urls {
                var text = "Enter password for \(url.lastPathComponent)"
                var alert = NSAlert(messageText: text, defaultButton: "OK", alternateButton: "Cancel", otherButton: nil, informativeTextWithFormat: "")
                var input = NSSecureTextField(frame: NSMakeRect(0, 0, 200, 24))
                alert.accessoryView = input
                var button: NSApplication.ModalResponse = alert.runModal()
                if button.rawValue != NSAlertDefaultReturn {
                    return
                }
                let type: NWError?
                var password = "\(input)" as NSString
                var data = Data(contentsOf: url)
                var ids: Any?
                do {
                    ids = try NWSecTools.identities(withPKCS12Data: data, password: password as String!)
                } catch let error as NSError {
                    if !(password.length == 0) && error.code == kNWErrorPKCS12Password {
                        ids = try? NWSecTools.identities(withPKCS12Data: data, password: nil)
                    }
                }
                if !(ids != nil) {
                    //NWLogWarn(@"Unable to read p12 file: %@", error.localizedDescription);
                    return
                }
                for identity: IdentityRef in ids {
                    var error: Error? = nil
                    var certificate: NWCertificateRef = try NWSecTools.certificate(withIdentity: identity) as NWCertificateRef
                    if certificate == nil {
                        //NWLogWarn(@"Unable to import p12 file: %@", error.localizedDescription);
                        return
                    }
                    pairs.append([certificate, identity])
                }
            }
            if pairs.count == 0 {
                //NWLogWarn(@"Unable to import p12 file: no push certificates found");
                return
            }
            //NWLogInfo(@"Imported %i certificate%@", (int)pairs.count, pairs.count == 1 ? @"" : @"s");
            var index: Int = self.certificateIdentityPairs.count
            self.certificateIdentityPairs = self.certificateIdentityPairs + pairs
            self.updateCertificatePopup()
            self.connectWithCertificate(at: index + 1)
            } as! (NSApplication.ModalResponse) -> Void)
    }
    
    private func selectedExpiry() -> Date {
        switch expiryPopup.indexOfSelectedItem {
        case 1:
            return Date(timeIntervalSince1970: 0)
            
        case 2:
            return Date(timeIntervalSinceNow: 60)
            
        case 3:
            return Date(timeIntervalSince1970: 300)
            
        case 4:
            return Date(timeIntervalSinceNow: 3600)
            
        case 5:
            return Date(timeIntervalSinceNow: 86400)
            
        case 6:
            return Date(timeIntervalSince1970: 1)
            
        case 7:
            return Date(timeIntervalSince1970: TimeInterval(UINT32_MAX))
            
        default:
            return Date()
            
        }
    }
    
    private func selectedPriority() -> Int {
        switch priorityPopup.indexOfSelectedItem {
        case 1:
            return 5
            
        case 2:
            return 10
            
        default:
            return 0
        }
    }
    
    private func updatePayloadCounter() {
        let payload: String = payloadField.string
        var isJSON = (try? JSONSerialization.jsonObject(with: payload.data(using: .utf8) ?? Data(), options: [])) ?? false
        //        countField = "\(isJSON ? "" : "malformed")  \(payload.count)"
        //        countField.textColor = payload.count > 256 || !isJSON as! (Bool) ? NSColor.red; : NSColor.darkGray
    }
    
    private func upPayloadTextIndex() {
        let payload: String = payloadField.string
        var range: NSRange = (payload as NSString).range(of: "\\([0-9]+\\)", options: .regularExpression)
        if range.location != NSNotFound {
            range.location += 1
            range.length -= 2
            
            let before: String = (payload as NSString).substring(to: range.location)
            let value = Int((payload as NSString).substring(with: range)) ?? 0 + 1
            let after: String = (payload as NSString).substring(from: range.location + range.length)
            payloadField.string = "\(before)\(value)\(after)"
        }
    }
    
    private func selectedEnvironment(for certificate: NWCertificateRef) -> NWEnvironment {
        // MARK: Help needed.
        return (.on ? .sandbox: .production) as? NWEnvironment
        
    }
    
    private func preferredEnvironment(for certificate: NWCertificateRef) -> NWEnvironment {
        let environmentOptions: NWEnvironmentOptions = NWSecTools.environmentOptions(forCertificate: certificate)
        return ((environmentOptions & NWEnvironmentOptionSandbox) ? NWEnvironmentSandbox : NWEnvironmentProduction) as? NWEnvironment
    }
    
    private func connectWithCertificate(at index: Int) {
        if index == 0 {
            certificatePopup.selectItem(at: 0)
            lastSelectedIndex = 0
            //MARK:  not sure...
            selectCertificate(.none, identity: NSNull(), environment: .sandbox)
            tokenCombo.isEnabled = false
            loadSelectedToken()
        }
        else if index <= certificateIdentityPairs.count {
            certificatePopup.selectItem(at: index)
            lastSelectedIndex = index
            let pair = certificateIdentityPairs[index - 1]
            let certificate = pair[0] as NWCertificateRef
            let identity = pair[1] as NWIdentityRef
            selectCertificate(certificate, identity: identity, environment: preferredEnvironment(for: certificate))
            tokenCombo.isEnabled = true
            loadSelectedToken()
        }
        else {
            certificatePopup.selectItem(at: lastSelectedIndex)
            importIdentity()
        }
    }
    
    private func disableButtons() {
        pushButton.isEnabled = false
        reconnectButton.isEnabled = false
        sanboxCheckBox.isEnabled = false
    }
    
    private func enableButtons(forCertificate certificate: NWCertificateRef, environment: NWEnvironment) {
        let environmentOptions: NWEnvironmentOptions = NWSecTools.environmentOptions(forCertificate: certificate)
        let shouldEnableEnvButton: Bool = environmentOptions == .any
        let shouldSelectSandboxEnv: Bool = environment == .sandbox
        pushButton.isEnabled = true
        reconnectButton.isEnabled = true
        sanboxCheckBox.isEnabled = shouldEnableEnvButton
        sanboxCheckBox.state = shouldSelectSandboxEnv ? .on : .off
    }
    
    private func selectCertificate(_ certificate: NWCertificateRef, identity: NWIdentityRef, environment: NWEnvironment) {
        self.hub?.disconnect()
        self.hub = nil
        disableButtons()
        //NWLogInfo(@"Disconnected from APN");
        
        selectedCertificate = certificate
        updateTokenCombo()
        
        if certificate.boolValue {
            //NSString *summary = [NWSecTools summaryWithCertificate:certificate];
            //NWLogInfo(@"Connecting to APN...  (%@ %@)", summary, descriptionForEnvironent(environment));
            
            serial?.async(execute: {() -> Void in
                let ident: NWIdentityRef = identity
                let hub = try? Hub.connect(with: self as? HubDelegate, identity: ident, environment: environment)
                DispatchQueue.main.async(execute: {() -> Void in
                    if (hub != nil) {
                        //NWLogInfo(@"Connected  (%@ %@)", summary, descriptionForEnvironent(environment));
                        self.hub = hub
                        self.enableButtons(forCertificate: certificate, environment: environment)
                    }
                    else {
                        //NWLogWarn(@"Unable to connect: %@", error.localizedDescription);
                        hub?.disconnect()
                        self.certificatePopup.selectItem(at: 0)
                    }
                })
                } as @convention(block) () -> Void)
        }
    }
    
    private func reconnect() {
        guard
            let cert = selectedCertificate
            else { return }
        //NSString *summary = [NWSecTools summaryWithCertificate:_selectedCertificate];
        let environment: NWEnvironment = selectedEnvironment(for: cert)
        //NWLogInfo(@"Reconnecting to APN...(%@ %@)", summary, descriptionForEnvironent(environment));
        selectCertificate(cert, identity: NSNull(), environment: environment)
    }
    
    private func push() {
        let payload: String = payloadField.string
        let token = "\(tokenCombo)"
        let expiry: Date? = selectedExpiry()
        let priority: Int = selectedPriority()
        //NWLogInfo(@"Pushing..");
        
        serial?.async(execute: {() -> Void in
            var notification = NWNotification(payload: payload, token: token, identifier: 0, expiration: expiry, priority: UInt(priority))
            var error: Error? = nil
            if var pushed: Bool = ((try self.hub?.pushNotification(notification, autoReconnect: true)) != nil)  {
                var popTime = DispatchTime.now() + Double(Int(1.0 * Double(NSEC_PER_SEC)))
                serial.asyncAfter(deadline: popTime as double_t / Double(NSEC_PER_SEC), execute: {(_: Void) -> Void in
                    var error: Error? = nil
                    var failed: NWNotification? = nil
                    var read: Bool = try? hub.readFailed(failed, autoReconnect: true)
                    if read {
                        //if (!failed) NWLogInfo(@"Payload has been pushed");
                    }
                    else {
                        //NWLogWarn(@"Unable to read: %@", error.localizedDescription);
                    }
                    hub.trimIdentifiers()
                })
            }
            else {
                //NWLogWarn(@"Unable to push: %@", error.localizedDescription);
            }
            } as! @convention(block) () -> Void)
    }
    
    private func feedback() {
        serial?.async(execute: {() -> Void in
            guard
                let certificate: NWCertificateRef = self.selectedCertificate
                else {
                    //NWLogWarn(@"Unable to connect to feedback service: no certificate selected");
                    return
            }
            
            //NWEnvironment environment = [self selectedEnvironmentForCertificate:certificate];
            //NSString *summary = [NWSecTools summaryWithCertificate:certificate];
            //NWLogInfo(@"Connecting to feedback service..  (%@ %@)", summary, descriptionForEnvironent(environment));
            
            let identity: NWIdentityRef = try NWSecTools.keychainIdentity(withCertificate: certificate) as NWIdentityRef
            guard
                let feedback = try? PushFeedback.connect(withIdentity: identity, environment: self.selectedEnvironment(for: certificate))
                else {
                    //NWLogWarn(@"Unable to connect to feedback service: %@", error.localizedDescription);
                    return
            }
            //NWLogInfo(@"Reading feedback service..  (%@ %@)", summary, descriptionForEnvironent(environment));
            
            let pairs = try feedback.readTokenDatePairs(withMax: 1000)
            if pairs.isEmpty {
                //NWLogWarn(@"Unable to read feedback: %@", error.localizedDescription);
                return
            }
            //for (NSArray *pair in pairs) {
            //NWLogInfo(@"token: %@  date: %@", pair[0], pair[1]);
            //}
            if pairs.count != 0 {
                //NWLogInfo(@"Feedback service returned %i device tokens, see logs for details", (int)pairs.count);
            }
            else {
                //NWLogInfo(@"Feedback service returned zero device tokens");
            }
            
            } as! @convention(block) () -> Void)
    }
    
    private func identifier(withCertificate certificate: NWCertificateRef) -> String {
        let environmentOptions: NWEnvironmentOptions = NWSecTools.environmentOptions(forCertificate: certificate)
        let summary: String = NWSecTools.summary(withCertificate: certificate)
        return (summary ? "\(summary)-\(ErrorUtil.descriptionForEnvironmentOptions(environmentOptions))" : nil) ?? ""
    }
    
    private func tokens(withCertificate certificate: NWCertificateRef, create: Bool) -> [AnyHashable]? {
        guard let cert = selectedCertificate
            else { return nil }
        let environment: NWEnvironment = selectedEnvironment(for: cert)
        guard let summary: String = NWSecTools.summary(withCertificate: certificate) else { return nil }
        
        let identifier: String?
        if environment == .sandbox {
            identifier = "\(summary)-sandbox"
        } else {
            identifier="\(summary)"
        }
        
        var result: Any?
        guard
            var config = config["identifiers"],
            let id = identifier
            else { return nil }
        
        result = config[id]
        if create && (result != nil) {
            result = config[id]
        }
        if !(result is [AnyHashable]) {
            result = config[id] = result
        }
        return (result as? [AnyHashable]) ?? [AnyHashable]()
    }
    
    private func addToken(_ token: String, certificate: NWCertificateRef) -> Bool {
        guard var tokens = self.tokens(withCertificate: certificate, create: true)
            else { return false }
        if token.count > 0 {
            tokens.append(token)
            return true
        }
        return false
    }
    
    private func selectToken(_ token: String, certificate: NWCertificateRef) -> Bool {
        guard
            var tokens = self.tokens(withCertificate: certificate, create: true)
            else { return false }
        
        while let elementIndex = tokens.index(of: token) { tokens.remove(at: elementIndex) }
        tokens.append(token)
        return true
    }
    
    private func removeToken(_ token: String, certificate: NWCertificateRef) -> Bool {
        guard
            var tokens = self.tokens(withCertificate: certificate, create: false)
            else { return false }
        while let elementIndex = tokens.index(of: token) { tokens.remove(at: elementIndex) }
        return true
        
    }
    
    private func updateTokenCombo() {
        tokenCombo.removeAllItems()
        
        guard
            let cert = selectedCertificate
            else { return }
        
        guard
            let tokens = self.tokens(withCertificate: cert, create: false),
            let tokenValue = (tokens as? NSArray)?.reverseObjectEnumerator().allObjects
            else { return }
        
        if tokens.count != 0 {
            tokenCombo.addItems(withObjectValues: tokenValue)
        }
    }
    
    private func loadSelectedToken() {
        guard
            let cert = selectedCertificate,
            let token = tokens(withCertificate: cert, create: true)
            else { return }
        
        tokenCombo.stringValue = token.last as? String ?? ""
        // _tokenCombo.stringValue = @"552fff0a65b154eb209e9dc91201025da1a4a413dd2ad6d3b51e9b33b90c977a my iphone";
    }
    
    private func addTokenAndUpdateCombo() {
        guard let cert = selectedCertificate
            else { return }
        let added: Bool = addToken("\(tokenCombo)", certificate: cert)
        if added {
            updateTokenCombo()
        }
    }
    
    private func selectTokenAndUpdateCombo() {
        guard let selectedCertificate = selectedCertificate
            else { return }
        let selected: Bool = selectToken("\(tokenCombo)", certificate: selectedCertificate)
        if selected {
            updateTokenCombo()
        }
    }
    
    private func configFileURL() -> URL? {
        let libraryURL: URL? = FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask).last
        let configURL: URL? = libraryURL?.appendingPathComponent("PushTool", isDirectory: true)
        
        
        // MARK: help needed
        let exists: Bool? = true //try? FileManager.default.createDirectory(at: configURL!, withIntermediateDirectories: true, attributes: nil)
        //NWLogWarnIfError(error);
        if let _ = exists {
            let result: URL? = configURL?.appendingPathComponent("config.plist")
            if let aPath = result?.path {
                if !FileManager.default.fileExists(atPath: aPath) {
                    let defaultURL: URL? = Bundle.main.url(forResource: "config", withExtension: "plist")
                    if let aURL = defaultURL, let aResult = result {
                        try? FileManager.default.copyItem(at: aURL, to: aResult)
                    }
                    //NWLogWarnIfError(error);
                }
            }
            return result!
        }
        return nil
        
    }
    
    private func loadConfig() {
        let url = configFileURL()
        config = [AnyHashable: Any](contentsOf: url)
        //NWLogInfo(@"Loaded config from %@", url.path);
    }
    
    private func saveConfig() {
        guard let url = configFileURL()
            else { return }
        if config.count > 0 {
            (config as NSDictionary).write(to: url, atomically: false)
        }
    }
    
    //    private func migrateOldConfigurationIfNeeded() {
    //        let libraryURL: URL? = FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask).last
    //        let configURL: URL? = libraryURL?.appendingPathComponent("PushTool", isDirectory: true)
    //        let newURL: URL? = configURL?.appendingPathComponent("config.plist")
    //        let oldURL: URL? = configURL?.appendingPathComponent("configuration.plist")
    //        if let aPath = newURL?.path {
    //            if FileManager.default.fileExists(atPath: aPath) {
    //                return
    //            }
    //        }
    //        if let aPath = oldURL?.path {
    //            if !FileManager.default.fileExists(atPath: aPath) {
    //                return
    //            }
    //        }
    //        var old = [AnyHashable: Any](contentsOf: oldURL)
    //        var identifiers = [:]
    //        for d: [AnyHashable: Any] in old["tokens"] {
    //            for identifier: String in d["identifiers"] {
    //                for token: [Any] in d["development"] {
    //                    var key = "\(identifier)-sandbox"
    //                    if !identifiers[key] {
    //                        identifiers[key] = [].mutableCopy
    //                    }
    //                    identifiers[key].append(token)
    //                }
    //                for token: [Any] in d["production"] {
    //                    var key: String = identifier
    //                    if !identifiers[key] {
    //                        identifiers[key] = [].mutableCopy
    //                    }
    //                    identifiers[key].append(token)
    //                }
    //            }
    //        }
    //        var new:[String: Any] = [:]
    //        new["payload"] = old["payload"]
    //        new["identifiers"] = identifiers
    //        (new as NSDictionary).write(to: newURL, atomically: false)
    //        var error: Error? = nil
    //        try FileManager.default.removeItem(at: oldURL)
    //        //NWLogWarnIfError(error);
    //
    //        //NWLogWarnIfError(error);
    //    }
    
    //- (void)log:(NSString *)message warning:(BOOL)warning
    //{
    //    dispatch_async(dispatch_get_main_queue(), ^{
    //        _infoField.textColor = warning ? NSColor.redColor : NSColor.blackColor;
    //        _infoField.stringValue = message;
    //        if (message.length) {
    //            NSDictionary *attributes = @{NSForegroundColorAttributeName: _infoField.textColor, NSFontAttributeName: [NSFont fontWithName:@"Monaco" size:10]};
    //            NSAttributedString *string = [[NSAttributedString alloc] initWithString:message attributes:attributes];
    //            [_logField.textStorage appendAttributedString:string];
    //            [_logField.textStorage.mutableString appendString:@"\n"];
    //            [_logField scrollRangeToVisible:NSMakeRange(_logField.textStorage.length - 1, 1)];
    //        }
    //    });
    //}
    
    //static void NWPusherPrinter(NWLContext context, CFStringRef message, void *info) {
    //    BOOL warning = context.tag && strncmp(context.tag, "warn", 5) == 0;
    //    id delegate = NSApplication.sharedApplication.delegate;
    //    [delegate log:(__bridge NSString *)message warning:warning];
    //}
    
}

