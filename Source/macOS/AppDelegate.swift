import AppKit
import Foundation
import os

@NSApplicationMain
@objcMembers
public class AppDelegate : NSObject, NSApplicationDelegate {
    @IBOutlet var certificatePopup: NSPopUpButton!
    @IBOutlet var countField: NSTextField!
    @IBOutlet var expiryPopup: NSPopUpButton!
    @IBOutlet var infoField: NSTextField!
    @IBOutlet var logField: NSTextView!
    @IBOutlet var logScroll: NSScrollView!
    @IBOutlet var payloadField: NSTextView!
    @IBOutlet var priorityPopup: NSPopUpButton!
    @IBOutlet var pushButton: NSButton!
    @IBOutlet var tokenCombo: NSComboBox!
    @IBOutlet var reconnectButton: NSButton!
    @IBOutlet var sandboxCheckBox: NSButton!
    @IBOutlet var window: NSWindow!

    // MARK: Private Instance Properties

    private var certificateIdentityPairs: [[Any]] = []
    private var config: [AnyHashable: Any] = [:]
    private var hub: Hub?
    private var lastSelectedIndex: Int = 0
    private var selectedCertificate: NWCertificateRef?
    private var serial: DispatchQueue?


    // MARK: Public Instance methods

    public func applicationDidFinishLaunching(_ notification: Foundation.Notification) {
        Logger.delegate = self

        Logger.logInfo("Application did finish launching")

        serial = DispatchQueue(label: "AppDelegate")

        certificateIdentityPairs = []
        loadCertificatesFromKeychain()
        //migrateOldConfigurationIfNeeded()
        loadConfig()
        updateCertificatePopup()

        guard
            let payload = config["payload"] as? String
            else { return }

        payloadField.string = payload.count > 0 ? payload : ""
        payloadField.font = NSFont(name: "Monaco", size: 10)
        payloadField.enabledTextCheckingTypes = NSTextCheckingTypes(0)
        logField.enabledTextCheckingTypes = NSTextCheckingTypes(0)

        updatePayloadCounter()
    }

    public func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }

    public func applicationWillTerminate(_ notification: Foundation.Notification) {
        saveConfig()
        hub?.disconnect()
        hub?.delegate = nil
        hub = nil
        //NWLogInfo(@"Application will terminate");
    }

    @IBAction private func certificateSelected(_ sender: NSPopUpButton) {
        connectWithCertificate(at: certificatePopup.indexOfSelectedItem)
    }

    @IBAction private func readFeedback(_ sender: Any) {
        feedback()
    }

    @IBAction private func reconnect(_ sender: NSButton) {
        reconnect()
    }

    @IBAction private func sandboxCheckBoxDidPressed(_ sender: NSButton) {
        if (selectedCertificate != nil) {
            reconnect()
        }
    }

    @IBAction private func selectOutput(_ sender: NSSegmentedControl) {
        logScroll.isHidden = sender.selectedSegment != 1
    }

    @IBAction private func tokenSelected(_ sender: NSComboBox) {
        selectTokenAndUpdateCombo()
    }

    @IBAction private func push(_ sender: NSButton) {
        addTokenAndUpdateCombo()
        push()
        upPayloadTextIndex()
    }

    // MARK: Private Instance methods

    private func addToken(_ token: String, certificate: NWCertificateRef) -> Bool {
        guard
            var tokens = self.tokens(withCertificate: certificate,
                                     create: true)
            else { return false }

        if token.count > 0 {
            tokens.append(token)
            return true
        }

        return false
    }

    private func addTokenAndUpdateCombo() {
        guard
            let cert = selectedCertificate
            else { return }

        let added: Bool = addToken(tokenCombo.stringValue,
                                   certificate: cert)

        if added {
            updateTokenCombo()
        }
    }

    private func configFileURL() -> URL? {
        let libraryURL: URL? = FileManager.default.urls(for: .libraryDirectory,
                                                        in: .userDomainMask).last

        guard
            let configURL: URL = libraryURL?.appendingPathComponent("PushTool", isDirectory: true)
            else { return nil }

        let exists: Any?

        exists = try? FileManager.default.createDirectory(at: configURL,
                                                          withIntermediateDirectories: true,
                                                          attributes: nil)

        //NWLogWarnIfError(error);
        if let _ = exists {
            let result: URL? = configURL.appendingPathComponent("config.plist")
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

    private func controlTextDidChange(_ obj: Notification) {
        //    if (notification.object == _tokenCombo) [self something];
    }

    private func connectWithCertificate(at index: Int) {
        if index == 0 {
            certificatePopup.selectItem(at: 0)
            lastSelectedIndex = 0
            //MARK:  not sure...
            selectCertificate(nil,
                              identity: nil,
                              environment: NWEnvironment.sandbox)
            tokenCombo.isEnabled = false
            loadSelectedToken()
        }
        else if index <= certificateIdentityPairs.count {
            certificatePopup.selectItem(at: index)
            lastSelectedIndex = index
            let pair = certificateIdentityPairs[index - 1]
            let certificate = pair[0] as NWCertificateRef
            let identity = pair[1] as NWIdentityRef

            selectCertificate(certificate,
                              identity: identity is NSNull ? nil : identity,
                              environment: preferredEnvironment(for: certificate))

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
        sandboxCheckBox.isEnabled = false
    }

    private func enableButtons(forCertificate certificate: NWCertificateRef, environment: NWEnvironment) {
        let environmentOptions: NWEnvironmentOptions = SecTools.environmentOptions(forCertificate: certificate)
        let shouldEnableEnvButton: Bool = environmentOptions == .any
        let shouldSelectSandboxEnv: Bool = environment == .sandbox
        pushButton.isEnabled = true
        reconnectButton.isEnabled = true
        sandboxCheckBox.isEnabled = shouldEnableEnvButton
        sandboxCheckBox.state = shouldSelectSandboxEnv ? .on : .off
    }

    private func feedback() {
        serial?.async {
            guard
                let certificate: NWCertificateRef = self.selectedCertificate
                else {
                    //NWLogWarn(@"Unable to connect to feedback service: no certificate selected");
                    return
            }

            //NWEnvironment environment = [self selectedEnvironmentForCertificate:certificate];
            //NSString *summary = [NWSecTools summaryWithCertificate:certificate];
            //NWLogInfo(@"Connecting to feedback service..  (%@ %@)", summary, descriptionForEnvironent(environment));

            let feedback: PushFeedback

            do {
                let identity = try SecTools.keychainIdentity(withCertificate: certificate)

                feedback = try PushFeedback.connect(withIdentity: identity as NWIdentityRef,
                                                    environment: self.selectedEnvironment(for: certificate))
            } catch {
                Logger.logWarn("Unable to connect to feedback service: \(error.localizedDescription)")
                return
            }

            //NWLogInfo(@"Reading feedback service..  (%@ %@)", summary, descriptionForEnvironent(environment));

            let pairs: [Any]

            do {
                pairs = try feedback.readTokenDatePairs(withMax: 1000)
            } catch {
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
        }
    }

    private func identifier(withCertificate certificate: NWCertificateRef) -> String {
        let environmentOptions: NWEnvironmentOptions = SecTools.environmentOptions(forCertificate: certificate)
        let summary: String = SecTools.summary(withCertificate: certificate)

        return "\(summary)-\(ErrorUtil.descriptionForEnvironmentOptions(environmentOptions))"
    }

    private func importIdentity() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = true
        panel.allowedFileTypes = ["p12"]

        panel.begin { result in
            if result.rawValue != NSFileHandlingPanelOKButton {
                return
            }

            var pairs: [[Any]] = []

            for url: URL in panel.urls {
                let text = "Enter password for \(url.lastPathComponent)"
                let alert = NSAlert()

                alert.messageText = text
                alert.addButton(withTitle: "OK")
                alert.addButton(withTitle: "Cancel")
                alert.informativeText = ""

                let input = NSSecureTextField(frame: NSMakeRect(0, 0, 200, 24))

                alert.accessoryView = input

                let button: NSApplication.ModalResponse = alert.runModal()

                if button.rawValue != NSApplication.ModalResponse.alertFirstButtonReturn.rawValue {
                    return
                }

                let password = "\(input)" as NSString

                guard
                    let data = try? Data(contentsOf: url)
                    else { return }

                var ids: [Any]?

                do {
                    ids = try SecTools.identities(withPKCS12Data: data,
                                                  password: password as String!)
                } catch let error as NSError {
                    if !(password.length == 0) && error.code == NWError.pkcs12Password.rawValue {
                        ids = try? SecTools.identities(withPKCS12Data: data,
                                                       password: "")
                    }
                }

                guard
                    let identities = ids
                    else {
                        //NWLogWarn(@"Unable to read p12 file: %@", error.localizedDescription);
                        return
                }

                for identity: IdentityRef in identities {
                    let certificate: NWCertificateRef

                    do {
                        certificate = try SecTools.certificate(withIdentity: identity as NWIdentityRef) as NWCertificateRef
                    } catch {
                        //NWLogWarn(@"Unable to import p12 file: %@", error.localizedDescription);
                        return
                    }

                    pairs.append([certificate, identity])
                }
            }

            if pairs.isEmpty {
                //NWLogWarn(@"Unable to import p12 file: no push certificates found");
                return
            }

            //NWLogInfo(@"Imported %i certificate%@", (int)pairs.count, pairs.count == 1 ? @"" : @"s");
            let index: Int = self.certificateIdentityPairs.count

            self.certificateIdentityPairs = self.certificateIdentityPairs + pairs
            self.updateCertificatePopup()
            self.connectWithCertificate(at: index + 1)
        }
    }

    private func loadConfig() {
        guard
            let url = configFileURL(),
            let tmpConfig = NSDictionary(contentsOf: url) as? [AnyHashable : Any]
            else { return }

        config = tmpConfig
        //NWLogInfo(@"Loaded config from %@", url.path);
    }

    private func loadCertificatesFromKeychain() {
        var certs: [Any] = []

        do {
            certs = try SecTools.keychainCertificates()
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
            let envOptionsA: NWEnvironmentOptions = SecTools.environmentOptions(forCertificate: a as NWCertificateRef)
            let envOptionsB: NWEnvironmentOptions = SecTools.environmentOptions(forCertificate: b as NWCertificateRef)
            if envOptionsA != envOptionsB {
                return envOptionsA.rawValue < envOptionsB.rawValue
            }
            let aname: String = SecTools.summary(withCertificate: a as NWCertificateRef)
            let bname: String = SecTools.summary(withCertificate: b as NWCertificateRef)
            return aname < bname
        })

        var pairs: [[Any]] = []

        for c: CertificateRef in certs {
            pairs.append([c, NSNull()])
        }

        certificateIdentityPairs = certificateIdentityPairs + pairs
    }

    private func notification(_ notification: Notification) throws {
        DispatchQueue.main.async(execute: {() -> Void in
            //NSLog(@"failed notification: %@ %@ %lu %lu %lu", notification.payload, notification.token, notification.identifier, notification.expires, notification.priority);
            //NWLogWarn(@"Notification error: %@", error.localizedDescription);
        })
    }

    private func loadSelectedToken() {
        guard
            let cert = selectedCertificate,
            let token = tokens(withCertificate: cert, create: true)
            else { return }

        tokenCombo.stringValue = token.last as? String ?? ""
        // _tokenCombo.stringValue = @"552fff0a65b154eb209e9dc91201025da1a4a413dd2ad6d3b51e9b33b90c977a my iphone";
    }

    private func push() {
        let payload: String = payloadField.string
        let token = tokenCombo.stringValue
        let expiry: Date? = selectedExpiry()
        let priority: Int = selectedPriority()
        //NWLogInfo(@"Pushing..");

        serial?.async {
            let notification = Notification(payload: payload,
                                            token: token,
                                            identifier: 0,
                                            expiration: expiry,
                                            priority: UInt(priority))

            do {
                try self.hub?.pushNotification(notification, autoReconnect: true)

                let popTime = DispatchTime.now() + Double(Int(1.0 * Double(NSEC_PER_SEC)))

                self.serial?.asyncAfter(deadline: popTime) {
                    do {
                        var failed: Notification? = nil

                        try self.hub?.readFailed(&failed,
                                                 autoReconnect: true)

                        //if (!failed) NWLogInfo(@"Payload has been pushed");
                    } catch {
                        //NWLogWarn(@"Unable to read: %@", error.localizedDescription);
                    }

                    _ = self.hub?.trimIdentifiers()
                }
            } catch {
                //NWLogWarn(@"Unable to push: %@", error.localizedDescription);
            }
        }
    }

    private func selectedEnvironment(for certificate: NWCertificateRef) -> NWEnvironment {
        return sandboxCheckBox.state == .on ? .sandbox : .production
    }

    private func selectedExpiry() -> Date? {
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
            return nil
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

    @objc
    private func textDidChange(_ notification: Foundation.Notification) {
        if let textView = notification.object as? NSTextView,
            textView === payloadField {
            updatePayloadCounter()
        }
    }

    private func updateCertificatePopup() {
        var suffix = " "

        certificatePopup.removeAllItems()
        certificatePopup.addItem(withTitle: "Select Push Certificate")

        let formatter = DateFormatter()

        formatter.dateStyle = .short
        formatter.timeStyle = .short

        for pair: [Any] in certificateIdentityPairs {
            let certificate = pair[0] as NWCertificateRef
            let hasIdentity: Bool = !(pair[1] is NSNull)
            let environmentOptions: NWEnvironmentOptions = SecTools.environmentOptions(forCertificate: certificate)
            var summary: NSString? = nil
            let certType: NWCertType = SecTools.type(withCertificate: certificate, summary: &summary)
            let type: String = ErrorUtil.descriptionForCertType(certType)
            let date: Date? = SecTools.expiration(withCertificate: certificate)
            let expire = "  [\((date != nil) ? formatter.string(from: date!) : "expired")]"

            certificatePopup.addItem(withTitle: "\(hasIdentity ? "imported: " : "")\(summary ?? "") (\(type) \(ErrorUtil.descriptionForEnvironmentOptions(environmentOptions)))\(expire)\(suffix)")

            suffix += " "
        }
        certificatePopup.addItem(withTitle: "Import PKCS #12 file (.p12)...")
    }

    private func updatePayloadCounter() {
        let payload: String = payloadField.string

        do {
            try JSONSerialization.jsonObject(with: payload.data(using: .utf8) ?? Data(),
                                             options: [])

            countField.stringValue = "\(payload.count)"
            countField.textColor = payload.count > 256 ? NSColor.red : NSColor.darkGray
        } catch {
            countField.stringValue = "malformed \(payload.count)"
            countField.textColor = NSColor.red
        }
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

    private func preferredEnvironment(for certificate: NWCertificateRef) -> NWEnvironment {
        let environmentOptions: NWEnvironmentOptions = SecTools.environmentOptions(forCertificate: certificate)

        return environmentOptions.contains(.sandbox) ? .sandbox : .production
    }

    private func reconnect() {
        guard
            let cert = selectedCertificate
            else { return }

        //NSString *summary = [NWSecTools summaryWithCertificate:_selectedCertificate];
        let environment: NWEnvironment = selectedEnvironment(for: cert)

        //NWLogInfo(@"Reconnecting to APN...(%@ %@)", summary, descriptionForEnvironent(environment));

        selectCertificate(cert,
                          identity: nil,
                          environment: environment)
    }

    private func removeToken(_ token: String, certificate: NWCertificateRef) -> Bool {
        guard
            var tokens = self.tokens(withCertificate: certificate, create: false)
            else { return false }

        while let elementIndex = tokens.index(of: token) {
            tokens.remove(at: elementIndex)
        }

        return true
    }

    private func saveConfig() {
        guard
            let url = configFileURL()
            else { return }

        if config.count > 0 {
            (config as NSDictionary).write(to: url,
                                           atomically: false)
        }
    }

    private func selectCertificate(_ certificate: NWCertificateRef?,
                                   identity: NWIdentityRef?,
                                   environment: NWEnvironment) {
        self.hub?.disconnect()
        self.hub = nil

        disableButtons()

        //NWLogInfo(@"Disconnected from APN");
//        os_log("This is additional info that may be helpful for troubleshooting.", log: OSLog.default, type: .info)


        selectedCertificate = certificate
        updateTokenCombo()

        if let cert = certificate {
            //NSString *summary = [NWSecTools summaryWithCertificate:certificate];
//            NWLogInfo(@"Connecting to APN...  (%@ %@)", summary, descriptionForEnvironent(environment));

            serial?.async {
                guard
                    let ident = identity ?? (try? SecTools.keychainIdentity(withCertificate: certificate))
                    else { return }


                let hub = try? Hub.connect(with: self,
                                           identity: ident as NWIdentityRef,
                                           environment: environment)

                DispatchQueue.main.async {
                    if (hub != nil) {
                        //NWLogInfo(@"Connected  (%@ %@)", summary, descriptionForEnvironent(environment));
                        self.hub = hub
                        self.enableButtons(forCertificate: cert,
                                           environment: environment)
                    }
                    else {
                        //NWLogWarn(@"Unable to connect: %@", error.localizedDescription);
                        hub?.disconnect()
                        self.certificatePopup.selectItem(at: 0)
                    }
                }
            }
        }
    }

    private func selectToken(_ token: String, certificate: NWCertificateRef) -> Bool {
        guard
            var tokens = self.tokens(withCertificate: certificate, create: true)
            else { return false }

        while let elementIndex = tokens.index(of: token) {
            tokens.remove(at: elementIndex)
        }

        tokens.append(token)

        return true
    }

    private func selectTokenAndUpdateCombo() {
        guard
            let cert = selectedCertificate
            else { return }

        let selected = selectToken("\(tokenCombo)", certificate: cert)

        if selected {
            updateTokenCombo()
        }
    }

    private func tokens(withCertificate certificate: NWCertificateRef,
                        create: Bool) -> [AnyHashable]? {
        guard
            let cert = selectedCertificate
            else { return nil }

        let environment = selectedEnvironment(for: cert)
        let summary = SecTools.summary(withCertificate: certificate)
        let identifier: String?

        if environment == .sandbox {
            identifier = "\(summary)-sandbox"
        } else {
            identifier="\(summary)"
        }

        var result: Any?

        guard
            var config = config["identifiers"] as? [AnyHashable: Any],
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

    private func updateTokenCombo() {
        tokenCombo.removeAllItems()

        guard
            let cert = selectedCertificate,
            let tokens = self.tokens(withCertificate: cert, create: false),
            let tokenValue = (tokens as NSArray?)?.reverseObjectEnumerator().allObjects
            else { return }

        if !tokens.isEmpty {
            tokenCombo.addItems(withObjectValues: tokenValue)
        }
    }
}

extension AppDelegate: LoggerDelegate {
    public func log(message: String, warning: Bool) {
        DispatchQueue.main.async {

            self.infoField.textColor = warning ? .red : .black
            self.infoField.stringValue = message

            if (!message.isEmpty) {
                var attributes: [NSAttributedStringKey: Any] = [:]

                if let length = self.logField.textStorage?.length,
                    let color = self.infoField.textColor,
                    let font = NSFont(name: "Monaco", size: 10) {

                    attributes = [NSAttributedStringKey.foregroundColor: color,
                                  NSAttributedStringKey.font: font]
                    let string = NSAttributedString(string: message, attributes: attributes)
                    self.logField.textStorage?.append(string)
                    self.logField.textStorage?.mutableString.append("/n")
                    self.logField.scrollRangeToVisible(NSMakeRange(length - 1, 1))
                }
            }
        }
    }
}

extension AppDelegate: HubDelegate {
    public func notification(_ notification: Notification?,
                             didFailWithError error: Error) {
//        dispatch_async(dispatch_get_main_queue(), ^{
//            //NSLog(@"failed notification: %@ %@ %lu %lu %lu", notification.payload, notification.token, notification.identifier, notification.expires, notification.priority);
//            NWLogWarn(@"Notification error: %@", error.localizedDescription);
//            });
    }
}
