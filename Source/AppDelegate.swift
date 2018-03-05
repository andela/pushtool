import AppKit
import Foundation

@NSApplicationMain
@objcMembers
public class AppDelegate: NSObject, NSApplicationDelegate {
    @IBOutlet private var certificatePopup: NSPopUpButton!
    @IBOutlet private var countField: NSTextField!
    @IBOutlet private var expiryPopup: NSPopUpButton!
    @IBOutlet private var infoField: NSTextField!
    @IBOutlet private var logField: NSTextView!
    @IBOutlet private var logScroll: NSScrollView!
    @IBOutlet private var payloadView: NSTextView!
    @IBOutlet private var priorityPopup: NSPopUpButton!
    @IBOutlet private var pushButton: NSButton!
    @IBOutlet private var tokenCombo: NSComboBox!
    @IBOutlet private var reconnectButton: NSButton!
    @IBOutlet private var sandboxCheckBox: NSButton!
    @IBOutlet private var window: NSWindow!

    // MARK: Private Instance Properties

    private var certificateIdentityPairs: [[Any]] = []
    private var config: [AnyHashable: Any] = [:]
    private var hub: Hub?
    private var lastSelectedIndex: Int = 0
    private var selectedCertificate: CertificateRef?
    private var serial: DispatchQueue?

    // MARK: Public Instance methods

    public func applicationDidFinishLaunching(_ notification: Foundation.Notification) {
        Logger.delegate = self
        Logger.logInfo("Application did finish launching")

        serial = DispatchQueue(label: "AppDelegate")

        certificateIdentityPairs = []
        loadCertificatesFromKeychain()
        loadConfig()
        updateCertificatePopup()

        guard
            let payload = config["payload"] as? String
            else { return }

        payloadView.string = !payload.isEmpty ? payload : ""
        payloadView.font = NSFont(name: "Monaco", size: 10)
        payloadView.enabledTextCheckingTypes = NSTextCheckingTypes(0)

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

        Logger.logInfo("Application will terminate")
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
        if selectedCertificate != nil {
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

    private func addToken(_ token: String, certificate: CertificateRef) -> Bool {
        guard
            var tokens = self.tokens(withCertificate: certificate,
                                     create: true)
            else { return false }

        if !token.isEmpty {
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
            let configURL: URL = libraryURL?.appendingPathComponent("PushTool",
                                                                    isDirectory: true)
            else { return nil }

        let exists: Any?

        exists = try? FileManager.default.createDirectory(at: configURL,
                                                          withIntermediateDirectories: true,
                                                          attributes: nil)

        if exists != nil {
            guard
                let result: URL? = configURL.appendingPathComponent("config.plist"),
                let aPath = result?.path
                else { return nil }

            if !FileManager.default.fileExists(atPath: aPath) {
                let defaultURL: URL? = Bundle.main.url(forResource: "config", withExtension: "plist")
                if let aURL = defaultURL, let aResult = result {
                    try? FileManager.default.copyItem(at: aURL, to: aResult)
                }

            }

            return result
        }

        return nil
    }

    private func connectWithCertificate(at index: Int) {
        if index == 0 {
            certificatePopup.selectItem(at: 0)
            lastSelectedIndex = 0
            selectCertificate(nil,
                              identity: nil,
                              environment: Environment.sandbox)
            tokenCombo.isEnabled = false
            loadSelectedToken()
        } else if index <= certificateIdentityPairs.count {
            certificatePopup.selectItem(at: index)
            lastSelectedIndex = index
            let pair = certificateIdentityPairs[index - 1]
            let certificate = pair[0] as CertificateRef
            let identity = pair[1] as IdentityRef

            selectCertificate(certificate,
                              identity: identity is NSNull ? nil : identity,
                              environment: preferredEnvironment(for: certificate))

            tokenCombo.isEnabled = true
            loadSelectedToken()
        } else {
            certificatePopup.selectItem(at: lastSelectedIndex)
            importIdentity()
        }
    }

    private func disableButtons() {
        pushButton.isEnabled = false
        reconnectButton.isEnabled = false
        sandboxCheckBox.isEnabled = false
    }

    private func enableButtons(forCertificate certificate: CertificateRef, environment: Environment) {
        let environmentOptions: EnvironmentOptions = SecTools.environmentOptions(forCertificate: certificate)
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
                let certificate: CertificateRef = self.selectedCertificate
                else { Logger.logWarn("Unable to connect to feedback service: no certificate selected"); return }

            let summary = SecTools.summary(withCertificate: certificate)
            let environment = self.selectedEnvironment(for: certificate)
            Logger.logInfo("Connecting to feedback service... \(summary), \(ErrorUtil.descriptionForEnvironment(environment))")

            let feedback: PushFeedback

            do {
                let identity = try SecTools.keychainIdentity(withCertificate: certificate)

                feedback = try PushFeedback.connect(withIdentity: identity as IdentityRef,
                                                    environment: self.selectedEnvironment(for: certificate))
            } catch {
                Logger.logWarn("Unable to connect to feedback service: \(error.localizedDescription)"); return }

            Logger.logInfo("Reading feedback service... \(summary), \(ErrorUtil.descriptionForEnvironment(environment))")
            let pairs: [[Any]]

            do {
                pairs = try feedback.readTokenDatePairs(withMax: 1_000)
            } catch {
                Logger.logWarn("Unable to read feedback: \(error.localizedDescription)"); return }

            pairs.forEach { Logger.logInfo("token: \($0[0]), date: \($0[1])") }

            if !pairs.isEmpty {
                Logger.logInfo("Feedback service returned \(pairs.count) device tokens, see logs for details")
            } else {
                Logger.logInfo("Feedback service returned zero device tokens")
            }
        }
    }

    private func identifier(withCertificate certificate: CertificateRef) -> String {
        let environmentOptions: EnvironmentOptions = SecTools.environmentOptions(forCertificate: certificate)
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
                let alert = NSAlert()
                let text = "Enter password for \(url.lastPathComponent)"

                alert.addButton(withTitle: "OK")
                alert.addButton(withTitle: "Cancel")
                alert.informativeText = ""
                alert.messageText = text

                let input = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 200, height: 24))

                alert.accessoryView = input

                let button: NSApplication.ModalResponse = alert.runModal()

                if button.rawValue != NSApplication.ModalResponse.alertFirstButtonReturn.rawValue {
                    return
                }

                let password = input.stringValue

                guard
                    let data = try? Data(contentsOf: url)
                    else { return }

                var ids: [Any]?

                do {
                    ids = try SecTools.identities(withPKCS12Data: data,
                                                  password: password)
                } catch let error as NSError {
                    if !password.isEmpty && error.code == PushError.pkcs12Password.rawValue {
                        ids = try? SecTools.identities(withPKCS12Data: data,
                                                       password: nil)
                    }
                }

                guard
                    let identities = ids
                    else { Logger.logWarn("Unable to read p12 file"); return }

                for identity: IdentityRef in identities {
                    let certificate: CertificateRef

                    do {
                        certificate = try SecTools.certificate(withIdentity: identity as IdentityRef) as CertificateRef
                    } catch {
                        Logger.logWarn("Unable to import p12 file"); return }

                    pairs.append([certificate, identity])
                }
            }

            if pairs.isEmpty {
                Logger.logWarn("Unable to import p12 file: no push certificates found"); return }

            Logger.logInfo("Impored \(pairs.count) certificate\(pairs.count == 1 ? "":"s")")
            let index: Int = self.certificateIdentityPairs.count

            self.certificateIdentityPairs += pairs
            self.updateCertificatePopup()
            self.connectWithCertificate(at: index + 1)
        }
    }

    private func loadConfig() {
        guard
            let url = configFileURL(),
            let tmpConfig = NSDictionary(contentsOf: url) as? [AnyHashable: Any]
            else { return }

        config = tmpConfig
        Logger.logInfo("Loaded config from \(url.path)")
    }

    private func loadCertificatesFromKeychain() {
        var certs: [Any] = []

        do {
            certs = try SecTools.keychainCertificates()
        } catch {
            Logger.logWarn("Unable to access keychain: \(error.localizedDescription)")
        }

        if certs.isEmpty {
            Logger.logWarn("No push certificates in keychain.")
        }

        certs = certs.sorted {(_ optA: CertificateRef, _ optB: CertificateRef) -> Bool in
            let envOptionsA: EnvironmentOptions = SecTools.environmentOptions(forCertificate: optA as CertificateRef)
            let envOptionsB: EnvironmentOptions = SecTools.environmentOptions(forCertificate: optB as CertificateRef)
            if envOptionsA != envOptionsB {
                return envOptionsA.rawValue < envOptionsB.rawValue
            }

            let aname: String = SecTools.summary(withCertificate: optA as CertificateRef)
            let bname: String = SecTools.summary(withCertificate: optB as CertificateRef)
            return aname < bname
        }

        var pairs: [[Any]] = []

        for c: CertificateRef in certs {
            pairs.append([c, NSNull()])
        }

        certificateIdentityPairs += pairs
    }

    private func notification(_ notification: Notification) throws {
        DispatchQueue.main.async {() -> Void in
            let infoString = """
            failed notification: \(notification.payload),
            \(notification.token),
            \(notification.identifier),
            \(String(describing: notification.expires)),
            \(notification.priority)
            """
            Logger.logInfo(infoString)
        }
    }

    private func loadSelectedToken() {
        guard
            let cert = selectedCertificate,
            let token = tokens(withCertificate: cert, create: true)
            else { return }

        tokenCombo.stringValue = token.last as? String ?? ""
    }

    private func push() {
        let payload: String = payloadView.string
        let token = tokenCombo.stringValue
        let expiry: Date? = selectedExpiry()
        let priority: Int = selectedPriority()
        Logger.logInfo("Pushing...")

        saveConfig()

        serial?.async {
            let notification = Notification(payload: payload,
                                            token: token,
                                            identifier: 0,
                                            expiration: expiry,
                                            priority: UInt(priority))

            do {
                try self.hub?.pushNotification(notification, autoReconnect: true)

                let popTime = DispatchTime.now() + 1.0

                self.serial?.asyncAfter(deadline: popTime) {
                    do {
                        var failed: Notification?

                        try self.hub?.readFailed(&failed,
                                                 autoReconnect: true)

                        Logger.logInfo("Payload has been pushed")
                    } catch {
                        Logger.logWarn("Unable to read: \(error.localizedDescription)")
                    }

                    _ = self.hub?.trimIdentifiers()
                }
            } catch {
                Logger.logWarn("Unable to push: \(error.localizedDescription)")
            }
        }
    }

    private func selectedEnvironment(for certificate: CertificateRef) -> Environment {
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
            return Date(timeIntervalSinceNow: 3_600)

        case 5:
            return Date(timeIntervalSinceNow: 86_400)

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
            textView === payloadView {
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
            let certificate = pair[0] as CertificateRef
            let hasIdentity: Bool = !(pair[1] is NSNull)
            let environmentOptions: EnvironmentOptions = SecTools.environmentOptions(forCertificate: certificate)
            var summary: NSString?
            let certType: CertType = SecTools.type(withCertificate: certificate, summary: &summary)
            let type: String = ErrorUtil.descriptionForCertType(certType)
            let date: Date? = SecTools.expiration(withCertificate: certificate)
            let expire = "  [\((date != nil) ? formatter.string(from: date ?? Date()) : "expired")]"

            certificatePopup.addItem(withTitle: """
                \(hasIdentity ? "imported: " : "")\(summary ?? "") \
                (\(type)\(ErrorUtil.descriptionForEnvironmentOptions(environmentOptions)))\(expire)\(suffix)
                """)

            suffix += " "
        }

        certificatePopup.addItem(withTitle: "Import PKCS #12 file (.p12)...")
    }

    private func updatePayloadCounter() {
        let payload: String = payloadView.string

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
        let payload: String = payloadView.string
        var range: NSRange = (payload as NSString).range(of: "\\([0-9]+\\)", options: .regularExpression)

        if range.location != NSNotFound {
            range.location += 1
            range.length -= 2

            let before: String = (payload as NSString).substring(to: range.location)
            let value = Int((payload as NSString).substring(with: range)) ?? 0 + 1
            let after: String = (payload as NSString).substring(from: range.location + range.length)

            payloadView.string = "\(before)\(value)\(after)"
        }
    }

    private func preferredEnvironment(for certificate: CertificateRef) -> Environment {
        let environmentOptions: EnvironmentOptions = SecTools.environmentOptions(forCertificate: certificate)

        return environmentOptions == .sandbox ? .sandbox : .production
    }

    private func reconnect() {
        guard
            let cert = selectedCertificate
            else { return }

        let environment: Environment = selectedEnvironment(for: cert)
        selectCertificate(cert,
                          identity: nil,
                          environment: environment,
                          message: "Reconnecting to APN...")
    }

    private func removeToken(_ token: String, certificate: CertificateRef) -> Bool {
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
            let url = configFileURL(),
            let cert = selectedCertificate,
            let tokens = self.tokens(withCertificate: cert, create: false),
            let tokenValue = (tokens as NSArray?)?.reverseObjectEnumerator().allObjects
            else { return }

        if !config.isEmpty {
            (config as NSDictionary).write(to: url,
                                           atomically: false)
        }
    }

    private func selectCertificate(_ certificate: CertificateRef?,
                                   identity: IdentityRef?,
                                   environment: Environment,
                                   message: String? = nil) {
        self.hub?.disconnect()
        self.hub = nil

        disableButtons()

        Logger.logInfo("Disconnected from APN")

        selectedCertificate = certificate
        updateTokenCombo()

        if let cert = certificate {
            let environment: Environment = selectedEnvironment(for: cert)
            let summary = SecTools.summary(withCertificate: cert)

            Logger.logInfo("\(message ?? "Connecting to APN..."), \(summary), \(ErrorUtil.descriptionForEnvironment(environment)) ")

            serial?.async {
                guard
                    let ident = identity ?? (try? SecTools.keychainIdentity(withCertificate: certificate))
                    else { return }

                let hub = try? Hub.connect(with: self,
                                           identity: ident as IdentityRef,
                                           environment: environment)

                DispatchQueue.main.async {
                    if hub != nil {
                        Logger.logInfo("Connected \(summary), \(ErrorUtil.descriptionForEnvironment(environment)) ")
                        self.hub = hub
                        self.enableButtons(forCertificate: cert,
                                           environment: environment)
                    } else {
                        Logger.logWarn("Unable to connect")
                        hub?.disconnect()
                        self.certificatePopup.selectItem(at: 0)
                    }
                }
            }
        }
    }

    private func selectToken(_ token: String, certificate: CertificateRef) -> Bool {
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

    private func tokens(withCertificate certificate: CertificateRef,
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

            if !message.isEmpty {
                var attributes: [NSAttributedStringKey: Any] = [:]

                if let color = self.infoField.textColor,
                    let font = NSFont(name: "Monaco", size: 10) {
                    attributes = [NSAttributedStringKey.foregroundColor: color,
                                  NSAttributedStringKey.font: font]

                    let string = NSAttributedString(string: message,
                                                    attributes: attributes)

                    self.logField.textStorage?.append(string)
                    self.logField.textStorage?.mutableString.append("\n")

                    if let length = self.logField.textStorage?.length {
                        self.logField.scrollRangeToVisible(NSRange(location: length - 1, length: 1))
                    }
                }
            }
        }
    }
}

extension AppDelegate: HubDelegate {
    public func notification(_ notification: Notification?,
                             didFailWithError error: Error) {
        DispatchQueue.main.async {
            if let notification = notification {
                Logger.logInfo("""
                    failed notification: \(notification.payload),
                    \(notification.token),
                    \(notification.identifier),
                    \(String(describing: notification.expires)),
                    \(notification.priority)
                    """)
                Logger.logWarn("Notification error: \(error.localizedDescription)")
            }
        }
    }
}
