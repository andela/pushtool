import AppKit
import Foundation

@NSApplicationMain
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

    // MARK: Internal Instance Properties

    internal var certificateIdentityPairs: [[Any]] = []
    internal var config: [AnyHashable: Any] = [:]
    internal var inputDiscreet: NSSecureTextField? = NSSecureTextField(frame: NSRect(x: 65, y: 23, width: 200, height: 24))
    internal var inputNonDiscreet: NSTextField? = NSTextField(frame: NSRect(x: 65, y: 23, width: 200, height: 24))
    internal var selectedCertificate: CertificateRef?
    internal var serial: DispatchQueue?

    // MARK: Private Instance Properties

    private var hub: Hub?
    private var lastSelectedIndex: Int = 0

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

    public func connectWithCertificate(at index: Int) {
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

    public func readIdentities(from url: URL,
                               password: String) -> [Any]? {
        guard
            let data = try? Data(contentsOf: url)
            else { return nil }

        var ids: [Any]?

        do {
            ids = try SecIdentityTools.identities(with: data,
                                                  password: password)
        } catch let error as PushError {
            if !password.isEmpty && error == .pkcs12Password {
                ids = try? SecIdentityTools.identities(with: data,
                                                       password: nil)
            }
        } catch {
        }

        return ids
    }

    public func selectCertificate(_ certificate: CertificateRef?,
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
            let summary = SecTools.summary(with: cert)

            Logger.logInfo("\(message ?? "Connecting to APN..."), \(summary), \(environment) ")

            serial?.async {
                guard
                    let ident = identity ?? (try? SecTools.keychainIdentity(with: certificate))
                    else { return }

                let hub = try? Hub.connect(with: self,
                                           identity: ident as IdentityRef,
                                           environment: environment)

                DispatchQueue.main.async {
                    if hub != nil {
                        Logger.logInfo("Connected \(summary), \(environment) ")
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

    public func selectedEnvironment(for certificate: CertificateRef) -> Environment {
        return sandboxCheckBox.state == .on ? .sandbox : .production
    }

    public func updateCertificatePopup() {
        var suffix = " "

        certificatePopup.removeAllItems()
        certificatePopup.addItem(withTitle: "Select Push Certificate")

        let formatter = DateFormatter()

        formatter.dateStyle = .short
        formatter.timeStyle = .short

        for pair: [Any] in certificateIdentityPairs {
            let certificate = pair[0] as CertificateRef
            let hasIdentity: Bool = !(pair[1] is NSNull)
            let environmentOptions: EnvironmentOptions = SecTools.environmentOptions(for: certificate)

            let result = SecTools.type(with: certificate)

            let certType = result.certType
            let summary = result.summary

            let date: Date? = SecTools.expiration(with: certificate)
            let expire = "  [\((date != nil) ? formatter.string(from: date ?? Date()) : "expired")]"

            certificatePopup.addItem(withTitle: "\(hasIdentity ? "imported: " : "")\(summary ?? "")"
                + " (\(certType) \(environmentOptions))\(expire)\(suffix)")

            suffix += " "
        }

        certificatePopup.addItem(withTitle: "Import PKCS #12 file (.p12)...")
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

    private func configKey(for certificate: CertificateRef,
                           in environment: Environment) -> String? {
        guard
            let summary = SecTools.plainSummary(with: certificate)
            else { return nil }

        switch environment {
        case .production:
            return "\(summary)-production"

        case .sandbox:
            return "\(summary)-sandbox"

        default:
            return nil
        }
    }

    private func disableButtons() {
        pushButton.isEnabled = false
        reconnectButton.isEnabled = false
        sandboxCheckBox.isEnabled = false
    }

    private func enableButtons(forCertificate certificate: CertificateRef, environment: Environment) {
        let environmentOptions: EnvironmentOptions = SecTools.environmentOptions(for: certificate)
        let shouldEnableEnvButton: Bool = environmentOptions == .any
        let shouldSelectSandboxEnv: Bool = environment == .sandbox
        pushButton.isEnabled = true
        reconnectButton.isEnabled = true
        sandboxCheckBox.isEnabled = shouldEnableEnvButton
        sandboxCheckBox.state = shouldSelectSandboxEnv ? .on : .off
    }

    private func identifier(withCertificate certificate: CertificateRef) -> String {
        let environmentOptions: EnvironmentOptions = SecTools.environmentOptions(for: certificate)
        let summary: String = SecTools.summary(with: certificate)

        return "\(summary)-\(environmentOptions)"
    }

    private func loadSelectedToken() {
        guard
            let cert = selectedCertificate,
            let token = tokens(withCertificate: cert, create: true)
            else { return }

        tokenCombo.stringValue = token.last as? String ?? ""
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

    private func preferredEnvironment(for certificate: CertificateRef) -> Environment {
        let environmentOptions: EnvironmentOptions = SecTools.environmentOptions(for: certificate)

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
                                            expires: expiry,
                                            priority: UInt(priority))

            do {
                try self.hub?.pushNotification(notification, autoReconnect: true)

                let popTime = DispatchTime.now() + 1.0

                self.serial?.asyncAfter(deadline: popTime) {
                    do {
                        try self.hub?.readFailed(autoReconnect: true)

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

    private func saveConfig() {
        guard
            let url = configFileURL(),
            let cert = selectedCertificate,
            let key = configKey(for: cert,
                                in: selectedEnvironment(for: cert))
            else { return }

        config[key] = tokenCombo.stringValue

        (config as NSDictionary).write(to: url,
                                       atomically: false)
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

    private func textDidChange(_ notification: Foundation.Notification) {
        if let textView = notification.object as? NSTextView,
            textView === payloadView {
            updatePayloadCounter()
        }
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
            let value = (Int((payload as NSString).substring(with: range)) ?? 0) + 1
            let after: String = (payload as NSString).substring(from: range.location + range.length)

            payloadView.string = "\(before)\(value)\(after)"
        }
    }

    private func updateTokenCombo() {
        tokenCombo.removeAllItems()

        guard
            let cert = selectedCertificate,
            let key = configKey(for: cert,
                                in: selectedEnvironment(for: cert)),
            let currentToken = config[key] as? String
            else { return }

        tokenCombo.stringValue = currentToken
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
                        self.logField.scrollRangeToVisible(NSRange(location: length - 1,
                                                                   length: 1))
                    }
                }
            }
        }
    }
}
