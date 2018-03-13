import AppKit
import Foundation

extension AppDelegate {
    public func configFileURL() -> URL? {
        let libraryURL: URL? = FileManager.default.urls(for: .libraryDirectory,
                                                        in: .userDomainMask).last
        guard
            let configURL: URL = libraryURL?.appendingPathComponent("PushTool",
                                                                    isDirectory: true)
            else { return nil }

        guard
            (try? FileManager.default.createDirectory(at: configURL,
                                                      withIntermediateDirectories: true,
                                                      attributes: nil)) != nil
            else { return nil }

        let result = configURL.appendingPathComponent("config.plist")

        if !FileManager.default.fileExists(atPath: result.path),
            let defaultURL = Bundle.main.url(forResource: "config",
                                             withExtension: "plist") {
            try? FileManager.default.copyItem(at: defaultURL,
                                              to: result)
        }

        return result
    }

    public func feedback() {
        serial?.async {
            guard
                let certificate: CertificateRef = self.selectedCertificate
                else { Logger.logWarn("Unable to connect to feedback service: no certificate selected"); return }

            let summary = SecTools.summary(with: certificate)
            let environment = self.selectedEnvironment(for: certificate)
            Logger.logInfo("Connecting to feedback service... \(summary), \(environment)")

            let feedback: PushFeedback

            do {
                let identity = try SecTools.keychainIdentity(with: certificate)

                feedback = try PushFeedback.connect(with: identity as IdentityRef,
                                                    environment: self.selectedEnvironment(for: certificate))
            } catch {
                Logger.logWarn("Unable to connect to feedback service: \(error.localizedDescription)"); return }

            Logger.logInfo("Reading feedback service... \(summary), \(environment)")
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

    public func importIdentity() {
        let panel = NSOpenPanel()

        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = true
        panel.allowedFileTypes = ["p12"]

        panel.begin { result in
            guard
                result.rawValue == NSFileHandlingPanelOKButton
                else { return }

            var pairs: [[Any]] = []

            for url: URL in panel.urls {
                guard
                    let password = self.obtainPassword(for: url)
                    else { continue }

                guard
                    let identities = self.readIdentities(from: url,
                                                         password: password)
                    else { Logger.logWarn("Unable to read p12 file"); return }

                for identity: IdentityRef in identities {
                    let certificate: CertificateRef

                    do {
                        certificate = try SecTools.certificate(with: identity as IdentityRef) as CertificateRef
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

    public func loadCertificatesFromKeychain() {
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
            let envOptionsA: EnvironmentOptions = SecTools.environmentOptions(for: optA as CertificateRef)
            let envOptionsB: EnvironmentOptions = SecTools.environmentOptions(for: optB as CertificateRef)

            if envOptionsA != envOptionsB {
                return envOptionsA < envOptionsB
            }

            let aname: String = SecTools.summary(with: optA as CertificateRef)
            let bname: String = SecTools.summary(with: optB as CertificateRef)

            return aname < bname
        }

        var pairs: [[Any]] = []

        for cert: CertificateRef in certs {
            pairs.append([cert, NSNull()])
        }

        certificateIdentityPairs += pairs
    }

    public func loadConfig() {
        guard
            let url = configFileURL(),
            let tmpConfig = NSDictionary(contentsOf: url) as? [AnyHashable: Any]
            else { return }

        self.config = tmpConfig
        Logger.logInfo("Loaded config from \(url.path)")
    }

    public func obtainPassword(for url: URL) -> String? {
        let alert = NSAlert()
        let text = "Enter password for “\(url.lastPathComponent)”:"

        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: "Cancel")
        alert.informativeText = ""
        alert.messageText = text

        self.inputDiscreet = NSSecureTextField(frame: NSRect(x: 70, y: 25, width: 200, height: 24))
        self.inputNonDiscreet = NSTextField(frame: NSRect(x: 70, y: 25, width: 200, height: 24))

        let label = NSTextField(frame: NSRect(x: 0, y: 30, width: 65, height: 18))

        label.drawsBackground = false
        label.isBezeled = false
        label.isEditable = false
        label.isSelectable = false
        label.stringValue = "Password:"

        let checkBox = NSButton(frame: NSRect(x: 70, y: 4, width: 120, height: 18))

        checkBox.action = #selector(self.swapTextInputFields)
        checkBox.setButtonType(.switch)
        checkBox.title = "Show password"

        let passwordInputView = NSView(frame: NSRect(x: 0, y: 0, width: 330, height: 64))

        guard
            let inputSecure = self.inputDiscreet,
            let inputNotSecure = self.inputNonDiscreet
            else { return nil }

        passwordInputView.addSubview(inputSecure)
        passwordInputView.addSubview(inputNotSecure)
        passwordInputView.addSubview(checkBox)
        passwordInputView.addSubview(label)

        self.inputNonDiscreet?.isHidden = true

        alert.accessoryView = passwordInputView

        let button: NSApplication.ModalResponse = alert.runModal()

        if button.rawValue != NSApplication.ModalResponse.alertFirstButtonReturn.rawValue {
            return nil
        }

        return visibleInputField()?.stringValue
    }

    public func tokens(withCertificate certificate: CertificateRef,
                       create: Bool) -> [AnyHashable]? {
        guard
            let cert = selectedCertificate
            else { return nil }

        let environment = selectedEnvironment(for: cert)
        let summary = SecTools.summary(with: certificate)
        let identifier: String

        if environment == .sandbox {
            identifier = "\(summary)-sandbox"
        } else {
            identifier="\(summary)"
        }

        var result: Any?

        guard
            var config = config[identifier] as? [AnyHashable: Any]
            else { return nil }

        result = config[identifier]

        if create && (result != nil) {
            result = config[identifier]
        }

        if !(result is [AnyHashable]) {
            result = config[identifier] = result
        }

        return (result as? [AnyHashable]) ?? [AnyHashable]()
    }

    @objc
    private func swapTextInputFields(_ sender: NSButton) {
        switch sender.state {
        case .off :
            if let text = inputNonDiscreet?.stringValue {
                inputDiscreet?.stringValue = text
            }

            inputDiscreet?.isHidden = false
            inputNonDiscreet?.isHidden = true

        case .on:
            if let text = inputDiscreet?.stringValue {
                inputNonDiscreet?.stringValue = text
            }

            inputDiscreet?.isHidden = true
            inputNonDiscreet?.isHidden = false

        default:
            inputDiscreet?.isHidden = false
            inputNonDiscreet?.isHidden = true
        }
    }

    private func visibleInputField() -> NSControl? {
        if let inputField = inputDiscreet, inputField.isHidden {
            return inputNonDiscreet
        }

        return inputDiscreet
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
