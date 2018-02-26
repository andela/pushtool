import UIKit

public let deviceToken = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
public let pkcs12FileName = "PushTool.p12"
public let pkcs12Password = "pa$$word"

@objcMembers
public class PusherViewController: UIViewController {
    
    // MARK: Public Instance Method
    
    public override func viewDidLoad() {
        
        super.viewDidLoad()
        
        serial = DispatchQueue(label: "AppDelegate")
        
        connectButton = UIButton(type: .roundedRect)
        connectButton.frame = CGRect(x: 20,
                                     y: 20,
                                     width: (view.bounds.size.width) / 2,
                                     height: 40)
        connectButton.setTitle("Connect", for: .normal)
        connectButton.addTarget(self,
                                action: #selector(self.connectButtonPressed),
                                for: .touchUpInside)
        view.addSubview(connectButton)
        
        sandboxSwitch = UISwitch()
        sandboxSwitch.frame = CGRect(x: (view.bounds.size.width  + 40) / 2,
                                     y: 20,
                                     width: 40,
                                     height: 40)
        sandboxSwitch.addTarget(self,
                                action: #selector(self.sanboxCheckBoxDidPressed),
                                for: .valueChanged)
        view.addSubview(sandboxSwitch)
        
        let sandboxLabel = UILabel()
        sandboxLabel.frame = CGRect(x: (sandboxSwitch.frame.maxX) + 10,
                                    y: 20,
                                    width: 80,
                                    height: 40)
        sandboxLabel.font = sandboxLabel.font.withSize(12.0)
        sandboxLabel.text = "Use sandbox"
        view.addSubview(sandboxLabel)
        
        textField = UITextField()
        textField.frame = CGRect(x: 20,
                                 y: 70,
                                 width: view.bounds.size.width - 40,
                                 height: 26)
        textField.text = "Testing.."
        textField.borderStyle = .bezel
        view.addSubview(textField)
        
        
        pushButton = UIButton(type: .roundedRect)
        pushButton.frame = CGRect(x: 20,
                                  y: 106,
                                  width: view.bounds.size.width - 40,
                                  height: 40)
        pushButton.setTitle("Push", for: .normal)
        pushButton.addTarget(self,
                             action: #selector(push(_:)),
                             for: .touchUpInside)
        pushButton.isEnabled = false
        view.addSubview(pushButton)
        
        infoLabel = UILabel()
        infoLabel.frame = CGRect(x: 20,
                                 y: 156,
                                 width: view.bounds.size.width - 40,
                                 height: 60)
        infoLabel.font = infoLabel.font.withSize(12.0)
        infoLabel.numberOfLines = 0
        view.addSubview(infoLabel)
        
        //NWLogInfo(@"Connect with Apple's Push Notification service");
        
        loadCertificate()
        
    }
    
    // MARK: Private Instance Properties
    
    private var connectButton: UIButton!
    private var infoLabel: UILabel!
    private var pushButton: UIButton!
    private var sandboxSwitch: UISwitch!
    private var textField: UITextField!
    
    private var certificate: NWCertificateRef?
    private var hub: Hub?
    private var identity: NWIdentityRef?
    private var index: Int = 0
    private var serial: DispatchQueue?
    
    // MARK: Private Instance Methods
    
    private func loadCertificate() {
        
        guard let url: URL = Bundle.main.url(forResource: pkcs12FileName,
                                        withExtension: nil)
        else { return }
        
        do {
            let pkcs12 = try Data(contentsOf: url)
            
            let ids = try SecTools.identities(withPKCS12Data: pkcs12,
                                              password: pkcs12Password) as [NWIdentityRef]
            
            if ids.isEmpty {
                
                //NWLogWarn(@"Unable to read p12 file: %@", error.localizedDescription);
                
                return
            }
            
            for identity in ids {
                
                guard
                    let certificate = try? SecTools.certificate(withIdentity: identity)
                    
                    //NWLogWarn(@"Unable to import p12 file: %@", error.localizedDescription);
                    
                    else { return }
                
                self.identity = identity
                self.certificate = certificate as NWCertificateRef
            }
        }
        catch {
            print(error)
        }
        
    }
    
    @IBAction func sanboxCheckBoxDidPressed(_ sender: UISwitch) {
        
        if let certificate = certificate {
            
            disconnect()
            connect(to: selectedEnvironment(forCertificate: certificate))
        }
    }
    
    private func selectedEnvironment(forCertificate certificate: NWCertificateRef) -> NWEnvironment {
        
        return (sandboxSwitch.isOn ? .sandbox : .production)
        
    }
    
    private func preferredEnvironment(forCertificate certificate: NWCertificateRef) -> NWEnvironment {
        
        let environmentOptions: NWEnvironmentOptions = SecTools.environmentOptions(forCertificate: certificate)
        
        if environmentOptions == .none {
            
            return .sandbox
        }
        else {
            
            return  .production
        }
        
    }
    
    @objc
    private func connectButtonPressed() {
        
        if hub != nil {
            disconnect()
            connectButton?.isEnabled = true
            connectButton?.setTitle("Connect", for: .normal)
            return
        }
        guard let certificate = self.certificate else { return }
        
        let preferredEnvironment: NWEnvironment = self.preferredEnvironment(forCertificate: certificate)
        connect(to: preferredEnvironment)
    }
    
    private func disconnect() {
        
        disableButtons()
        hub?.disconnect()
        hub = nil
        
        //NWLogInfo(@"Disconnected");
        
    }
    
    private func connect(to environment: NWEnvironment) {
        
        disconnect()
        
        //NWLogInfo(@"Connecting..");
        
        guard let identity = identity else { return }
        guard let hubInstance = try? Hub.connect(with: self,
                                                 identity: identity,
                                                 environment: environment)
            else { return }
        
        DispatchQueue.main.async(execute: {[weak self]() -> Void in
            
            if (self?.hub != nil) {
                
                //NWLogInfo(@"Connected to APN: %@ (%@)", summary, descriptionForEnvironent(environment));
                
                self?.hub = hubInstance
                self?.connectButton?.setTitle("Disconnect", for: .normal)
                
            }
            else{
                
                //NWLogWarn(@"Unable to connect: %@", error.localizedDescription);
                
                guard let certificate =  self?.certificate else { return }
                self?.enableButtons(forCertificate: certificate,
                                    environment: environment)
            }
        })
        
    }
    
    @objc
    private func push(_ sender: Any) {
        
        let payload = "{\"aps\":{\"alert\":\"%@\",\"badge\":1,\"sound\":\"default\"}}"
        let token = String(deviceToken)
        
        // NWLogInfo(@"Pushing..");
        
        serial?.async(execute: {[weak self]() -> Void in
            
            let _ = self?.hub?.pushPayload(payload, token: token)
            let popTime = DispatchTime.now() + Double(__int64_t(1.0 * Double(NSEC_PER_SEC)))
            let dispatchTime = DispatchTime(uptimeNanoseconds: popTime.uptimeNanoseconds/NSEC_PER_SEC)
            
            // NSUInteger failed2 = failed + [_hub readFailed];
            // if (!failed2) NWLogInfo(@"Payload has been pushed");
            
            self?.serial?.asyncAfter(deadline: dispatchTime, execute: {
                
            })
        })
    }
    
    private func notification(_ notification: NWNotification) throws {
        
        DispatchQueue.main.sync(execute: {() -> Void in
            
            // NSLog(@"failed notification: %@ %@ %lu %lu %lu", notification.payload, notification.token, notification.identifier, notification.expires, notification.priority);
            // NWLogWarn(@"Notification error: %@", error.localizedDescription);
            
        })
    }
    
    private func disableButtons() {
        
        pushButton?.isEnabled = false
        connectButton?.isEnabled = false
        sandboxSwitch?.isEnabled = false
    }
    
    private func enableButtons(forCertificate certificate: NWCertificateRef, environment: NWEnvironment) {
        
        let environmentOptions: NWEnvironmentOptions = SecTools.environmentOptions(forCertificate: certificate)
        let shouldEnableEnvButton: Bool = environmentOptions == .any
        let shouldSelectSandboxEnv: Bool = environment == .sandbox
        
        pushButton.isEnabled = true
        connectButton.isEnabled = true
        sandboxSwitch.isEnabled = shouldEnableEnvButton
        sandboxSwitch.isOn = shouldSelectSandboxEnv
    }
    
}

extension PusherViewController : HubDelegate {
    
    public func notification(_ notification: NWNotification?, didFailWithError error: Error) {
    }
    
}
