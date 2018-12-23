//
//  ViewController.swift
//  rsa_test
//
//  Created by Makoto Abe on 2018/12/19.
//  Copyright © 2018 m0a. All rights reserved.
//

import UIKit
import SwiftyRSA
import SwCrypt

class ViewController: UIViewController {

    
    func encryptOld() {
        
        let publicKey = try! PublicKey.publicKeys(pemEncoded: "-----BEGIN PUBLIC KEY-----\nMIIBHjANBgkqhkiG9w0BAQEFAAOCAQsAMIIBBgKB/gC8H1ERLRU7Xv0q6K+W8uq2\nDIXG/EkN7L1TOTTi/elkmmGGPfwVpErFyQpwToTEJHX3Lt2/deGKOZy4CRqCCWXZ\nj3rIx5i9JqA9H1lNHdpCS0AhbeiGeh+3DT0W5K8g9EmFAZLbzrst7Su/M2WqDkRe\nDXmHAEUa1GUP+vrnMLcituKB6dCS4mJzwEKzFLy1hvAZyF6pmGGJ+7Lh95ol3PLy\nwrTS666xiGjbYZydykp607J4eDtVupDIOVnzRjZ7m/xxTUECRDsaGOu0/l1CrD/z\nZO1u5Dh+t9ELSHOkHalk/cYvuWW1rRUs7UBCtaWJaRSX9ovs9nwCYiwapaqnAgMB\nAAE=\n-----END PUBLIC KEY-----\n")[0]
        
        struct Temp:Codable {
            let access_token: String
            let secret: String
        }
        
        let temp = Temp(access_token: "1072405846200446976-6AmGO5NOh7ODv4hiHj2n016BxMEHnh", secret: "QQfNZxbM7O0w9tXzQYWx5bv2Ag0aBbM754qV4TgSlmmS9")
        let data = try! JSONEncoder().encode(temp)
        let json = String(data:data, encoding: .utf8)!
        
        
        let clear = try! ClearMessage(string: json, using: .utf8)
        
        
        // oaep
        do {
            let encrypted = try! clear.encrypted(with: publicKey, padding: .OAEP)
            
            // Then you can use:
            let base64String = encrypted.base64String
            print("padding:OAEP base64String= ",base64String)
        }
        
        // plcs1 pattern
        do {
            let encrypted = try! clear.encrypted(with: publicKey, padding: .PKCS1)
            let base64String = encrypted.base64String
            print("padding:PKCS1 base64String= '\(base64String)'")
        }
        
        
    }
    func encrypt() {
        let publicKeyDER = try! SwKeyConvert.PublicKey.pemToPKCS1DER("-----BEGIN PUBLIC KEY-----\nMIIBHjANBgkqhkiG9w0BAQEFAAOCAQsAMIIBBgKB/gC8H1ERLRU7Xv0q6K+W8uq2\nDIXG/EkN7L1TOTTi/elkmmGGPfwVpErFyQpwToTEJHX3Lt2/deGKOZy4CRqCCWXZ\nj3rIx5i9JqA9H1lNHdpCS0AhbeiGeh+3DT0W5K8g9EmFAZLbzrst7Su/M2WqDkRe\nDXmHAEUa1GUP+vrnMLcituKB6dCS4mJzwEKzFLy1hvAZyF6pmGGJ+7Lh95ol3PLy\nwrTS666xiGjbYZydykp607J4eDtVupDIOVnzRjZ7m/xxTUECRDsaGOu0/l1CrD/z\nZO1u5Dh+t9ELSHOkHalk/cYvuWW1rRUs7UBCtaWJaRSX9ovs9nwCYiwapaqnAgMB\nAAE=\n-----END PUBLIC KEY-----\n")
        
        
        struct Temp:Codable {
            let access_token: String
        }
        
        let temp = Temp(access_token: "EAAgkUFrhPQkBACPY3MVmWaHGZAItdPxeUVdzapPoF2PvP1lgoPa1NjJYYt87s9wDtku9q7CmOeagGQDMzGTBxMT6uaKUPsGDTHdri1TcCfZAp1xnOp0fZCTbzv8S0ZBTs38lLwvWAjRbW8HxQi0yAPNHiGjnPoLIMqdTYabWoan9lVvzMgZCGPYu50ciRMuMoNYtpkUBOnxKOkZC7WkIcXcuXkPSCs13ocRLe2f3ZB7ts0V5l1tjW0k")
        let data = try! JSONEncoder().encode(temp)
        let json = String(data:data, encoding: .utf8)!
        let jsonData = json.data(using: .utf8)!
        
        let chiperText = try! CC.RSA.encrypt(jsonData, derKey: publicKeyDER, tag: Data(), padding: .pkcs1, digest: .sha256)
        print("cText = \(chiperText.base64EncodedString())")
        
    }
    override func viewDidLoad() {
        super.viewDidLoad()
//        encrypt()
    }


}

