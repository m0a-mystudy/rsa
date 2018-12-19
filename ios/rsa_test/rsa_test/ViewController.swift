//
//  ViewController.swift
//  rsa_test
//
//  Created by Makoto Abe on 2018/12/19.
//  Copyright © 2018 m0a. All rights reserved.
//

import UIKit
import SwiftyRSA

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
        print("in viewdidLoad")
        let publicKey = try! PublicKey.publicKeys(pemEncoded: "-----BEGIN PUBLIC KEY-----\nMIIBBwKCAQBxY8hCshkKiXCUKydkrtQtQSRke28w4JotocDiVqou4k55DEDJakvW\nbXXDcakV4HA8R2tOGgbxvTjFo8EK470w9O9ipapPUSrRRaBsSOlkaaIs6OYh4FLw\nZpqMNBVVEtguVUR/C34Y2pS9kRrHs6q+cGhDZolkWT7nGy5eSEvPDHg0EBq11hu6\nHmPmI3r0BInONqJg2rcK3U++wk1lnbD3ysCZsKOqRUms3n/IWKeTqXXmz2XKJ2t0\nNSXwiDmA9q0Gm+w0bXh3lzhtUP4MlzS+lnx9hK5bjzSbCUB5RXwMDG/uNMQqC4Mm\nA4BPceSfMyAIFjdRLGy/K7gbb2viOYRtAgED\n-----END PUBLIC KEY-----\n")
        let clear = try! ClearMessage(string: "hello rsa", using: .utf8)
        let encrypted = try! clear.encrypted(with: publicKey[0], padding: .OAEP)
        
        // Then you can use:
        let base64String = encrypted.base64String
        print("padding:OAEP base64String= ",base64String)
        
        // plcs1 pattern
        do {
            let encrypted = try! clear.encrypted(with: publicKey[0], padding: .PKCS1)
            let base64String = encrypted.base64String
            print("padding:PKCS1 base64String= ",base64String)
        }
        
        
    }


}

