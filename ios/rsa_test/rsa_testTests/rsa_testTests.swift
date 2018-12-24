//
//  rsa_testTests.swift
//  rsa_testTests
//
//  Created by Makoto Abe on 2018/12/19.
//  Copyright © 2018 m0a. All rights reserved.
//

import XCTest
import SwCrypt
import SwiftyRSA

@testable import rsa_test

class rsa_testTests: XCTestCase {
    var publicKey: Data = Data()
    var publicKeyPem: String = ""
    
    override func setUp() {
        let publicKeyPath = Bundle.main.path(forResource: "public_key", ofType: "pem") ?? ""
        self.publicKeyPem = try! String(contentsOfFile: publicKeyPath)
        self.publicKey = try! SwKeyConvert.PublicKey.pemToPKCS1DER(self.publicKeyPem)
    }

    func testEncOAEP_SwCrypt() {
        let expectString = "hello ios rsa"
        guard let data = expectString.data(using: .utf8) else {
            return
        }
        
        guard let tag = "label".data(using: .utf8) else {
            return
        }
        
        do {
        let chiperText = try CC.RSA.encrypt(data, derKey: self.publicKey, tag: tag, padding: .oaep, digest: .sha256)
            print("SwCrypt chiperText[\(chiperText.base64EncodedString())]")
        } catch {
            XCTAssertNotNil(error)
        }
    }
    
    func testEncOAEP_SwiftyRSA() {
        let publicKey = try! PublicKey.publicKeys(pemEncoded: self.publicKeyPem)[0]
        let expectString = "hello ios rsa"
        let clear = try! ClearMessage(string: expectString, using: .utf8)
        let encrypted = try! clear.encrypted(with: publicKey, padding: .OAEP)
        print("SwiftyRSA chiperText[\(encrypted.base64String)]")
    }
    
}
