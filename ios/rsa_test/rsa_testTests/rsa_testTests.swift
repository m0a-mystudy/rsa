//
//  rsa_testTests.swift
//  rsa_testTests
//
//  Created by Makoto Abe on 2018/12/19.
//  Copyright © 2018 m0a. All rights reserved.
//

import XCTest
import SwCrypt

@testable import rsa_test

class rsa_testTests: XCTestCase {
    var public_key: Data = Data()
    
    override func setUp() {
        let filepath = Bundle.main.path(forResource: "public_key", ofType: "pem")
        let pemData = try! String(contentsOfFile: filepath!)
        self.public_key = try! SwKeyConvert.PublicKey.pemToPKCS1DER(pemData)
    }

    func testEnc() {
        let expectString = "hello ios rsa"
        guard let data = expectString.data(using: .utf8) else {
            return
        }
        
        guard let tag = "label".data(using: .utf8) else {
            return
        }
        
        do {
        let chiperText = try CC.RSA.encrypt(data, derKey: self.public_key, tag: tag, padding: .oaep, digest: .sha256)
            print("chiperText[\(chiperText.base64EncodedString())]")
        } catch {
            XCTAssertNotNil(error)
        }
    }
}
