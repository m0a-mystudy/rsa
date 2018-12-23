# rsa

Goで暗号化と復号を行うことは至って簡単ですが
iOSとGoで暗号化と復号をおこった場合、なかなかスムーズに行きませんでした。

クライアント: iOS
サーバサイド: Go

# 秘密鍵と公開鍵の準備

以下のコマンドで作成します

```
openssl genrsa 2048 > private_key.pem
openssl rsa -pubout < private_key.pem > public_key.key
```

# Goだけで暗号化、復号化を行う



RSA暗号化と言っても一言で言ってPrivateKeyのビット数やpaddingアルゴリズムの指定など
細かなオプションがあります。

今回はPrivateKeyのビット数は2048,ハッシュ関数はSHA256
paddingアルゴリズムはOAEPを使います。


```go

package rsa_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"testing"
)

func TestEncDec(t *testing.T) {
	privateKey, err := readRsaPrivateKey("private_key.pem")
	if err != nil {
		t.Errorf("sorry. can't read privatekey err=%s", err.Error())
	}

	expectMessage := "hello rsa"
	secretMessage := []byte(expectMessage)
	label := []byte("label")

	t.Logf("secretMessage = %s", secretMessage)

	// crypto/rand.Reader is a good source of entropy for randomizing the
	// encryption function.
	rng := rand.Reader

	// 暗号化
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &privateKey.PublicKey, secretMessage, label)
	if err != nil {
		t.Errorf("Error from encryption: %s\n", err)
		return
	}

	t.Logf("ciphertext = %s", ciphertext)
	// 復号
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, privateKey, ciphertext, label)
	if err != nil {
		t.Errorf("Error from decryption: %s\n", err)
		return
	}

	t.Logf("Plaintext: %s\n", string(plaintext))

	if expectMessage != string(plaintext) {
		t.Fatalf("expect %s, but %s", expectMessage, string(plaintext))
	}

}

func readRsaPrivateKey(pemFile string) (*rsa.PrivateKey, error) {
	bytes, err := ioutil.ReadFile(pemFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, errors.New("invalid private key data")
	}

	var key *rsa.PrivateKey
	if block.Type == "RSA PRIVATE KEY" {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	} else if block.Type == "PRIVATE KEY" {
		keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		var ok bool
		key, ok = keyInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not RSA private key")
		}
	} else {
		return nil, fmt.Errorf("invalid private key type : %s", block.Type)
	}

	key.Precompute()

	if err := key.Validate(); err != nil {
		return nil, err
	}

	return key, nil
}


```

参考:
http://increment.hatenablog.com/entry/2017/08/25/223915


実行結果はこんな感じです

```
$ go test -v -timeout 30s github.com/m0a-mystudy/rsa/go -run ^(TestEncDec)$

=== RUN   TestEncDec
--- PASS: TestEncDec (0.00s)
    enc_dec_test.go:25: secretMessage = hello rsa
    enc_dec_test.go:38: ciphertext = ����*����η
                                               �K�*>�V�>'���X''n�O
                                                                  �Lj�91%v:���+A��n�Jʿ�ՠ�[=�o
                                                                                             @@AL:�fR9�(K���
                                                                                                            a�ӄ�_�g�V!��ʠ�~Tk=��^�Ho׌�
                                                                                                                                      3V����j�]���f�I��v�-,�a�@:�ׯ���L���[�����C0��	�XK����5�\J.�Ш�x�
                                                         rsPjA!O
Oꂕ8��E"��Z�v��S�/��i�5pgU�c
    enc_dec_test.go:46: Plaintext: hello rsa
PASS
ok  	github.com/m0a-mystudy/rsa/go	(cached)
```

なんの問題もなく暗号化と復号が成功しています。まぁ当たり前です。
では暗号化の部分をiOSに担当していただきましょう。


# iOSで暗号化

現在rsa暗号化をサポートしているライブラリはgithubで探しますがめぼしいのは２つほどです。

* [TakeScoop/SwiftyRSA](https://github.com/TakeScoop/SwiftyRSA) 601 star
* [soyersoyer/SwCrypt](https://github.com/soyersoyer/SwCrypt) 483 star

参考:https://github.com/topics/rsa

自分は何も考えず601 starのSwiftyRSAを最初に採用してしまいました。全てはこれが良くなかった。
結論から言ってSwCryptを選んでおけばいろいろ検証にハマることもなかったですのに。


* SwCryptの実行例

```swift

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
            // 暗号化
            let chiperText = try CC.RSA.encrypt(data, derKey: self.public_key, tag: tag, padding: .oaep, digest: .sha256)
            print("chiperText[\(chiperText.base64EncodedString())]")
        } catch {
            XCTAssertNotNil(error)
        }
    }
}

```

上記の出力結果抜粋

```
Test Case '-[rsa_testTests.rsa_testTests testEnc]' started.
chiperText[BBQQRNm9c+magYbq3eXN7ydzdCKSOGy1FmjHIwT2PzLTHnJbZ65f83RY3N8/iyNhBB+RSe9SjXZYz8qIr529bTSyUSmcxeK5Etsc8wsGLLwXkbdcLrYImiU0YC6ymIKAzxeJT9ObMMcopdsUYrxe2laVg6Wio+29RLs1WWaELJvWml2rkMX/uWEm9VpWqcwiBZmBT9GyrR8C71yOr5dtsuxMIIOJlhqq7S2FYRix3GStZyHRXnOBY+hob9+XFVXDMtVkibi8Sx5wK3asD0zrniz2o0DX7GDkZvDbqj45zi16kXv8ZpxIl9jH343NfV8YX7g/rbmI6P/rB6AUjjb7gQ==]
```

生成された文字列をGoで復号してみます。
(追加したテストのみ記載します)

```go

package rsa_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"testing"
)

func TestDecforiOS(t *testing.T) {
	base64Text := "BBQQRNm9c+magYbq3eXN7ydzdCKSOGy1FmjHIwT2PzLTHnJbZ65f83RY3N8/iyNhBB+RSe9SjXZYz8qIr529bTSyUSmcxeK5Etsc8wsGLLwXkbdcLrYImiU0YC6ymIKAzxeJT9ObMMcopdsUYrxe2laVg6Wio+29RLs1WWaELJvWml2rkMX/uWEm9VpWqcwiBZmBT9GyrR8C71yOr5dtsuxMIIOJlhqq7S2FYRix3GStZyHRXnOBY+hob9+XFVXDMtVkibi8Sx5wK3asD0zrniz2o0DX7GDkZvDbqj45zi16kXv8ZpxIl9jH343NfV8YX7g/rbmI6P/rB6AUjjb7gQ=="
	expectMessage := "hello ios rsa"

	privateKey, err := readRsaPrivateKey("private_key.pem")
	if err != nil {
		t.Errorf("sorry. can't read privatekey err=%s", err.Error())
	}
	rng := rand.Reader
	label := []byte("label")

	ciphertext, _ := base64.StdEncoding.DecodeString(base64Text)

	t.Logf("ciphertext = %s", ciphertext)
	// 復号
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, privateKey, ciphertext, label)
	if err != nil {
		t.Errorf("Error from decryption: %s\n", err)
		return
	}

	t.Logf("Plaintext: %s\n", string(plaintext))

	if expectMessage != string(plaintext) {
		t.Fatalf("expect %s, but %s", expectMessage, string(plaintext))
	}

}

```

出力結果

```
$ go test -v  github.com/m0a-mystudy/rsa/go -run ^(TestDecforiOS)$

=== RUN   TestDecforiOS
--- PASS: TestDecforiOS (0.00s)
    enc_dec_test.go:29: ciphertext = Dٽs隁������'st"�8l�h�#�?2�r[g�_�tX��?�#a�I�R�vX�ʈ���m4�Q)�����
                                                                                                   ,���\.�%4`.������Oӛ0�(��b�^�V������D�5Yf�,�֚]�����a&�ZV��"��OѲ��\���m��L �����-�a��d�g!�^s�c�hoߗU�2�d���Kp+v�L�,�@��`�f�۪>9�-z�{�f�H���ߍ�}__�?��������6�
    enc_dec_test.go:37: Plaintext: hello ios rsa
PASS
ok  	github.com/m0a-mystudy/rsa/go	0.015s
```

# SwiftyRSAの場合

Goの復号化関数のインターフェースを見てみると

```go

func DecryptOAEP(hash hash.Hash, random io.Reader, priv *PrivateKey, ciphertext []byte, label []byte) ([]byte, error) {
```

* hashアルゴリズムの指定
* privateKey
* 暗号文
* label

といった引数が必要ですがSwiftyRSAの場合

```swift
let publicKey = try PublicKey(pemNamed: "public")
let clear = try ClearMessage(string: "Clear Text", using: .utf8)
// 暗号化
let encrypted = try clear.encrypted(with: publicKey, padding: .PKCS1)
```

*hashアルゴリズムの指定
*label

と言った指定ができないようです。引数パラメータの足りなさから除外を検討すべきでした。

どうももともとappleが提供しているライブラリ自体に上記パラメータを設定する余地が無いようです。

```swift
OSStatus SecKeyEncrypt(
                       SecKeyRef           key,
                       SecPadding          padding,
                       const uint8_t		*plainText,
                       size_t              plainTextLen,
                       uint8_t             *cipherText,
                       size_t              *cipherTextLen)
__OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_2_0);

```



# 結論

Goと組み合わせるならSwCryptを使っておこう




