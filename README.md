
# はじめに

rsa暗号化についてはいくつかオプションがあります。
特にpaddingアルゴリズムの影響によるオプションです。

前提として選択暗号文攻撃に強いRSA-OAEPに絞った調査を行っています。

# 秘密鍵と公開鍵の準備

以下のコマンドで作成します

```
openssl genrsa 2048 > private_key.pem
openssl rsa -pubout < private_key.pem > public_key.key
```

# Goだけで暗号化、復号化を行う

OAEPについてはいかに情報があります。
https://ja.wikipedia.org/wiki/Optimal_Asymmetric_Encryption_Padding

Goは割と素直な感じで

![oaep](https://upload.wikimedia.org/wikipedia/commons/1/18/Oaep-diagram-20080305.png)

上記の概念図おけるG,Hのハッシュアルゴリズムの指定とrに当たるラベルの指定ができます。


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

上記２つのライブラリについて実際に暗号化と復号化を行ってみます。

## SwiftyRSAの場合

歴史的経緯なのかhashアルゴリズムとラベルの指定をサポートしておらず、
sha1,ラベルは空で固定のようです。

### iOSで暗号化

```swift

import XCTest
import SwiftyRSA

@testable import rsa_test

class rsa_testTests: XCTestCase {
    var publicKey: Data = Data()
    var publicKeyPem: String = ""
    
    override func setUp() {
        let publicKeyPath = Bundle.main.path(forResource: "public_key", ofType: "pem") ?? ""
        self.publicKeyPem = try! String(contentsOfFile: publicKeyPath)
    }
    
    func testEncOAEP_SwiftyRSA() {
        let publicKey = try! PublicKey.publicKeys(pemEncoded: self.publicKeyPem)[0]
        let expectString = "hello ios rsa"
        let clear = try! ClearMessage(string: expectString, using: .utf8)
        let encrypted = try! clear.encrypted(with: publicKey, padding: .OAEP)
        print("SwiftyRSA chiperText[\(encrypted.base64String)]")
    }
    
}

```

出力例はこちら

```
SwiftyRSA chiperText[eCezV7gNUMHWNmS2ayePXIe64b7Rk86Is98/uZgPv1g3JLrQieUArhM1gAaJyZaK7Yf/BOqe8/CQ7O2ybKIZDu3HCbwEPhYjoKpNeXVNaIRdiLJa3onmFM5mQJdU+Zr7cH6GOvmx29ZKR4mC6p8BrRqZnh6s3D/5PcGrKqrgh8X9ry9F1ZYptDf36ZO4YdBNKTYy9mVoYqGFlmmiZWAQvvCufnte+PCr5Gxw6DsADYt1ByiDeron+hZMzK9PPiZup8fquAXdXup+PXqlJIvXFyrCneocrsBY1YA8xTfJlxF/ZHUPNZaSb0QiM6PJj3xsU3vg5ZUT/OcgTYhI7lW5SQ==]
```

### Goで復号

```go
package rsa_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"testing"
)

func TestDecforSwiftyRSA(t *testing.T) {
	base64Text := "lqEicpwE0xPg9iXdn2xSQLeoIEkwvKdxGBMrjwHxW2S5x7IuhrWCnWnFZ1w0nd21nCuZfveW29nCzekvJEBji8W+HcbwQUapIcRoENp6+IkcjISnOR9hR5ZOJBUNP7X0eLniFHuqPXuySWuzGXJIfP2P8iBwFEC0AvUTGUfpXdYEoRP5uEExHBdxw/WywtjocGkgz+sbmBzgCdN+BmAas8h/RdsYI2D83VyvG492Hp45SR+vgoyv4TbqcWZqdPC6T4ZFurQvZKlMKT5Xfhe4WTQUVL1fKvFWGkxXhIesKmxZpvIfKqLF7ZuGs13RJaIDvF6i71fvmF7rN2fvE/iuoA=="
	expectMessage := "hello ios rsa"

	privateKey, err := readRsaPrivateKey("private_key.pem")
	if err != nil {
		t.Errorf("sorry. can't read privatekey err=%s", err.Error())
	}
	rng := rand.Reader

	ciphertext, _ := base64.StdEncoding.DecodeString(base64Text)

	t.Logf("ciphertext = %s", ciphertext)
	// 復号
	plaintext, err := rsa.DecryptOAEP(sha1.New(), rng, privateKey, ciphertext, nil)
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

出力結果

```
$ go test -v  github.com/m0a-mystudy/rsa/go -run ^(TestDecforSwiftyRSA)$
=== RUN   TestDecforSwiftyRSA
--- PASS: TestDecforSwiftyRSA (0.00s)
?��x��{�={�Ik�rH|�� p@��G�]���A1q�����pi ����%ݟl�~`��E�#`��\�v�9I�����6�qfjt�O�E��/d�L)>W~�Y4T�_*�VLW���*lY��*��훆�]�%��^��W�^�7g��
    enc_dec_test.go:37: Plaintext: hello ios rsa
PASS
ok  	github.com/m0a-mystudy/rsa/go	0.015s
```


## SwCryptの場合

```swift

import XCTest
import SwCrypt

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
        
}


```

上記の出力結果抜粋

```
SwCrypt chiperText[N9QE8lG5A9LRRprfwkzAxoldJkNSJqEQ/gLAcNjMFbLgcGu2yffY3x91/DOCApsxtAU3I7GTCnk0TOTV5Y32zVqOE7S+GksCFFa7iDLsqYvQbKJZXcb8bTe4p93SPU+RBkH0r/H8NBTUDSvNtARcXntqWNwr0FNAW2HH/Ht+ZmL1pWMa0MmdXLc/+4S/KFjlip/b5neMw6EoQkfNNDz8i7+IHiIpz+vJ2ZFvpf8RGXLgUTMGdUrQfv+XyLZZAnYny5a8HzuMbEcSunez0G7T25NGj6ubJJ2zalLACV1GysolOAJFn6YD6jSukDGQmHKlL1JOkKhqUm9EZT6Mw7wBkQ==]
```

生成された文字列をGoで復号してみます。
(追加したテストのみ記載します)

```go

func TestDecforSwCrypt(t *testing.T) {
	base64Text := "N9QE8lG5A9LRRprfwkzAxoldJkNSJqEQ/gLAcNjMFbLgcGu2yffY3x91/DOCApsxtAU3I7GTCnk0TOTV5Y32zVqOE7S+GksCFFa7iDLsqYvQbKJZXcb8bTe4p93SPU+RBkH0r/H8NBTUDSvNtARcXntqWNwr0FNAW2HH/Ht+ZmL1pWMa0MmdXLc/+4S/KFjlip/b5neMw6EoQkfNNDz8i7+IHiIpz+vJ2ZFvpf8RGXLgUTMGdUrQfv+XyLZZAnYny5a8HzuMbEcSunez0G7T25NGj6ubJJ2zalLACV1GysolOAJFn6YD6jSukDGQmHKlL1JOkKhqUm9EZT6Mw7wBkQ=="
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





# 最後に

テストとして書いたコードはこちらにおいておきます
https://github.com/m0a-mystudy/rsa





