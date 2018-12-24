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
