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
