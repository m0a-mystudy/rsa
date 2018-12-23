package rsa_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"testing"
)

var test2048Key *rsa.PrivateKey
var test4096Key *rsa.PrivateKey

func init() {
	test2048Key = ReadRsaPrivateKey("-----BEGIN RSA PRIVATE KEY-----\nMIIEjgIBAAKB/gC8H1ERLRU7Xv0q6K+W8uq2DIXG/EkN7L1TOTTi/elkmmGGPfwV\npErFyQpwToTEJHX3Lt2/deGKOZy4CRqCCWXZj3rIx5i9JqA9H1lNHdpCS0AhbeiG\neh+3DT0W5K8g9EmFAZLbzrst7Su/M2WqDkReDXmHAEUa1GUP+vrnMLcituKB6dCS\n4mJzwEKzFLy1hvAZyF6pmGGJ+7Lh95ol3PLywrTS666xiGjbYZydykp607J4eDtV\nupDIOVnzRjZ7m/xxTUECRDsaGOu0/l1CrD/zZO1u5Dh+t9ELSHOkHalk/cYvuWW1\nrRUs7UBCtaWJaRSX9ovs9nwCYiwapaqnAgMBAAECgf1BTC17ZMal4QbHShUItDC8\nGASnWRKSfsYIiSbOU4wbm2qWihVh/bDmji3NZbO30WAQ+HeH6Ybrz6uSRbapxFFR\n/veDkaR2o12jWapJlj8YG76a2+eGJgW0KCg4NhCDw8dxH2a2XT+jZVt19oUnTeR1\nMQAp1/Ikqeyaa2eDr+kXzkmpXgjroQBQGnmSxGnEWDQcAm3Uf45QXZhoNQ/8wakH\nHooC0QuUwCyQJVMQa61UZ2SbqyIX3XDsORja0hyNeJtABNxxvZQGFZIpRx4va/JO\ne+4ru3PglFPGGKp/I1G/4vYcDq62BhxP+LoQIlvP5Nd7nPlGPzLBgRaaXoDBAn8P\nk8+RNShdeRELETC5RZIOnF+LOXE2Pwq0r1xYSqqT0ArShTGLlymHiKMUWOTklbJ6\nKqHJI5kV639ASVurDipU7+O2XNMbiCCYvpdC/S2Bjda0cJhn/CxZqgdkyVTlqN6l\nx1r15zpafHcXaHyM7U5TnfND2xQW8gkd3YMK133/An8ME54KUpa5X6P0MuZusNIN\n1+Dcc1uRt+3QcAa0vQEEDgMUxC9PfQ05WhpP27YsXir5uFBYuYmXo2UmaZEIIRjO\nEd4GEWAB5qr2SKLf06MwarEnBrxilWeGVC/lpcgAm5W6bthaZyM+3cODV+geE9TS\nTZcsLITPH/EPx4GifyNZAn8HlGOug1Al03AAk5fCvuBn7Zzr8MJuo9RAwQdNCt/f\nVp69ewP1qVMS2OCJWQvfUhvrJ+1bItAtg06C6G8LV7Qvah7CMH6kaeN6j1qoxOqs\nnGi5mgP+rQyjgIFigDioGzhjMBLJjn6tYtzL7hKUvC+drkCdZu9qjtDy0EMgNmTf\nAn8BLcUGYutdas15H6LIeS/3s/O58PSmM5rd9qFg8PXxbGC2nTO1AZLR306kLuEI\nUaTGPUxybKHWkFdmOXWzom9mZe4TD40cgmR7p7lmOaU7K57hHVI0GTtCrGMEensc\nPBOQYBN0N48EKudTobgBf5QNdw9je3D3Ornv/VxU/S35An8KK/4ZNPo8pKv74zTy\nX30cdEekJBbnvWo8U36bqsl0hakwZt1Fy2bZWkhtnnMJOp0bEiYZ4StJA/utpSfL\nWI69zLkP4jlVhT/IIbojnrr6oP2D7sYWMI4NQGERkfo8rfF1s+CDPM0Fs2E4fjVd\n0ynBi0pujO+xJ5HbvEmMscQA\n-----END RSA PRIVATE KEY-----\n")
	test4096Key = ReadRsaPrivateKey("-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----\n")
}

func ReadRsaPrivateKey(privateKey string) *rsa.PrivateKey {

	// decode pem
	block, _ := pem.Decode([]byte(privateKey))

	if block == nil || block.Type != "RSA PRIVATE KEY" {
		// c.Logger().Warnf("failed to invalid pem decode. block nil or Not [RSA PRIVATE KEY] type.")
		return nil
	}

	// get key
	var key *rsa.PrivateKey
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// c.Logger().Warnf("failed to parse block bytes as private key. :%s", err.Error())
		return nil
	}

	key.Precompute()

	if err := key.Validate(); err != nil {
		// c.Logger().Warnf("failed to validate performs basic sanity checks on the private key. :%s", err.Error())
		return nil
	}

	return key
}

func TestPKCSEncryptFromiOS(t *testing.T) {
	base64Text := `EsDPfbEHJ+mkLZFrs5cwcFSkDTDGA6bXGU0oTE902dzjwyXXNQMMJ/JB9ZHkrg3ARROnSsMa4ar1N8QAWcP7iTN5gfoFCjc4wduMPpZSKUF3Xw2edE1tuN4iRDJBtS2g8TbpPnZOgn0friczL7Zw4N6OVkIAWyPVTXiyCXtA8xEPMS3aURR0cp/H7Snet3b7SpcfqMOBVo3pB6eoPLy3i1V7bAu5lcwZ14pDao9l87AoezqVXJK0Eg48XbMVXwVD/tmJHKsZUnqKUAgVo0yFLuAwaLZuW3mx5Y7EuFjaTfExST3MhaM1fL+HMCQNlI5XjFIDpXExBQ3DsL/6Ww==`
	expectPlainText := `{"access_token":"abc123"}`

	chiper, _ := base64.StdEncoding.DecodeString(base64Text)
	rng := rand.Reader

	t.Logf("hexString=%s", hex.EncodeToString(chiper))
	plaintext, err := rsa.DecryptPKCS1v15(rng, test2048Key, chiper)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from decryption: %s\n", err)
		t.Fatal()
	}

	if string(plaintext) != expectPlainText {
		t.Fatalf("expect %s but %s", expectPlainText, string(plaintext))
	}
}

func TestOAEPEncryptFromiOS(t *testing.T) {
	test2048Key = ReadRsaPrivateKey("-----BEGIN RSA PRIVATE KEY-----\nMIIEjgIBAAKB/gC8H1ERLRU7Xv0q6K+W8uq2DIXG/EkN7L1TOTTi/elkmmGGPfwV\npErFyQpwToTEJHX3Lt2/deGKOZy4CRqCCWXZj3rIx5i9JqA9H1lNHdpCS0AhbeiG\neh+3DT0W5K8g9EmFAZLbzrst7Su/M2WqDkReDXmHAEUa1GUP+vrnMLcituKB6dCS\n4mJzwEKzFLy1hvAZyF6pmGGJ+7Lh95ol3PLywrTS666xiGjbYZydykp607J4eDtV\nupDIOVnzRjZ7m/xxTUECRDsaGOu0/l1CrD/zZO1u5Dh+t9ELSHOkHalk/cYvuWW1\nrRUs7UBCtaWJaRSX9ovs9nwCYiwapaqnAgMBAAECgf1BTC17ZMal4QbHShUItDC8\nGASnWRKSfsYIiSbOU4wbm2qWihVh/bDmji3NZbO30WAQ+HeH6Ybrz6uSRbapxFFR\n/veDkaR2o12jWapJlj8YG76a2+eGJgW0KCg4NhCDw8dxH2a2XT+jZVt19oUnTeR1\nMQAp1/Ikqeyaa2eDr+kXzkmpXgjroQBQGnmSxGnEWDQcAm3Uf45QXZhoNQ/8wakH\nHooC0QuUwCyQJVMQa61UZ2SbqyIX3XDsORja0hyNeJtABNxxvZQGFZIpRx4va/JO\ne+4ru3PglFPGGKp/I1G/4vYcDq62BhxP+LoQIlvP5Nd7nPlGPzLBgRaaXoDBAn8P\nk8+RNShdeRELETC5RZIOnF+LOXE2Pwq0r1xYSqqT0ArShTGLlymHiKMUWOTklbJ6\nKqHJI5kV639ASVurDipU7+O2XNMbiCCYvpdC/S2Bjda0cJhn/CxZqgdkyVTlqN6l\nx1r15zpafHcXaHyM7U5TnfND2xQW8gkd3YMK133/An8ME54KUpa5X6P0MuZusNIN\n1+Dcc1uRt+3QcAa0vQEEDgMUxC9PfQ05WhpP27YsXir5uFBYuYmXo2UmaZEIIRjO\nEd4GEWAB5qr2SKLf06MwarEnBrxilWeGVC/lpcgAm5W6bthaZyM+3cODV+geE9TS\nTZcsLITPH/EPx4GifyNZAn8HlGOug1Al03AAk5fCvuBn7Zzr8MJuo9RAwQdNCt/f\nVp69ewP1qVMS2OCJWQvfUhvrJ+1bItAtg06C6G8LV7Qvah7CMH6kaeN6j1qoxOqs\nnGi5mgP+rQyjgIFigDioGzhjMBLJjn6tYtzL7hKUvC+drkCdZu9qjtDy0EMgNmTf\nAn8BLcUGYutdas15H6LIeS/3s/O58PSmM5rd9qFg8PXxbGC2nTO1AZLR306kLuEI\nUaTGPUxybKHWkFdmOXWzom9mZe4TD40cgmR7p7lmOaU7K57hHVI0GTtCrGMEensc\nPBOQYBN0N48EKudTobgBf5QNdw9je3D3Ornv/VxU/S35An8KK/4ZNPo8pKv74zTy\nX30cdEekJBbnvWo8U36bqsl0hakwZt1Fy2bZWkhtnnMJOp0bEiYZ4StJA/utpSfL\nWI69zLkP4jlVhT/IIbojnrr6oP2D7sYWMI4NQGERkfo8rfF1s+CDPM0Fs2E4fjVd\n0ynBi0pujO+xJ5HbvEmMscQA\n-----END RSA PRIVATE KEY-----\n")
	base64Text := "s1BdNQTTtb1Bgt4APmCAOHjNNu7kGVT+Dw2/i8rYj8UUZqChxaOXp0UZewpimdfvvJLuuiM+i+PUN61hfcESTlsiHvixRLJ5Vrt9lfVZlDscqE3z/F5w9osjZIyKZkDvicyiNENqJcoB5xJ34efiD6lBawTJjeGxUZ0w7E6SILBUM+WAvAW0+3oyFtGtJl0s/SGc4Kiu2m+5uIZY5eJkRYIhzd4VvcmEBbdWJ10FW6+UxvfJ4dkVhwBC6VB0GN+D1/CuwSHDuxvpAm7e7AEntFZrmcsob28AHckwZO6bAHRaZDG5uBsXc76jhX8y+7g181jHQIJh9ikJHdpwzw=="
	expectPlainText := "hello rsa"
	label := []byte("")

	chiper, _ := base64.StdEncoding.DecodeString(base64Text)
	rng := rand.Reader

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, test2048Key, chiper, label)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from decryption: %s\n", err)
		t.Fatal()
	}

	t.Logf("Plaintext: %s\n", string(plaintext))

	if string(plaintext) != expectPlainText {
		t.Fatalf("expect %s but %s", expectPlainText, string(plaintext))
	}
}

// func TestEncriptndDecript(t *testing.T) {
// 	secretMessage := []byte(`{"access_token":"EAAgkUFrhPQkBACPY3MVmWaHGZAItdPxeUVdzapPoF2PvP1lgoPa1NjJYYt87s9wDtku9q7CmOeagGQDMzGTBxMT6uaKUPsGDTHdri1TcCfZAp1xnOp0fZCTbzv8S0ZBTs38lLwvWAjRbW8HxQi0yAPNHiGjnPoLIMqdTYabWoan9lVvzMgZCGPYu50ciRMuMoNYtpkUBOnxKOkZC7WkIcXcuXkPSCs13ocRLe2f3ZB7ts0V5l1tjW0k"}`)
// 	label := []byte("orders")

// 	// crypto/rand.Reader is a good source of entropy for randomizing the
// 	// encryption function.
// 	rng := rand.Reader

// 	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &test4096Key.PublicKey, secretMessage, label)
// 	if err != nil {
// 		t.Errorf("Error from encryption: %s\n", err)
// 		return
// 	}

// 	encodedStr := hex.EncodeToString(ciphertext)
// 	// t.Logf("encode str = %s", encodedStr)
// 	chiper, _ := hex.DecodeString(encodedStr)

// 	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, test4096Key, chiper, label)
// 	if err != nil {
// 		t.Errorf("Error from decryption: %s\n", err)
// 		return
// 	}

// 	t.Logf("Plaintext: %s\n", string(plaintext))

// 	t.Fail()

// }

// func TestOAEP(t *testing.T) {
// 	secretMessage := []byte("send reinforcements, we're going to advance")
// 	label := []byte("orders")

// 	// crypto/rand.Reader is a good source of entropy for randomizing the
// 	// encryption function.
// 	rng := rand.Reader

// 	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &test2048Key.PublicKey, secretMessage, label)
// 	if err != nil {
// 		fmt.Fprintf(os.Stderr, "Error from encryption: %s\n", err)
// 		return
// 	}

// 	encodedStr := hex.EncodeToString(ciphertext)
// 	t.Errorf("encode str = %s", encodedStr)
// 	chiper, _ := hex.DecodeString(encodedStr)

// 	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, test2048Key, chiper, label)
// 	if err != nil {
// 		fmt.Fprintf(os.Stderr, "Error from decryption: %s\n", err)
// 		return
// 	}

// 	t.Errorf("Plaintext: %s\n", string(plaintext))

// 	pemPrivateBlock := &pem.Block{
// 		Type:  "RSA PRIVATE KEY",
// 		Bytes: x509.MarshalPKCS1PrivateKey(test2048Key),
// 	}

// 	pemPublicBlock := &pem.Block{
// 		Type:  "RSA PUBLIC KEY",
// 		Bytes: x509.MarshalPKCS1PublicKey(&test2048Key.PublicKey),
// 	}

// 	pemPrivateFile, err := os.Create("private_key.pem")
// 	if err != nil {
// 		fmt.Println(err)
// 		os.Exit(1)
// 	}
// 	err = pem.Encode(pemPrivateFile, pemPrivateBlock)
// 	if err != nil {
// 		fmt.Println(err)
// 		os.Exit(1)
// 	}
// 	pemPrivateFile.Close()

// 	pemPublicFile, err := os.Create("public_key.pem")
// 	if err != nil {
// 		fmt.Println(err)
// 		os.Exit(1)
// 	}
// 	err = pem.Encode(pemPublicFile, pemPublicBlock)
// 	if err != nil {
// 		fmt.Println(err)
// 		os.Exit(1)
// 	}
// 	pemPublicFile.Close()
// }
