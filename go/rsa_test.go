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
	"math/big"
	"os"
	"testing"
)

var test2048Key *rsa.PrivateKey

func fromBase10(base10 string) *big.Int {
	i, ok := new(big.Int).SetString(base10, 10)
	if !ok {
		panic("bad number: " + base10)
	}
	return i
}

func init() {
	test2048Key = &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: fromBase10("14314132931241006650998084889274020608918049032671858325988396851334124245188214251956198731333464217832226406088020736932173064754214329009979944037640912127943488972644697423190955557435910767690712778463524983667852819010259499695177313115447116110358524558307947613422897787329221478860907963827160223559690523660574329011927531289655711860504630573766609239332569210831325633840174683944553667352219670930408593321661375473885147973879086994006440025257225431977751512374815915392249179976902953721486040787792801849818254465486633791826766873076617116727073077821584676715609985777563958286637185868165868520557"),
			E: 3,
		},
		D: fromBase10("9542755287494004433998723259516013739278699355114572217325597900889416163458809501304132487555642811888150937392013824621448709836142886006653296025093941418628992648429798282127303704957273845127141852309016655778568546006839666463451542076964744073572349705538631742281931858219480985907271975884773482372966847639853897890615456605598071088189838676728836833012254065983259638538107719766738032720239892094196108713378822882383694456030043492571063441943847195939549773271694647657549658603365629458610273821292232646334717612674519997533901052790334279661754176490593041941863932308687197618671528035670452762731"),
		Primes: []*big.Int{
			fromBase10("130903255182996722426771613606077755295583329135067340152947172868415809027537376306193179624298874215608270802054347609836776473930072411958753044562214537013874103802006369634761074377213995983876788718033850153719421695468704276694983032644416930879093914927146648402139231293035971427838068945045019075433"),
			fromBase10("109348945610485453577574767652527472924289229538286649661240938988020367005475727988253438647560958573506159449538793540472829815903949343191091817779240101054552748665267574271163617694640513549693841337820602726596756351006149518830932261246698766355347898158548465400674856021497190430791824869615170301029"),
		},
	}
	test2048Key.Precompute()
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

	test2048Key = ReadRsaPrivateKey("-----BEGIN RSA PRIVATE KEY-----\nMIIEjgIBAAKB/gC8H1ERLRU7Xv0q6K+W8uq2DIXG/EkN7L1TOTTi/elkmmGGPfwV\npErFyQpwToTEJHX3Lt2/deGKOZy4CRqCCWXZj3rIx5i9JqA9H1lNHdpCS0AhbeiG\neh+3DT0W5K8g9EmFAZLbzrst7Su/M2WqDkReDXmHAEUa1GUP+vrnMLcituKB6dCS\n4mJzwEKzFLy1hvAZyF6pmGGJ+7Lh95ol3PLywrTS666xiGjbYZydykp607J4eDtV\nupDIOVnzRjZ7m/xxTUECRDsaGOu0/l1CrD/zZO1u5Dh+t9ELSHOkHalk/cYvuWW1\nrRUs7UBCtaWJaRSX9ovs9nwCYiwapaqnAgMBAAECgf1BTC17ZMal4QbHShUItDC8\nGASnWRKSfsYIiSbOU4wbm2qWihVh/bDmji3NZbO30WAQ+HeH6Ybrz6uSRbapxFFR\n/veDkaR2o12jWapJlj8YG76a2+eGJgW0KCg4NhCDw8dxH2a2XT+jZVt19oUnTeR1\nMQAp1/Ikqeyaa2eDr+kXzkmpXgjroQBQGnmSxGnEWDQcAm3Uf45QXZhoNQ/8wakH\nHooC0QuUwCyQJVMQa61UZ2SbqyIX3XDsORja0hyNeJtABNxxvZQGFZIpRx4va/JO\ne+4ru3PglFPGGKp/I1G/4vYcDq62BhxP+LoQIlvP5Nd7nPlGPzLBgRaaXoDBAn8P\nk8+RNShdeRELETC5RZIOnF+LOXE2Pwq0r1xYSqqT0ArShTGLlymHiKMUWOTklbJ6\nKqHJI5kV639ASVurDipU7+O2XNMbiCCYvpdC/S2Bjda0cJhn/CxZqgdkyVTlqN6l\nx1r15zpafHcXaHyM7U5TnfND2xQW8gkd3YMK133/An8ME54KUpa5X6P0MuZusNIN\n1+Dcc1uRt+3QcAa0vQEEDgMUxC9PfQ05WhpP27YsXir5uFBYuYmXo2UmaZEIIRjO\nEd4GEWAB5qr2SKLf06MwarEnBrxilWeGVC/lpcgAm5W6bthaZyM+3cODV+geE9TS\nTZcsLITPH/EPx4GifyNZAn8HlGOug1Al03AAk5fCvuBn7Zzr8MJuo9RAwQdNCt/f\nVp69ewP1qVMS2OCJWQvfUhvrJ+1bItAtg06C6G8LV7Qvah7CMH6kaeN6j1qoxOqs\nnGi5mgP+rQyjgIFigDioGzhjMBLJjn6tYtzL7hKUvC+drkCdZu9qjtDy0EMgNmTf\nAn8BLcUGYutdas15H6LIeS/3s/O58PSmM5rd9qFg8PXxbGC2nTO1AZLR306kLuEI\nUaTGPUxybKHWkFdmOXWzom9mZe4TD40cgmR7p7lmOaU7K57hHVI0GTtCrGMEensc\nPBOQYBN0N48EKudTobgBf5QNdw9je3D3Ornv/VxU/S35An8KK/4ZNPo8pKv74zTy\nX30cdEekJBbnvWo8U36bqsl0hakwZt1Fy2bZWkhtnnMJOp0bEiYZ4StJA/utpSfL\nWI69zLkP4jlVhT/IIbojnrr6oP2D7sYWMI4NQGERkfo8rfF1s+CDPM0Fs2E4fjVd\n0ynBi0pujO+xJ5HbvEmMscQA\n-----END RSA PRIVATE KEY-----\n")

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
