package rsa_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
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

func TestOAEP(t *testing.T) {
	secretMessage := []byte("send reinforcements, we're going to advance")
	label := []byte("orders")

	// crypto/rand.Reader is a good source of entropy for randomizing the
	// encryption function.
	rng := rand.Reader

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &test2048Key.PublicKey, secretMessage, label)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from encryption: %s\n", err)
		return
	}

	encodedStr := hex.EncodeToString(ciphertext)
	t.Errorf("encode str = %s", encodedStr)
	chiper, _ := hex.DecodeString(encodedStr)

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, test2048Key, chiper, label)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from decryption: %s\n", err)
		return
	}

	t.Errorf("Plaintext: %s\n", string(plaintext))

	pemPrivateBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(test2048Key),
	}

	pemPublicBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&test2048Key.PublicKey),
	}

	pemPrivateFile, err := os.Create("private_key.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	err = pem.Encode(pemPrivateFile, pemPrivateBlock)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	pemPrivateFile.Close()

	pemPublicFile, err := os.Create("public_key.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	err = pem.Encode(pemPublicFile, pemPublicBlock)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	pemPublicFile.Close()
}

// func TestEncOAEP(t *testing.T) {
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

// 	// Since encryption is a randomized function, ciphertext will be
// 	// different each time.
// 	// t.Lo("Ciphertext: %x\n", ciphertext)
// 	t.Errorf("ciphertext =  %x", ciphertext)
// }

// func TestDevOAEP(t *testing.T) {
// 	ciphertext, _ := hex.DecodeString("4d1ee10e8f286390258c51a5e80802844c3e6358ad6690b7285218a7c7ed7fc3a4c7b950fbd04d4b0239cc060dcc7065ca6f84c1756deb71ca5685cadbb82be025e16449b905c568a19c088a1abfad54bf7ecc67a7df39943ec511091a34c0f2348d04e058fcff4d55644de3cd1d580791d4524b92f3e91695582e6e340a1c50b6c6d78e80b4e42c5b4d45e479b492de42bbd39cc642ebb80226bb5200020d501b24a37bcc2ec7f34e596b4fd6b063de4858dbf5a4e3dd18e262eda0ec2d19dbd8e890d672b63d368768360b20c0b6b8592a438fa275e5fa7f60bef0dd39673fd3989cc54d2cb80c08fcd19dacbc265ee1c6014616b0e04ea0328c2a04e73460")
// 	label := []byte("orders")

// 	// crypto/rand.Reader is a good source of entropy for blinding the RSA
// 	// operation.
// 	rng := rand.Reader

// 	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, test2048Key, ciphertext, label)
// 	if err != nil {
// 		fmt.Fprintf(os.Stderr, "Error from decryption: %s\n", err)
// 		return
// 	}

// 	t.Errorf("Plaintext: %s\n", string(plaintext))

// 	// Remember that encryption only provides confidentiality. The
// 	// ciphertext should be signed before authenticity is assumed and, even
// 	// then, consider that messages might be reordered.
// }
