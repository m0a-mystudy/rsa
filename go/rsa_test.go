package rsa_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
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

func TestPKCSEncryptFromiOS(t *testing.T) {
	base64Text := "Np06HdmfPMT8zpAYH3Xdx9Rb38RSJqg59sK80DyMvgNHxP0O7pkwV2vbyxPs954YXPGSAOerQ/cPKZKnaROUdx3+nZOzkZ64UjRBae6aOegpsdIScQi4cGXUGKQKPCuoDotCZMRYngKdh8AgaQjqcrnEzYVFU9LYyhioNIiEIrdWu/VY8abE6ij8OLGWExHgBI+wxLUvmxu5Waa06aX+GeEhoX/6AjUegkvp/YSZLRftOQaPa98o1YRkH4E77tZeB/2yluzqWadQTQyH7bwhoVW2t94ElVxTrmK93ME4yFVzz87k32LNMUxuzO9VHanaFZjdE8dSRSmgXv4SV2pGhg=="
	expectPlainText := "hello rsa"

	chiper, _ := base64.StdEncoding.DecodeString(base64Text)
	rng := rand.Reader

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
	base64Text := "KeWgyOzzPPGZuPr6p1aKNKnH40HFeYnyuXmLYW3pjwsl30eWHFL9TD0fwkQu9coFvWbfmflvCBwHoM4Qn2uWz/g97v2HRw5tW5PD+rW/y1O3bEbt5TlOnieuY8YUXdbHSwNQAOY4b6nVuGZN4eMZQI4d/6U+CRM9K8U1pYe00im7zZGya1wlxfaNGGE38RIfITilnrYWjVA7fCDa/Uif34wQtT7WPkax+4I0dZM+0THu3pT2StRgvtBoPKIzMyazlFLXyy6xt5vWHsRPEjdZRp51Id8Ll33Uj+3NnpKVRYDlDMRmQuR5LPsEw3HXtPKsZtLmdZU1XqyxOqpGQzwrlA=="
	expectPlainText := "hello rsa"
	label := []byte("")

	chiper, _ := base64.StdEncoding.DecodeString(base64Text)
	rng := rand.Reader

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, test2048Key, chiper, label)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from decryption: %s\n", err)
		t.Fatal()
	}

	t.Errorf("Plaintext: %s\n", string(plaintext))

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
