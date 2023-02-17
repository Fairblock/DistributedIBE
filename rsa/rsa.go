package distIBE

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

type SignedMessage struct {
	signed string
	msg    string
}

func RSA_Encrypt(secretMessage string, key rsa.PublicKey) (string,error) {
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &key, []byte(secretMessage), label)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func RSA_Decrypt(cipherText string, privKey rsa.PrivateKey) (string, error) {
	ct, _ := base64.StdEncoding.DecodeString(cipherText)
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, &privKey, ct, label)
	if err != nil {
		return "", err
	}
	fmt.Println("Plaintext:", string(plaintext))
	return string(plaintext), nil
}

func CheckSig(pk rsa.PublicKey, signedM SignedMessage) (bool, error) {

	msgHash := sha256.New()
	_, err := msgHash.Write([]byte(signedM.msg))
	if err != nil {
		panic(err)
	}
	msgHashSum := msgHash.Sum(nil)
	err = rsa.VerifyPSS(&pk, crypto.SHA256, msgHashSum, []byte(signedM.signed), nil)
	if err != nil {
		return false, err
	}
	return true, nil
}
