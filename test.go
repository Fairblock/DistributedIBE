package tlock

import (
	"bytes"
	"crypto/rand"

	"fmt"

	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"

	"math/big"
	"reflect"

	"github.com/drand/kyber/pairing"
)

func H3Tag() []byte {
	return []byte("IBE-H3")
}

func h3(s pairing.Suite, sigma, msg []byte) (kyber.Scalar, error) {
	h3 := s.Hash()

	if _, err := h3.Write(H3Tag()); err != nil {
		return nil, fmt.Errorf("err hashing h3 tag: %v", err)
	}
	if _, err := h3.Write(sigma); err != nil {
		return nil, fmt.Errorf("err hashing sigma: %v", err)
	}
	_, _ = h3.Write(msg)
	hashable, ok := s.G1().Scalar().(kyber.HashableScalar)
	if !ok {
		panic("scalar can't be created from hash")
	}

	h3Reader := bytes.NewReader(h3.Sum(nil))

	return hashable.Hash(s, h3Reader)
}

func bigFromHex(hex string) *big.Int {
	if len(hex) > 1 && hex[:2] == "0x" {
		hex = hex[2:]
	}
	n, _ := new(big.Int).SetString(hex, 16)
	return n
}

// n keepers in total, threshold = t, (t+1) of them participated in decryption
func DistributedIBE(n int, t int, message string, ID string) (bool, error) {

	// Setup
	s := bls.NewBLS12381Suite()
	var secretVal []byte = []byte{187}
	var qBig = bigFromHex("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")
	secret, _ := h3(s, secretVal, []byte("msg"))

	signers := []int{}
	for i := 0; i < n; i++ {
		signers = append(signers, 0)
	}
	j := 0
	for j < t+1 {

		randomVal, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
		if signers[randomVal.Int64()] == 0 {
			signers[randomVal.Int64()] = 1
			j++
		}
	}

	// generating secret shares

	shares, _ := GenerateShares(uint32(n), uint32(t), secret, qBig)

	// Public Key
	PK := s.G1().Point().Mul(secret, s.G1().Point().Base())

	// Generating commitments

	var c []Commitment
	for j := 0; j < n; j++ {
		if signers[j] == 1 {
			c = append(c, Commitment{s.G1().Point().Mul(shares[j].Value, s.G1().Point().Base()), uint32(j + 1)})
		}
	}

	// Encryption
	Cipher, _ := Encrypt(s, PK, []byte(ID), []byte(message))

	// Extracting the keys using shares
	var sk []ExtractedKey
	for k := 0; k < n; k++ {
		if signers[k] == 1 {
			sk = append(sk, Extract(s, shares[k].Value, uint32(k+1), []byte(ID)))
		}
	}

	// Aggregating keys to get the secret key for decryption
	SK, _ := AggregateSK(s,
		sk,
		c, []byte(ID))

	// Decryption
	decrypted, _ := Decrypt(s, SK, Cipher)

	// Verify that the decrypted message matches the original message
	if !reflect.DeepEqual(message, string(decrypted[:])) {
		return false, fmt.Errorf("wrong decrypted message: %s", string(decrypted[:]))
	}
	return true, nil
}

// n keepers in total, threshold = t, (t-1) of them participated in decryption
func DistributedIBEFail(n int, t int, message string, ID string) (bool, error) {

	// Setup
	s := bls.NewBLS12381Suite()
	var secretVal []byte = []byte{187}
	var qBig = bigFromHex("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")
	secret, _ := h3(s, secretVal, []byte("msg"))

	signers := []int{}
	for i := 0; i < n; i++ {
		signers = append(signers, 0)
	}
	j := 0
	for j < t-1 {

		randomVal, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
		if signers[randomVal.Int64()] == 0 {
			signers[randomVal.Int64()] = 1
			j++
		}
	}

	// generating secret shares

	Shares, _ := GenerateShares(uint32(n), uint32(t), secret, qBig)

	// Public Key
	PK := s.G1().Point().Mul(secret, s.G1().Point().Base())

	// Generating commitments

	var c []Commitment
	for j := 0; j < n; j++ {
		if signers[j] == 1 {
			c = append(c, Commitment{s.G1().Point().Mul(Shares[j].Value, s.G1().Point().Base()), uint32(j + 1)})
		}
	}

	// Encryption
	Cipher, _ := Encrypt(s, PK, []byte(ID), []byte(message))

	// Extracting the keys using shares
	var sk []ExtractedKey
	for k := 0; k < n; k++ {
		if signers[k] == 1 {
			sk = append(sk, Extract(s, Shares[k].Value, uint32(k+1), []byte(ID)))
		}
	}

	// Aggregating keys to get the secret key for decryption
	SK, _ := AggregateSK(s,
		sk,
		c, []byte(ID))

	// Decryption
	decrypted, err := Decrypt(s, SK, Cipher)
	if err != nil {
		return false, err
	}
	// Verify that the decrypted message matches the original message
	if !reflect.DeepEqual(message, string(decrypted[:])) {
		return false, fmt.Errorf(string(decrypted[:]))
	}
	return true, nil
}

// n keepers in total, threshold = t, (t+1) of them participated in decryption but one commitment is wrong
func DistributedIBEFInvalidCommitment(n int, t int, message string, ID string) (bool, error) {

	// Setup
	s := bls.NewBLS12381Suite()
	var secretVal []byte = []byte{187}
	var qBig = bigFromHex("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")
	secret, _ := h3(s, secretVal, []byte("msg"))

	signers := []int{}
	for i := 0; i < n; i++ {
		signers = append(signers, 0)
	}
	j := 0
	for j < t+1 {

		randomVal, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
		if signers[randomVal.Int64()] == 0 {
			signers[randomVal.Int64()] = 1
			j++
		}
	}

	// generating secret shares

	shares, _ := GenerateShares(uint32(n), uint32(t), secret, qBig)

	// Public Key
	PK := s.G1().Point().Mul(secret, s.G1().Point().Base())

	// Generating commitments

	var c []Commitment
	for j := 0; j < n; j++ {
		if signers[j] == 1 {
			c = append(c, Commitment{s.G1().Point().Mul(shares[j].Value, s.G1().Point().Base()), uint32(j + 1)})
		}
	}

	// Encryption
	Cipher, err := Encrypt(s, PK, []byte(ID), []byte(message))
	if err != nil {
		return false,err
	}
	// Extracting the keys using shares
	var sk []ExtractedKey
	for k := 0; k < n; k++ {
		if signers[k] == 1 {
			sk = append(sk, Extract(s, shares[k].Value, uint32(k+1), []byte(ID)))
		}
	}
	// chaning the first commitment to something else
	c[0] = c[1]
	// Aggregating keys to get the secret key for decryption
	SK,invalids := AggregateSK(s,
		sk,
		c, []byte(ID))
	if len(invalids) != 0{
		return false, fmt.Errorf("invalids: %d",invalids)
	}
	// Decryption
	decrypted, errDecrypt := Decrypt(s, SK, Cipher)
	if errDecrypt != nil {
		return false,errDecrypt
	}
	// Verify that the decrypted message matches the original message
	if !reflect.DeepEqual(message, string(decrypted[:])) {
		return false, fmt.Errorf("wrong decrypted message: %s", string(decrypted[:]))
	}
	return true, nil
}

// n keepers in total, threshold = t, (t+1) of them participated in decryption but one share is wrong
func DistributedIBEFInvalidShare(n int, t int, message string, ID string) (bool, error) {

	// Setup
	s := bls.NewBLS12381Suite()
	var secretVal []byte = []byte{187}
	var qBig = bigFromHex("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")
	secret, _ := h3(s, secretVal, []byte("msg"))

	signers := []int{}
	for i := 0; i < n; i++ {
		signers = append(signers, 0)
	}
	j := 0
	for j < t+1 {

		randomVal, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
		if signers[randomVal.Int64()] == 0 {
			signers[randomVal.Int64()] = 1
			j++
		}
	}

	// generating secret shares

	shares, _ := GenerateShares(uint32(n), uint32(t), secret, qBig)
	
	// Public Key
	PK := s.G1().Point().Mul(secret, s.G1().Point().Base())

	// Generating commitments

	var c []Commitment
	for j := 0; j < n; j++ {
		if signers[j] == 1 {
			c = append(c, Commitment{s.G1().Point().Mul(shares[j].Value, s.G1().Point().Base()), uint32(j + 1)})
		}
	}

	// Encryption
	Cipher, err := Encrypt(s, PK, []byte(ID), []byte(message))
	if err != nil {
		return false,err
	}
	// Extracting the keys using shares
	var sk []ExtractedKey
	for k := 0; k < n; k++ {
		if signers[k] == 1 {
			sk = append(sk, Extract(s, shares[k].Value, uint32(k+1), []byte(ID)))
		}
	}
	// chaning the first extracted key to something else (previous value * 2 in this case)
	sk[0].sk = sk[0].sk.Add(sk[0].sk,sk[0].sk)

	// Aggregating keys to get the secret key for decryption
	SK,invalids := AggregateSK(s,
		sk,
		c, []byte(ID))
	if len(invalids) != 0{
		return false, fmt.Errorf("invalids: %d",invalids)
	}
	// Decryption
	decrypted, errDecrypt := Decrypt(s, SK, Cipher)
	if errDecrypt != nil {
		return false,errDecrypt
	}
	// Verify that the decrypted message matches the original message
	if !reflect.DeepEqual(message, string(decrypted[:])) {
		return false, fmt.Errorf("wrong decrypted message: %s", string(decrypted[:]))
	}
	return true, nil
}