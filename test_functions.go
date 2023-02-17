package distIBE

import (
	enc "DistributedIBE/encryption"
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"reflect"

	//"github.com/aws/aws-sdk-go/service/panorama"
	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
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
func DistributedIBE(n int, t int, ID string, src bytes.Buffer, message string) (bool, error) {

	// Setup
	s := bls.NewBLS12381Suite()
	buf := make([]byte, 128)

	_, err := rand.Read(buf)
	if err != nil {
		return false, err
	}
	var secretVal []byte = buf
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
	var cipherData bytes.Buffer
	_ = enc.Encrypt(PK, []byte(ID), &cipherData, &src)

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
	var plainData bytes.Buffer
	// Decryption
	_ = enc.Decrypt(PK, SK, &plainData, &cipherData)

	// Verify that the decrypted message matches the original message
	if !reflect.DeepEqual(string(plainData.Bytes()[:]), message) {
		return false, fmt.Errorf("wrong decrypted message: %s VS %s", string(plainData.Bytes()[:]), message)
	}
	return true, nil
}

//n keepers in total, threshold = t, (t-1) of them participated in decryption
func DistributedIBEFail(n int, t int, ID string, src bytes.Buffer, message string) (bool, error) {

	// Setup
	s := bls.NewBLS12381Suite()
	buf := make([]byte, 128)

	_, err := rand.Read(buf)
	if err != nil {
		return false, err
	}
	var secretVal []byte = buf
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
	var cipherData bytes.Buffer
	_ = enc.Encrypt(PK, []byte(ID), &cipherData, &src)

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
	var plainData bytes.Buffer
	// Decryption
	err = enc.Decrypt(PK, SK, &plainData, &cipherData)
	if err != nil {
		return false, err
	}
	// Verify that the decrypted message matches the original message
	if !reflect.DeepEqual(string(plainData.Bytes()[:]), message) {
		return false, fmt.Errorf("wrong decrypted message: %s VS %s", string(plainData.Bytes()[:]), message)
	}

	return true, nil
}

// n keepers in total, threshold = t, (t+1) of them participated in decryption but one commitment is wrong
func DistributedIBEFInvalidCommitment(n int, t int, ID string, src bytes.Buffer, message string) (bool, error) {

	// Setup
	s := bls.NewBLS12381Suite()
	buf := make([]byte, 128)

	_, err := rand.Read(buf)
	if err != nil {
		return false, err
	}
	var secretVal []byte = buf
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
	var cipherData bytes.Buffer
	_ = enc.Encrypt(PK, []byte(ID), &cipherData, &src)

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
	SK, invalids := AggregateSK(s,
		sk,
		c, []byte(ID))
	if len(invalids) != 0 {
		return false, fmt.Errorf("invalids: %d", invalids)
	}
	var plainData bytes.Buffer
	// Decryption
	err = enc.Decrypt(PK, SK, &plainData, &cipherData)
	if err != nil {
		return false, err
	}
	// Verify that the decrypted message matches the original message
	if !reflect.DeepEqual(string(plainData.Bytes()[:]), message) {
		return false, fmt.Errorf("wrong decrypted message: %s VS %s", string(plainData.Bytes()[:]), message)
	}

	return true, nil

}

// n keepers in total, threshold = t, (t+1) of them participated in decryption but one share is wrong
func DistributedIBEFInvalidShare(n int, t int, ID string, src bytes.Buffer, message string) (bool, error) {

	// Setup
	s := bls.NewBLS12381Suite()
	buf := make([]byte, 128)

	_, err := rand.Read(buf)
	if err != nil {
		return false, err
	}
	var secretVal []byte = buf
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
	var cipherData bytes.Buffer
	_ = enc.Encrypt(PK, []byte(ID), &cipherData, &src)

	// Extracting the keys using shares
	var sk []ExtractedKey
	for k := 0; k < n; k++ {
		if signers[k] == 1 {
			sk = append(sk, Extract(s, shares[k].Value, uint32(k+1), []byte(ID)))
		}
	}
	// chaning the first extracted key to something else (previous value * 2 in this case)
	sk[0].sk = sk[0].sk.Add(sk[0].sk, sk[0].sk)
	// Aggregating keys to get the secret key for decryption
	SK, invalids := AggregateSK(s,
		sk,
		c, []byte(ID))
	if len(invalids) != 0 {
		return false, fmt.Errorf("invalids: %d", invalids)
	}
	var plainData bytes.Buffer
	// Decryption
	err = enc.Decrypt(PK, SK, &plainData, &cipherData)
	if err != nil {
		return false, err
	}
	// Verify that the decrypted message matches the original message
	if !reflect.DeepEqual(string(plainData.Bytes()[:]), message) {
		return false, fmt.Errorf("wrong decrypted message: %s VS %s", string(plainData.Bytes()[:]), message)
	}

	return true, nil

}

// n keepers in total, threshold = t, (t+1) of them participated in decryption. The ciphertext is changed to become invalid.
func DistributedIBEWrongCiphertext(n int, t int, ID string, src bytes.Buffer, message string) (bool, error) {

	// Setup
	s := bls.NewBLS12381Suite()
	buf := make([]byte, 128)

	_, err := rand.Read(buf)
	if err != nil {
		return false, err
	}
	var secretVal []byte = buf
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
	var cipherData bytes.Buffer
	_ = enc.Encrypt(PK, []byte(ID), &cipherData, &src)

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

	var plainData bytes.Buffer

	// Adding random string to ciphertext
	cipherData.WriteString("hihihihihi")
	err = enc.Decrypt(PK, SK, &plainData, &cipherData)
	if err != nil {
		return false, err
	}
	// Verify that the decrypted message matches the original message
	if !reflect.DeepEqual(string(plainData.Bytes()[:]), message) {
		return false, fmt.Errorf("wrong decrypted message: %s VS %s", string(plainData.Bytes()[:]), message)
	}
	return true, nil
}
