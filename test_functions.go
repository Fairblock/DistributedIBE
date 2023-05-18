package distIBE

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"

	"fmt"
	"math/big"
	"reflect"
	"sync"

	enc "DistributedIBE/encryption"

	//"github.com/aws/aws-sdk-go/service/panorama"
	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/group/mod"
	"github.com/drand/kyber/pairing"
)

func H3Tag() []byte {
	return []byte("IBE-H3")
}

// func h3(s pairing.Suite, sigma, msg []byte) (kyber.Scalar, error) {
// 	h3 := s.Hash()

// 	if _, err := h3.Write(H3Tag()); err != nil {
// 		return nil, fmt.Errorf("err hashing h3 tag: %v", err)
// 	}
// 	if _, err := h3.Write(sigma); err != nil {
// 		return nil, fmt.Errorf("err hashing sigma: %v", err)
// 	}
// 	_, _ = h3.Write(msg)
// 	hashable, ok := s.G1().Scalar().(kyber.HashableScalar)
// 	if !ok {
// 		panic("scalar can't be created from hash")
// 	}

// 	h3Reader := bytes.NewReader(h3.Sum(nil))

// 	return hashable.Hash(s, h3Reader)
// }

func h3(s pairing.Suite, sigma, msg []byte) (kyber.Scalar, error) {
	h := s.Hash()

	if _, err := h.Write(H3Tag()); err != nil {
		return nil, fmt.Errorf("err hashing h3 tag: %v", err)
	}
	if _, err := h.Write(sigma); err != nil {
		return nil, fmt.Errorf("err hashing sigma: %v", err)
	}
	if _, err := h.Write(msg); err != nil {
		return nil, fmt.Errorf("err hashing msg: %v", err)
	}
	// we hash it a first time: buffer = hash("IBE-H3" || sigma || msg)
	buffer := h.Sum(nil)

	hashable, ok := s.G1().Scalar().(*mod.Int)
	if !ok {
		return nil, fmt.Errorf("unable to instantiate scalar as a mod.Int")
	}
	canonicalBitLen := hashable.MarshalSize() * 8
	actualBitLen := hashable.M.BitLen()
	toMask := canonicalBitLen - actualBitLen

	for i := uint16(1); i < 65535; i++ {
		h.Reset()
		// We will hash iteratively: H(i || H("IBE-H3" || sigma || msg)) until we get a
		// value that is suitable as a scalar.
		iter := make([]byte, 2)
		binary.LittleEndian.PutUint16(iter, i)
		_, _ = h.Write(iter)
		_, _ = h.Write(buffer)
		hashed := h.Sum(nil)
		// We then apply masking to our resulting bytes at the bit level
		// but we assume that toMask is a few bits, at most 8.
		// For instance when using BLS12-381 toMask == 1.
		if hashable.BO == mod.BigEndian {
			hashed[0] = hashed[0] >> toMask
		} else {
			hashed[len(hashed)-1] = hashed[len(hashed)-1] >> toMask
		}
		// NOTE: Here we unmarshal as a test if the buffer is within the modulo
		// because we know unmarshal does this test. This implementation
		// is almost generic if not for this line. TO make it truly generic
		// we would need to add methods to create a scalar from bytes without
		// reduction and a method to check if it is within the modulo on the
		// Scalar interface.
		if err := hashable.UnmarshalBinary(hashed); err == nil {
			fmt.Println("value of i is ", i)
			return hashable, nil
		}
	}
	// if we didn't return in the for loop then something is wrong
	return nil, fmt.Errorf("rejection sampling failure")
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
	// buf := make([]byte, 128)

	// _, err := rand.Read(buf)
	// if err != nil {
	// 	return false, err
	// }
	// var secretVal []byte = buf
	// var qBig = bigFromHex("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")
	// secret, _ := h3(s, secretVal, []byte("msg"))

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

	shares, PK, _, _ := GenerateShares(uint32(n), uint32(t))

	// Public Key

	// Generating commitments

	var c []Commitment
	for j := 0; j < n; j++ {
		fmt.Println(shares[j].Value)
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

// n keepers in total, threshold = t, (t-1) of them participated in decryption
func DistributedIBEFail(n int, t int, ID string, src bytes.Buffer, message string) (bool, error) {

	// Setup
	s := bls.NewBLS12381Suite()
	// buf := make([]byte, 128)

	// _, err := rand.Read(buf)
	// if err != nil {
	// 	return false, err
	// }
	// var secretVal []byte = buf
	// var qBig = bigFromHex("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")
	// secret, _ := h3(s, secretVal, []byte("msg"))

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

	shares, PK, _, _ := GenerateShares(uint32(n), uint32(t))

	// Public Key

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
	err := enc.Decrypt(PK, SK, &plainData, &cipherData)
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
	// buf := make([]byte, 128)

	// _, err := rand.Read(buf)
	// if err != nil {
	// 	return false, err
	// }
	// var secretVal []byte = buf
	// var qBig = bigFromHex("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")
	// secret, _ := h3(s, secretVal, []byte("msg"))

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

	shares, PK, _, _ := GenerateShares(uint32(n), uint32(t))

	// Public Key

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
	err := enc.Decrypt(PK, SK, &plainData, &cipherData)
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
	// buf := make([]byte, 128)

	// _, err := rand.Read(buf)
	// if err != nil {
	// 	return false, err
	// }
	// var secretVal []byte = buf
	// var qBig = bigFromHex("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")
	// secret, _ := h3(s, secretVal, []byte("msg"))

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

	shares, PK, _, _ := GenerateShares(uint32(n), uint32(t))

	// Public Key

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
	sk[0].SK = sk[0].SK.Add(sk[0].SK, sk[0].SK)
	// Aggregating keys to get the secret key for decryption
	SK, invalids := AggregateSK(s,
		sk,
		c, []byte(ID))
	if len(invalids) != 0 {
		return false, fmt.Errorf("invalids: %d", invalids)
	}
	var plainData bytes.Buffer
	// Decryption
	err := enc.Decrypt(PK, SK, &plainData, &cipherData)
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
	// buf := make([]byte, 128)

	// _, err := rand.Read(buf)
	// if err != nil {
	// 	return false, err
	// }
	// var secretVal []byte = buf
	// var qBig = bigFromHex("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")
	// secret, _ := h3(s, secretVal, []byte("msg"))

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

	shares, PK, _, _ := GenerateShares(uint32(n), uint32(t))

	// Public Key

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
	err := enc.Decrypt(PK, SK, &plainData, &cipherData)
	if err != nil {
		return false, err
	}
	// Verify that the decrypted message matches the original message
	if !reflect.DeepEqual(string(plainData.Bytes()[:]), message) {
		return false, fmt.Errorf("wrong decrypted message: %s VS %s", string(plainData.Bytes()[:]), message)
	}
	return true, nil
}

func Config(n int, t int, ID string) (kyber.Point, kyber.Point, error) {

	// Setup
	s := bls.NewBLS12381Suite()

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

	shares, PK, _, _ := GenerateShares(uint32(n), uint32(t))

	// Public Key

	// Generating commitments

	var c []Commitment
	for j := 0; j < n; j++ {

		if signers[j] == 1 {
			c = append(c, Commitment{s.G1().Point().Mul(shares[j].Value, s.G1().Point().Base()), uint32(j + 1)})
		}
	}

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
	return PK, SK, nil
}

func Encrypt(PK kyber.Point, ID string, src bytes.Buffer, message string) (bytes.Buffer, error) {
	// Encryption
	var cipherData bytes.Buffer
	err := enc.Encrypt(PK, []byte(ID), &cipherData, &src)
	if err != nil {
		return bytes.Buffer{}, err
	}
	return cipherData, nil

}

func Decrypt(PK kyber.Point, SK kyber.Point, cipherData bytes.Buffer) (bool, error) {
	var plainData bytes.Buffer
	err := enc.Decrypt(PK, SK, &plainData, &cipherData)
	if err != nil {
		return false, err
	}
	return true, nil
}

func DecryptParallel(PK kyber.Point, SK kyber.Point, cipherData bytes.Buffer, wg *sync.WaitGroup) (bool, error) {
	defer wg.Done()
	var plainData bytes.Buffer
	err := enc.Decrypt(PK, SK, &plainData, &cipherData)
	if err != nil {
		return false, err
	}
	return true, nil
}

func Shares(n int, t int, ID string) ([]Commitment, []Share, []int, error) {

	// Setup
	s := bls.NewBLS12381Suite()

	signers := []int{}
	for i := 0; i < n; i++ {
		signers = append(signers, 0)
	}
	j := 0
	for j < t {

		randomVal, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
		if signers[randomVal.Int64()] == 0 {
			signers[randomVal.Int64()] = 1
			j++
		}
	}

	// generating secret shares

	shares, PK, _, _ := GenerateShares(uint32(n), uint32(t))

	// Public Key

	_ = PK
	// Generating commitments

	var c []Commitment
	for j := 0; j < n; j++ {

		if signers[j] == 1 {
			c = append(c, Commitment{s.G1().Point().Mul(shares[j].Value, s.G1().Point().Base()), uint32(j + 1)})
		}
	}

	return c, shares, signers, nil
}

func KZGTest(n uint32, t uint32) error {

	_, commitment, proof, srs, err := GenerateSharesKZG(n, t)
	if err != nil {
		return err
	}

	for i := 0; uint32(i) < n; i++ {

		err = Verify(commitment, proof[i], proof[i].Index, srs)
		if err != nil {
			return err
		}
	}
	return nil
}

func KZGTestFail(n uint32, t uint32) error {

	_, commitment, proof, srs, err := GenerateSharesKZG(n, t)
	if err != nil {
		return err
	}
	// Changing a proof to a wrong value
	proof[1].H = proof[1].H.Add(proof[1].H, proof[1].H)

	for i := 0; uint32(i) < n; i++ {

		err = Verify(commitment, proof[i], proof[i].Index, srs)
		if err != nil {
			return err
		}
	}
	return nil
}

func VSSTest(n uint32, t uint32) error {

	shares, _, commitments, err := GenerateShares(n, t)
	if err != nil {
		return err
	}
	for i := 0; uint32(i) < n; i++ {
		res := VerifyShare(shares[i], commitments)
		if !res {
			return fmt.Errorf("wrong share")
		}
	}
	return nil
}
