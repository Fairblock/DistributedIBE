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
func TestDistributedIBE(n int, t int) {

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
	for ; j < t+1 ; {
		
		randomVal,_ := rand.Int(rand.Reader, big.NewInt(int64(n)))
		if signers[randomVal.Int64()] == 0{
			signers[randomVal.Int64()] = 1
			j++
		}
	}
	
	
	// generating secret shares
	
	Shares,_ := GenerateShares(uint32(n),uint32(t),secret,qBig)

    // Public Key
	PK := s.G1().Point().Mul(secret, s.G1().Point().Base())

	// Generating commitments
	
	var c []Commitment
	for j := 0; j < n; j++ {
		if signers[j] == 1 {
		c = append(c, Commitment{s.G1().Point().Mul(Shares[j].Value, s.G1().Point().Base()), uint32(j+1)})
		}
	}

	
	// The message: string
	// ID         : Any string but in this setting, a specific block number
	message := "hi"
	ID_round1 := "3000"
	// Encryption
	Cipher_round1, _ := Encrypt(s, PK, []byte(ID_round1), []byte(message))

	// Extracting the keys using shares
	var sk []ExtractedKey
	for k := 0; k < n; k++ {
		if signers[k] == 1 {
		sk = append(sk, Extract(s, Shares[k].Value, uint32(k+1), []byte(ID_round1)))
		}
	}
	
	// Aggregating keys to get the secret key for decryption
	SK_round1, _ := AggregateSK(s,
		sk,
		c, []byte(ID_round1))
	
	// Decryption
	decrypted, _ := Decrypt(s, SK_round1, Cipher_round1)

	// Verify that the decrypted message matches the original message
	if !reflect.DeepEqual(message, string(decrypted[:])) {
		fmt.Errorf(string(decrypted[:]))
	}

}
