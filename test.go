package tlock

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	
	"github.com/drand/kyber/pairing"
	"math/big"
	"reflect"
	"strings"
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

// polynomial represents A classic polynomial, with convenience methods useful for
// the operations the Threshold Cryptography library needs.
type polynomial []kyber.Scalar

// newPolynomial creates A polynomial of degree d with all its d+1 coefficients in 0.
func newPolynomial(d int) polynomial {
	poly := make(polynomial, d+1)
	for i := 0; i < len(poly); i++ {
		poly[i] = bls.NewKyberScalar()
	}
	return poly
}

// GetDegree returns the degree of A polynomial, which is the length of the coefficient
// array, minus 1.
func (p polynomial) getDegree() int {
	return len(p) - 1
}

// createRandomPolynomial creates A polynomial of degree "d" with random coefficients as terms
// with degree greater than 1. The coefficient of the term of degree 0 is x0 and the module for all the
// coefficients of the polynomial is m.
func createRandomPolynomial(d int, x0 kyber.Scalar, m *big.Int) (polynomial, error) {
	if m.Sign() < 0 {
		return polynomial{}, fmt.Errorf("m is negative")
	}
	poly := newPolynomial(d)

	poly[0].Set(x0)

	for i := 1; i < len(poly); i++ {
		r, err := rand.Int(rand.Reader, m)
		if err != nil {
			return polynomial{}, err
		}
		poly[i] = kyber.Scalar.SetInt64(poly[i], r.Int64())
	}
	return poly, nil
}

// eval evaluates A polynomial to x with Horner's method and returns the result.
func (p polynomial) eval(x kyber.Scalar) kyber.Scalar {
	y := bls.NewKyberScalar()
	y.SetInt64(int64(0))
	for k := len(p) - 1; k >= 0; k-- {
		y.Mul(y, x)
		y.Add(y, p[k])
	}
	return y
}

// string returns the polynomial formatted as A string.
func (p polynomial) String() string {
	s := make([]string, len(p))
	for i := 0; i < len(p); i++ {
		s[i] = fmt.Sprintf("%dx^%d", p[i], i)
	}
	return strings.Join(s, " + ")
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
	p, err := createRandomPolynomial(t, secret, qBig)

	if err != nil {
		fmt.Errorf("could not create a random polynomial")
		return
	}

	//=============================== After DKG ================================
	// After DKG, they will have their secret shares
	var Shares []kyber.Scalar
	for i := 0; i < n; i++ {
		Shares = append(Shares,bls.NewKyberScalar())
		Shares[i] = p.eval(kyber.Scalar.SetInt64(Shares[i], int64(i+1)))
	}
    // Public Key
	PK := s.G1().Point().Mul(secret, s.G1().Point().Base())

	// Generating commitments
	var c []Commitment
	for j := 0; j < t+1; j++ {

		c = append(c, Commitment{s.G1().Point().Mul(Shares[j], s.G1().Point().Base()), uint32(j+1)})
	}

	//=============================== From User view ================================
	// The message: string
	// ID         : Any string but in this setting, a specific block number
	message := "hi"
	ID_round1 := "3000"
	// Encryption
	Cipher_round1, _ := Encrypt(s, PK, []byte(ID_round1), []byte(message))

	// Extracting the keys using shares
	var sk []ExtractedKey
	for k := 0; k < t+1; k++ {

		sk = append(sk, Extract(s, Shares[k], uint32(k+1), []byte(ID_round1)))
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
