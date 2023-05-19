package distIBE

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/pairing"
	// "github.com/drand/kyber/proof"
)

type PolynomialCoeff []kyber.Scalar
type Commitments []kyber.Point

type Share struct {
	Index kyber.Scalar
	Value kyber.Scalar
}


func hexToBin(hexString string) string {

	hexChar2BinChar := map[string]string{
		"0": "0000",
		"1": "0001",
		"2": "0010",
		"3": "0011",
		"4": "0100",
		"5": "0101",
		"6": "0110",
		"7": "0111",
		"8": "1000",
		"9": "1001",
		"a": "1010",
		"b": "1011",
		"c": "1100",
		"d": "1101",
		"e": "1110",
		"f": "1111",
	}

	var binString bytes.Buffer
	hexStringArr := strings.Split(hexString, "")

	for i := 0; i < len(hexStringArr); i++ {
		binString.WriteString(hexChar2BinChar[hexStringArr[i]])
	}
	return binString.String()
}

func newPolynomial(threshold uint32) PolynomialCoeff {
	poly := make(PolynomialCoeff, threshold)
	for i := 0; i < len(poly); i++ {
		poly[i] = bls.NewKyberScalar()
	}
	return poly
}

func createRandomPolynomial(threshold uint32, masterSecretKey kyber.Scalar, groupOrder *big.Int) (poly PolynomialCoeff, err error) {
	if groupOrder.Sign() < 0 {
		return PolynomialCoeff{}, fmt.Errorf("group order is negative")
	}
	poly = newPolynomial(threshold)

	poly[0].Set(masterSecretKey)

	for i := 1; i < len(poly); i++ {
		one := big.NewInt(int64(1))
		max := big.NewInt(int64(0))
		max.Sub(groupOrder, one)

		r, err := rand.Int(rand.Reader, max)
		if err != nil {
			return PolynomialCoeff{}, err
		}
		r.Add(r, one)

		poly[i] = kyber.Scalar.SetInt64(poly[i], r.Int64())
	}
	return poly, nil
}

func (p PolynomialCoeff) eval(x kyber.Scalar) kyber.Scalar {
	y := bls.NewKyberScalar().Zero()

	for k := len(p) - 1; k >= 0; k-- {
		y.Mul(y, x)
		y.Add(y, p[k])
	}
	return y
}

func Exp(base, exponent kyber.Scalar) kyber.Scalar {

	if exponent.Equal(bls.NewKyberScalar().Zero()) {
		return bls.NewKyberScalar().One()
	}

	if exponent.Equal(bls.NewKyberScalar().One()) {
		return base
	}

	if base.Equal(bls.NewKyberScalar().One()) {
		return base
	}

	expBinStr := hexToBin(exponent.String())
	expBinStringArr := strings.Split(expBinStr, "")
	res := bls.NewKyberScalar().One()

	bPrime := bls.NewKyberScalar().One()
	bPrime.Mul(bPrime, base)

	for j := len(expBinStringArr) - 1; j >= 0; j-- {

		if expBinStringArr[j] == "1" {
			res.Mul(res, bPrime)
		}
		bPrime.Mul(bPrime, bPrime)
	}

	return res
}

func GenerateMSKAndMPK(groupOrder *big.Int) (masterSecretKey kyber.Scalar, masterPublicKey kyber.Point) {
	one := big.NewInt(int64(1))
	max := big.NewInt(int64(0))
	max.Sub(groupOrder, one)

	r, err := rand.Int(rand.Reader, max)
	if err != nil {
		fmt.Println("could not generate random master secret key")
		return
	}
	r.Add(r, one)
	masterSecretKey = bls.NewKyberScalar().SetInt64(r.Int64())

	s := bls.NewBLS12381Suite()
	PointG := s.G1().Point().Base()
	masterPublicKey = s.G1().Point().Mul(masterSecretKey, PointG)

	return masterSecretKey, masterPublicKey
}

func GenerateShares(numberOfShares, threshold uint32) (shares []Share, MPK kyber.Point, commits Commitments, err error) {
	buf := make([]byte, 128)
	groupOrder := bigFromHex("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")
	s := bls.NewBLS12381Suite()

	_, err = rand.Read(buf)
	if err != nil {
		return nil, nil, nil, err
	}
	var secretVal []byte = buf
	masterSecretKey, _ := h3(s, secretVal, []byte("msg"))
	MPK = s.G1().Point().Mul(masterSecretKey, s.G1().Point().Base())
	polynomial, err := createRandomPolynomial(threshold, masterSecretKey, groupOrder)

	if err != nil {
		return shares, nil, nil, fmt.Errorf("shares could not be created due to random polynomial generation failing")
	}

	randomPoly := polynomial

	index := make([]kyber.Scalar, numberOfShares)
	value := make([]kyber.Scalar, numberOfShares)

	for i := range index {
		index[i] = bls.NewKyberScalar().SetInt64(int64(i + 1))
		evalPoly := polynomial.eval(index[i])
		value[i] = evalPoly
	}

	shares = make([]Share, numberOfShares)
	for j := range shares {
		shares[j] = Share{Index: index[j], Value: value[j]}
	}
	commits = GenerateCommits(randomPoly)
	return shares, MPK, commits, nil
}

// func GenerateSharesKZG(numberOfShares, threshold uint32) (kyber.Point, kyber.Point, []OpeningProof, SRS, error) {
// 	buf := make([]byte, 128)
// 	groupOrder := bigFromHex("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")
// 	s := bls.NewBLS12381Suite()

// 	_, err := rand.Read(buf)
// 	if err != nil {
// 		return nil, nil, nil, SRS{}, err
// 	}
// 	var secretVal []byte = buf
// 	masterSecretKey, _ := h3(s, secretVal, []byte("msg"))
// 	MPK := s.G1().Point().Mul(masterSecretKey, s.G1().Point().Base())
// 	polynomial, err := createRandomPolynomial(threshold, masterSecretKey, groupOrder)

// 	if err != nil {
// 		return nil, nil, nil, SRS{}, fmt.Errorf("shares could not be created due to random polynomial generation failing")
// 	}

// 	randomPoly := polynomial

// 	index := make([]kyber.Scalar, numberOfShares)
// 	value := make([]kyber.Scalar, numberOfShares)

// 	for i := range index {
// 		index[i] = bls.NewKyberScalar().SetInt64(int64(i + 1))
// 		evalPoly := polynomial.eval(index[i])
// 		value[i] = evalPoly
// 	}
// 	srs, err := NewSRS(uint64(threshold))
// 	if err != nil {
// 		return nil, nil, nil, SRS{}, err
// 	}
// 	commitment, err := Commit(randomPoly, srs)
// 	if err != nil {
// 		return nil, nil, nil, SRS{}, err
// 	}

// 	var proof []OpeningProof
// 	proof = make([]OpeningProof, numberOfShares)
// 	var p OpeningProof

// 	var shares []Share
// 	shares = make([]Share, numberOfShares)
// 	for j := range shares {
// 		shares[j] = Share{Index: index[j], Value: value[j]}

// 	}

// 	for i := 0; i < int(numberOfShares); i++ {
// 		p, err = Open(randomPoly, shares[i].Index, shares[i].Value, srs)
// 		if err != nil {
// 			return nil, nil, nil, SRS{}, err
// 		}

// 		proof[i].H = s.G1().Point().Base()
// 		proof[i].H.Set(p.H)
// 		proof[i].ClaimedValue = p.ClaimedValue
// 		proof[i].Index = p.Index

// 	}

// 	return MPK, commitment, proof, srs, nil
// }

func lagrangeCoefficientFromShares(indexJ kyber.Scalar, shares []Share) kyber.Scalar {
	nominator := bls.NewKyberScalar().SetInt64(int64(1))
	denominator := bls.NewKyberScalar().SetInt64(int64(1))

	for _, share := range shares {
		if share.Index != indexJ {
			nominator.Mul(nominator, share.Index)

			denominator.Mul(denominator, bls.NewKyberScalar().SetInt64(int64(1)).Add(share.Index, bls.NewKyberScalar().SetInt64(int64(1)).Neg(indexJ)))

		}
	}
	return bls.NewKyberScalar().SetInt64(int64(1)).Div(nominator, denominator) //Inverse will panic if denominator is 0
}

func LagrangeCoefficient(suite pairing.Suite, signer uint32, S []uint32) kyber.Scalar {
	nominator := bls.NewKyberScalar()
	temp := bls.NewKyberScalar()
	temp1 := bls.NewKyberScalar()
	nominator.SetInt64(int64(1))
	denominator := bls.NewKyberScalar()
	denominator.SetInt64(int64(1))

	for _, s := range S {
		if s != signer {
			nominator.Mul(nominator, kyber.Scalar.SetInt64(temp, int64(s)))

			denominator.Mul(denominator,
				kyber.Scalar.Sub(temp,
					kyber.Scalar.SetInt64(temp, int64(s)),
					kyber.Scalar.SetInt64(temp1, int64(signer))))

		}
	}

	var outScalar kyber.Scalar = bls.NewKyberScalar()
	kyber.Scalar.Div(outScalar, nominator, denominator)

	return outScalar
}

func RegenerateSecret(threshold uint32, shares []Share) (masterSecretKey kyber.Scalar, err error) {
	if uint32(len(shares)) != threshold {
		return masterSecretKey, fmt.Errorf("not enough shares to reconstruct master secret key")
	}

	masterSecretKey = bls.NewKyberScalar().Zero()

	for _, share := range shares {
		lagrangeCoeff := lagrangeCoefficientFromShares(share.Index, shares)
		product := bls.NewKyberScalar().One()
		masterSecretKey.Add(masterSecretKey, product.Mul(share.Value, lagrangeCoeff))
	}
	return masterSecretKey, nil
}

func GenerateCommits(polynomial PolynomialCoeff) (commits Commitments) {

	s := bls.NewBLS12381Suite()
	PointG := s.G1().Point().Base()
	commits = make(Commitments, len(polynomial))

	for i := 0; i < len(polynomial); i++ {
		commits[i] = s.G1().Point().Mul(polynomial[i], PointG)
	}

	return commits
}

func VerifyShare(share Share, commits Commitments) bool {

	s := bls.NewBLS12381Suite()
	PointG := s.G1().Point().Base()

	shareTimesPointG := s.G1().Point().Mul(share.Value, PointG)
	sum := s.G1().Point().Set(commits[0])

	for i := 1; i < len(commits); i++ {
		indexToI := Exp(share.Index, bls.NewKyberScalar().SetInt64(int64(i)))
		product := s.G1().Point().Mul(indexToI, commits[i])
		sum = s.G1().Point().Add(sum, product)
	}

	return shareTimesPointG.Equal(sum)
}
