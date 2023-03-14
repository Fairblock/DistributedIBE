package distIBE

// import (
// 	"crypto/rand"
// 	"fmt"
// 	"github.com/drand/kyber"
// 	bls "github.com/drand/kyber-bls12381"
// 	"github.com/drand/kyber/pairing"
// 	"math/big"
// )

// type PolynomialCoeff []kyber.Scalar

// type Share struct {
// 	Index kyber.Scalar
// 	Value kyber.Scalar
// }

// func newPolynomial(threshold uint32) PolynomialCoeff {
// 	poly := make(PolynomialCoeff, threshold)
// 	for i := 0; i < len(poly); i++ {
// 		poly[i] = bls.NewKyberScalar()
// 	}
// 	return poly
// }

// func createRandomPolynomial(threshold uint32, masterSecretKey kyber.Scalar, groupOrder *big.Int) (poly PolynomialCoeff, err error) {
// 	if groupOrder.Sign() < 0 {
// 		return PolynomialCoeff{}, fmt.Errorf("group order is negative")
// 	}
// 	poly = newPolynomial(threshold)

// 	poly[0].Set(masterSecretKey)

// 	for i := 1; i < len(poly); i++ {
// 		one := big.NewInt(int64(1))
// 		max := big.NewInt(int64(0))
// 		max.Sub(groupOrder, one)

// 		r, err := rand.Int(rand.Reader, max)
// 		if err != nil {
// 			return PolynomialCoeff{}, err
// 		}
// 		r.Add(r, one)

// 		poly[i] = kyber.Scalar.SetInt64(poly[i], r.Int64())
// 	}
// 	return poly, nil
// }

// func (p PolynomialCoeff) eval(x kyber.Scalar) kyber.Scalar {
// 	y := bls.NewKyberScalar().SetInt64(int64(0))

// 	for k := len(p) - 1; k >= 0; k-- {
// 		y.Mul(y, x)
// 		y.Add(y, p[k])
// 	}
// 	return y
// }

// func GenerateShares(numberOfShares, threshold uint32, masterSecretKey kyber.Scalar, groupOrder *big.Int) (Shares []Share, err error) {

// 	polynomial, err := createRandomPolynomial(threshold, masterSecretKey, groupOrder)

// 	if err != nil {
// 		return Shares, fmt.Errorf("shares could not be created due to random polynomial generation failing")
// 	}

// 	index := make([]kyber.Scalar, numberOfShares)
// 	value := make([]kyber.Scalar, numberOfShares)

// 	for i := range index {
// 		index[i] = bls.NewKyberScalar().SetInt64(int64(i + 1))
// 		evalPoly := polynomial.eval(index[i])
// 		value[i] = evalPoly
// 	}

// 	Shares = make([]Share, numberOfShares)
// 	for j := range Shares {
// 		Shares[j] = Share{Index: index[j], Value: value[j]}
// 	}

// 	return Shares, err
// }

// func lagrangeCoefficientFromShares(indexJ kyber.Scalar, shares []Share) kyber.Scalar {
// 	nominator := bls.NewKyberScalar().SetInt64(int64(1))
// 	denominator := bls.NewKyberScalar().SetInt64(int64(1))

// 	for _, share := range shares {
// 		if share.Index != indexJ {
// 			nominator.Mul(nominator, share.Index)

// 			denominator.Mul(denominator, bls.NewKyberScalar().SetInt64(int64(1)).Add(share.Index, bls.NewKyberScalar().SetInt64(int64(1)).Neg(indexJ)))

// 		}
// 	}
// 	return bls.NewKyberScalar().SetInt64(int64(1)).Div(nominator, denominator) //Inverse will panic if denominator is 0
// }

// func LagrangeCoefficient(suite pairing.Suite, signer uint32, S []uint32) kyber.Scalar {
// 	nominator := bls.NewKyberScalar()
// 	temp := bls.NewKyberScalar()
// 	temp1 := bls.NewKyberScalar()
// 	nominator.SetInt64(int64(1))
// 	denominator := bls.NewKyberScalar()
// 	denominator.SetInt64(int64(1))

// 	for _, s := range S {
// 		if s != signer {
// 			nominator.Mul(nominator, kyber.Scalar.SetInt64(temp, int64(s)))

// 			denominator.Mul(denominator,
// 				kyber.Scalar.Sub(temp,
// 					kyber.Scalar.SetInt64(temp, int64(s)),
// 					kyber.Scalar.SetInt64(temp1, int64(signer))))

// 		}
// 	}

// 	var outScalar kyber.Scalar = bls.NewKyberScalar()
// 	kyber.Scalar.Div(outScalar, nominator, denominator)

// 	return outScalar
// }

// func RegenerateSecret(threshold uint32, shares []Share) (masterSecretKey kyber.Scalar, err error) {
// 	if uint32(len(shares)) != threshold {
// 		return masterSecretKey, fmt.Errorf("not enough shares to reconstruct master secret key")
// 	}

// 	masterSecretKey = bls.NewKyberScalar().SetInt64(int64(0))

// 	for _, share := range shares {
// 		lagrangeCoeff := lagrangeCoefficientFromShares(share.Index, shares)
// 		product := bls.NewKyberScalar().SetInt64(int64(1))
// 		masterSecretKey.Add(masterSecretKey, product.Mul(share.Value, lagrangeCoeff))
// 	}
// 	return masterSecretKey, nil
// }
