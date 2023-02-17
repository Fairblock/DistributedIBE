package distIBE

import (
	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing"
)

func AggregateSK(s pairing.Suite, receivedShares []ExtractedKey, commitments []Commitment, id []byte) (kyber.Point, []uint32) {
	SkShares := []kyber.Point{}
	invalid := []uint32{}
	valid := []uint32{}
	validShare := []ExtractedKey{}
	for i, _ := range receivedShares {
		receivedShare := receivedShares[i]
		commitment := commitments[i]
		hG2, ok := s.G2().Point().(kyber.HashablePoint)
		if !ok {
			panic("point needs to implement `kyber.HashablePoint`")
		}
		Qid := hG2.Hash(id)
		if verifyShare(s, commitment, receivedShare, Qid) {
			valid = append(valid, receivedShare.Index)
			validShare = append(validShare, receivedShare)
		} else {
			invalid = append(invalid, commitment.Index)
		}
	}

	for _, r := range validShare {

		processedShare := processSK(s, r, valid)
		SkShares = append(SkShares, processedShare.SK)
	}

	SK := aggregate(SkShares...)
	return SK, invalid
}

func processSK(suite pairing.Suite, share ExtractedKey, S []uint32) ExtractedKey {

	lagrangeCoef := LagrangeCoefficient(suite, share.Index, S)
	idenityKey := share.SK.Mul(lagrangeCoef, share.SK)
	return ExtractedKey{idenityKey, share.Index}
}

func aggregate(keys ...kyber.Point) kyber.Point {
	var sk kyber.Point = keys[0]
	for _, key := range keys {

		if key != sk {
			sk.Add(sk, key)
		}
	}

	return sk
}
