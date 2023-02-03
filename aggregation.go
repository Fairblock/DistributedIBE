package tlock

import (
	"github.com/drand/kyber"
	
	"github.com/drand/kyber/pairing"
)

func AggregateSK(s pairing.Suite, ReceivedShares []ExtractedKey, Commitments []Commitment, id []byte) (kyber.Point, []uint32) {
	SkShares := []kyber.Point{}
	Invalid := []uint32{}
	Valid := []uint32{}
	ValidShare := []ExtractedKey{}
	for i, _ := range ReceivedShares {
		receivedShare := ReceivedShares[i]
		commitment := Commitments[i]
		hG2, ok := s.G2().Point().(kyber.HashablePoint)
		if !ok {
			panic("point needs to implement `kyber.HashablePoint`")
		}
		Qid := hG2.Hash(id)
		if verifyShare(s, commitment, receivedShare, Qid) {
			Valid = append(Valid, receivedShare.index)
			ValidShare = append(ValidShare, receivedShare)
		} else {
			Invalid = append(Invalid, commitment.index)
		}
	}

	for _, r := range ValidShare {

		processedShare := processSK(s, r, Valid)
		SkShares = append(SkShares, processedShare.sk)
	}

	SK := Aggregate(SkShares...)
	return SK, Invalid
}

func processSK(suite pairing.Suite, share ExtractedKey, S []uint32) ExtractedKey {

	lagrangeCoef := lagrangeCoefficient(suite, share.index, S)
	idenityKey := share.sk.Mul(lagrangeCoef, share.sk)
	return ExtractedKey{idenityKey, share.index}
}


func Aggregate(keys ...kyber.Point) kyber.Point {
	var sk kyber.Point = keys[0]
	for _, key := range keys {

		if key != sk {
			sk.Add(sk, key)
		}
	}

	return sk
}
