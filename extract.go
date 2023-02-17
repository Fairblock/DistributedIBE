package distIBE

import (
	"fmt"

	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing"
)

type ExtractedKey struct {
	SK    kyber.Point
	Index uint32
}

func Extract(s pairing.Suite, share kyber.Scalar, index uint32, id []byte) ExtractedKey {
	hG2, ok := s.G2().Point().(kyber.HashablePoint)
	if !ok {
		fmt.Errorf("invalid point")
	}
	Qid := hG2.Hash(id)
	retSk := s.G2().Point().Mul(share, Qid)
	return ExtractedKey{retSk, index}
}
