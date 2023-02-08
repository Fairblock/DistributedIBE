package distIBE

import (
	"reflect"
	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing"
)

type Commitment struct {
	sP    kyber.Point
	index uint32
}

func verifyShare(s pairing.Suite, c Commitment, share ExtractedKey, qid kyber.Point) bool {
	//e(s1 * P, H(ID))
	a := s.Pair(c.sP, qid)
	//e(P, s1 * H(ID))
	b := s.Pair(s.G1().Point().Base(), share.sk)
	return reflect.DeepEqual(a, b)

}
