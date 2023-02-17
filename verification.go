package distIBE

import (
	"reflect"

	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing"
)

type Commitment struct {
	SP    kyber.Point
	Index uint32
}

func verifyShare(s pairing.Suite, c Commitment, share ExtractedKey, qid kyber.Point) bool {
	//e(s1 * P, H(ID))
	a := s.Pair(c.SP, qid)
	//e(P, s1 * H(ID))
	b := s.Pair(s.G1().Point().Base(), share.SK)
	return reflect.DeepEqual(a, b)

}
