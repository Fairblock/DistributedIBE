package distIBE

import (
	"fmt"
	"math/big"

	ibe "github.com/drand/kyber/encrypt/ibe"

	bls "github.com/drand/kyber-bls12381"
)

func main() {
	s := bls.NewBLS12381Suite()

	// sigma := "ed69a8c50df8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9c"
	// message := "1d69a8c50cf8c9836be3b67c7eeff416612d45ba39a5c199d48fa668bf558c9c"
	message := "1d69a8c50cf8c9836be3b67c7eeff416"
	id := "18f020b98eb798752a50ed0563b079c125b0db5dd0b1060d1c1b47d4a193e1e4"

	byteMessage := []byte(message)
	// byteSigma, err := hex.DecodeString(sigma)
	// byteMessage, err := hex.DecodeString(message)
	// if err != nil {
	// 	fmt.Println("error in converting message to array of bytes")
	// 	return
	// }

	byteID := []byte(id)
	// byteID, err := hex.DecodeString(id)
	// if err != nil {
	// 	fmt.Println("error in converting ID to array of bytes")
	// 	return
	// }

	r := big.NewInt(25)
	masterSecretKey := bls.NewKyberScalar().SetInt64(r.Int64())

	PointG := s.G1().Point().Base()
	masterPublicKey := s.G1().Point().Mul(masterSecretKey, PointG)

	C, err := ibe.EncryptCCAonG1(s, masterPublicKey, byteID, byteMessage)
	if err != nil {
		fmt.Println("error in encryption occured ", err.Error())
	}

	fmt.Println(C)
}
