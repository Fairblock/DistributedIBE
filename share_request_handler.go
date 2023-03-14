package distIBE

// import (
// 	"fmt"
// 	"reflect"
// 	"crypto/rsa"
// 	bls "github.com/drand/kyber-bls12381"
// 	rsa_impl "DistributedIBE/rsa"
// )

// type EncryptedShare struct{
// 	encShare string
// 	index int
// 	pk rsa.PublicKey
// }

// var sharesList []EncryptedShare 

// func setup(n int, t int, pkList []rsa.PublicKey) error{
// 	sharesList = []EncryptedShare{}
// 	s := bls.NewBLS12381Suite()
// 	var secretVal []byte = []byte{187}
// 	var qBig = bigFromHex("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")
// 	secret, _ := h3(s, secretVal, []byte("msg"))
	
// 	// generating secret shares

// 	shares, _ := GenerateShares(uint32(n), uint32(t), secret, qBig)

// 	// Public Key
// 	PK := s.G1().Point().Mul(secret, s.G1().Point().Base())
// 	i := 0
// 	for _,s := range shares{
// 		res,err := rsa_impl.RSA_Encrypt(s.Value.String(),pkList[i])
// 		if err != nil{
// 			fmt.Errorf(err.Error())
// 		}
// 		share := EncryptedShare{res,i,pkList[i]}
// 		sharesList =  append(sharesList, share )
// 		i = i + 1
// 	}
// 	_ = PK

// return nil
// }

// func requestKey(pk rsa.PublicKey, signedM rsa_impl.SignedMessage) (EncryptedShare, error) {
// 	res, err := rsa_impl.CheckSig(pk,signedM)
// if !res {
// 	return EncryptedShare{}, err
// }
// for _,s := range sharesList{
// 	if reflect.DeepEqual(s.pk, pk) {
// 		return s, nil
// 	}
// }
// return EncryptedShare{}, fmt.Errorf("pk not in the list")
// }