package distIBE

import (
	"bytes"
	"fmt"
	"math/rand"
	"reflect"
	"testing"

	bls "github.com/drand/kyber-bls12381"
)

func TestDistributedIBE(t *testing.T) {
	message := "this is a long message with more than 32 bytes! this is a long message with more than 32 bytes!long message with more than 32 bytes! this is a long message with long message with more than 32 bytes! this is a long message with long message with more than 32 bytes! this is a long message with long message with more than 32 bytes! this is a long message with long message with more than 32 bytes! this is a long message with long message with more than 32 bytes! this is a long message with long message with more than 32 bytes! this is a long message with "
	var plainData bytes.Buffer
	plainData.WriteString(message)

	res, err := DistributedIBE(4, 1, "300", plainData, message)
	t.Error("hi")
	if res == false {
		t.Errorf(err.Error())
	}

}

func TestDistributedIBEFail(t *testing.T) {

	message := "this is a long message with more than 32 bytes!"
	var plainData bytes.Buffer
	plainData.WriteString(message)

	res, err := DistributedIBEFail(6, 3, "300", plainData, message)

	if res == true {
		t.Errorf("Decryption worked with lower than threshold shares!")
	}
	if !reflect.DeepEqual("age decrypt: errNoMatch", err.Error()) {
		t.Errorf(err.Error())
	}
}

func TestDistributedIBEFInvalidCommitment(t *testing.T) {

	message := "this is a long message with more than 32 bytes!"
	var plainData bytes.Buffer
	plainData.WriteString(message)

	_, err := DistributedIBEFInvalidCommitment(6, 3, "300", plainData, message)

	if err == nil {
		t.Errorf("Wrong commitment accepted!")
	}

}

func TestDistributedIBEFInvalidShare(t *testing.T) {

	message := "this is a long message with more than 32 bytes!"
	var plainData bytes.Buffer
	plainData.WriteString(message)

	_, err := DistributedIBEFInvalidShare(6, 3, "300", plainData, message)

	if err == nil {
		t.Errorf("Wrong share accepted!")
	}

}

func TestDistributedIBEWrongCiphertext(t *testing.T) {
	message := "this is a long message with more than 32 bytes! this is a long message with more than 32 bytes!"
	var plainData bytes.Buffer
	plainData.WriteString(message)

	_, err := DistributedIBEWrongCiphertext(6, 3, "300", plainData, message)

	if err.Error() != "write: failed to decrypt and authenticate payload chunk" {
		t.Errorf("wrong ciphertext decrypted or some other part failed!")
	}

}

var participants = []struct {
	input int
}{

	{input: 4},
	{input: 8},
	{input: 16},
	{input: 32},
	{input: 64},
	{input: 128},
}

func BenchmarkDistributedIBEE(b *testing.B) {
	message := "this is a long message with more than 32 bytes!"
	var plainData bytes.Buffer
	plainData.WriteString(message)
	for _, v := range participants {
		b.Run(fmt.Sprintf("input_size_%d", v.input), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				DistributedIBE(v.input, v.input-1, "300", plainData, message)

			}
		})
	}

}

var messageSize = []struct {
	input int
}{

	{input: 8},
	{input: 32},
	{input: 128},
	{input: 512},
	{input: 2048},
	{input: 8192},
}

func randomStringGenerator(n int) string {
	var letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	byteString := make([]byte, n)
	for i := range byteString {
		byteString[i] = letters[rand.Intn(len(letters))]
	}
	return string(byteString)
}

func BenchmarkDistributedIBEEMessageSize(b *testing.B) {

	for _, v := range messageSize {
		b.Run(fmt.Sprintf("input_size_%d", v.input), func(b *testing.B) {
			message := randomStringGenerator(v.input)
			var plainData bytes.Buffer
			plainData.WriteString(message)
			for i := 0; i < b.N; i++ {
				DistributedIBE(4, 3, "300", plainData, message)
			}
		})
	}

}

var messageNum = []struct {
	input int
}{

	{input: 8},
	{input: 32},
	{input: 128},
	{input: 512},
	{input: 1024},
}

func BenchmarkDecryption(b *testing.B) {
	message := "this is a long message with more than 32 bytes!"
	var plainData bytes.Buffer
	plainData.WriteString(message)
	PK, SK, err := Config(100, 70, "3000")
	if err != nil {
		panic(err.Error())
	}
	cipher, err := Encrypt(PK, "3000", plainData, message)
	if err != nil {
		panic(err.Error())
	}
	for _, v := range messageNum {
		b.Run(fmt.Sprintf("input_size_%d", v.input), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				for j := 0; j < v.input; j++ {
					res, err := Decrypt(PK, SK, cipher)
					if !res {
						panic(err.Error())
					}
				}

			}
		})
	}

}

var messageNumEnc = []struct {
	input int
}{

	{input: 1},
	{input: 4},
	{input: 16},
	{input: 64},
	{input: 256},
}

func BenchmarkEncryption(b *testing.B) {
	message := "this is a long message with more than 32 bytes!"
	var plainData bytes.Buffer
	plainData.WriteString(message)
	PK, _, err := Config(100, 70, "3000")
	if err != nil {
		panic(err.Error())
	}

	for _, v := range messageNumEnc {
		b.Run(fmt.Sprintf("input_size_%d", v.input), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				for j := 0; j < v.input; j++ {
					_, err := Encrypt(PK, "3000", plainData, message)
					if err != nil {
						panic(err.Error())
					}
				}

			}
		})
	}

}

var Input = []struct {
	input int
}{

	{input: 1},
}

func BenchmarkExtractAndAggregate(b *testing.B) {
	message := "this is a long message with more than 32 bytes!"
	var plainData bytes.Buffer
	plainData.WriteString(message)
	ID := "3000"
	c, shares, signers, err := Shares(128, 127, ID)
	s := bls.NewBLS12381Suite()
	if err != nil {
		panic(err.Error())
	}

	for _, v := range Input {
		b.Run(fmt.Sprintf("input_size_%d", v.input), func(b *testing.B) {
			for i := 0; i < b.N; i++ {

				// Extracting the keys using shares
				var sk []ExtractedKey
				for k := 0; k < 100; k++ {
					if signers[k] == 1 {
						sk = append(sk, Extract(s, shares[k].Value, uint32(k+1), []byte(ID)))
					}
				}
				SK, _ := AggregateSK(s,
					sk,
					c, []byte(ID))
				_ = SK
			}

		})
	}

}
