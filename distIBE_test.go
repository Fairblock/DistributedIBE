package distIBE

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"reflect"
	"sync"
	"testing"

	enc "github.com/FairBlock/DistributedIBE/encryption"
	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
)

func TestVSS(t *testing.T) {

	err := VSSTest(4, 2)

	if err != nil {
		t.Errorf(err.Error())
	}

}

func TestDistributedIBE(t *testing.T) {
	message := "this is a long message with more than 32 bytes! this is a long message with more than 32 bytes!long message with more than 32 bytes! this is a long message with long message with more than 32 bytes! this is a long message with long message with more than 32 bytes! this is a long message with long message with more than 32 bytes! this is a long message with long message with more than 32 bytes! this is a long message with long message with more than 32 bytes! this is a long message with long message with more than 32 bytes! this is a long message with "
	var plainData bytes.Buffer
	plainData.WriteString(message)

	res, err := DistributedIBE(4, 1, "300", plainData, message)

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

func BenchmarkVSS(b *testing.B) {

	for _, v := range participants {
		shares, _, commitments, err := GenerateShares(uint32(v.input), uint32(v.input)-1)
		if err != nil {
			panic(err.Error())
		}
		b.Run(fmt.Sprintf("input_size_%d", v.input), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				for i := 0; uint32(i) < uint32(v.input); i++ {
					res := VerifyVSSShare(shares[i], commitments)
					if !res {
						panic("wrong share")
					}
				}
			}
		})
	}

}

func BenchmarkVSSShareGen(b *testing.B) {

	for _, v := range participants {

		b.Run(fmt.Sprintf("input_size_%d", v.input), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, _, err := GenerateShares(uint32(v.input), uint32(v.input)-1)
				if err != nil {
					panic(err.Error())
				}
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
	{input: 32768},
	{input: 131072},
	{input: 524288},
	{input: 1048576},
	{input: 10485760},
	{input: 104857600},
}

func randomStringGenerator(n int) string {

	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	byteString := make([]byte, n)

	for i := range byteString {

		randomBytes := make([]byte, 1)
		rand.Read(randomBytes)
		index := int(randomBytes[0]) % len(letters)
		byteString[i] = letters[index]
	}

	return string(byteString)
}

func BenchmarkDistributedIBEEMessageSize(b *testing.B) {

	const (
		nParticipants = 4
		threshold     = 3
		identity      = "300"
		warmupRuns    = 3
	)

	messages := make(map[int]string)
	plainDataBuffers := make(map[int]bytes.Buffer)

	for _, v := range messageSize {
		message := randomStringGenerator(v.input)
		messages[v.input] = message

		var plainData bytes.Buffer
		plainData.WriteString(message)
		plainDataBuffers[v.input] = plainData
	}

	for _, v := range messageSize {
		message := messages[v.input]
		plainData := plainDataBuffers[v.input]

		b.Run(fmt.Sprintf("MessageSize_%d_bytes", v.input), func(b *testing.B) {

			for i := 0; i < warmupRuns; i++ {
				_, err := DistributedIBE(nParticipants, threshold, identity, plainData, message)
				if err != nil {
					b.Fatalf("Warm-up run failed: %v", err)
				}
			}

			b.ResetTimer()

			for i := 0; i < b.N; i++ {

				b.ReportAllocs()

				success, err := DistributedIBE(nParticipants, threshold, identity, plainData, message)

				if !success {
					b.Fatalf("DistributedIBE failed: %v", err)
				}
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

func BenchmarkDecryptionParallel(b *testing.B) {
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

	var wg sync.WaitGroup
	for _, v := range messageNum {
		b.Run(fmt.Sprintf("input_size_%d", v.input), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				wg.Add(v.input)
				for j := 0; j < v.input; j++ {

					go DecryptParallel(PK, SK, cipher, &wg)

				}
				wg.Wait()

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

func BenchmarkDistributedIBEComprehensive(b *testing.B) {

	b.Run("MessageSize", BenchmarkDistributedIBEEMessageSize)
	b.Run("DecryptionOnly", BenchmarkDistributedIBEDecryptionOnly)
	b.Run("EncryptionOnly", BenchmarkDistributedIBEEncryptionOnly)

}

func BenchmarkDistributedIBEDecryptionOnly(b *testing.B) {
	const (
		nParticipants = 4
		threshold     = 3
		identity      = "300"
		warmupRuns    = 3
	)

	type testData struct {
		message    string
		cipherData bytes.Buffer
		PK         kyber.Point
		SK         kyber.Point
	}

	testDataMap := make(map[int]testData)

	for _, v := range messageSize {
		message := randomStringGenerator(v.input)
		var plainData bytes.Buffer
		plainData.WriteString(message)

		shares, PK, _, _ := GenerateShares(uint32(nParticipants), uint32(threshold))

		signers := make([]int, nParticipants)
		for i := 0; i < nParticipants; i++ {
			signers[i] = 0
		}
		j := 0
		for j < threshold+1 {
			randomVal, _ := rand.Int(rand.Reader, big.NewInt(int64(nParticipants)))
			if signers[randomVal.Int64()] == 0 {
				signers[randomVal.Int64()] = 1
				j++
			}
		}

		s := bls.NewBLS12381Suite()
		var c []Commitment
		for j := 0; j < nParticipants; j++ {
			if signers[j] == 1 {
				c = append(c, Commitment{s.G1().Point().Mul(shares[j].Value, s.G1().Point().Base()), uint32(j + 1)})
			}
		}

		var sk []ExtractedKey
		for k := 0; k < nParticipants; k++ {
			if signers[k] == 1 {
				sk = append(sk, Extract(s, shares[k].Value, uint32(k+1), []byte(identity)))
			}
		}

		SK, _ := AggregateSK(s, sk, c, []byte(identity))

		var cipherData bytes.Buffer
		_ = enc.Encrypt(PK, []byte(identity), &cipherData, &plainData)

		testDataMap[v.input] = testData{
			message:    message,
			cipherData: cipherData,
			PK:         PK,
			SK:         SK,
		}
	}

	for _, v := range messageSize {
		data := testDataMap[v.input]

		b.Run(fmt.Sprintf("DecryptionOnly_%d_bytes", v.input), func(b *testing.B) {

			for i := 0; i < warmupRuns; i++ {
				success, err := Decrypt(data.PK, data.SK, data.cipherData)
				if !success {
					b.Fatalf("Warm-up decryption failed: %v", err)
				}
			}

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				b.ReportAllocs()

				success, err := Decrypt(data.PK, data.SK, data.cipherData)
				if !success {
					b.Fatalf("Decryption failed: %v", err)
				}
			}
		})
	}
}

func BenchmarkDistributedIBEEncryptionOnly(b *testing.B) {
	const (
		nParticipants = 4
		threshold     = 3
		identity      = "300"
		warmupRuns    = 3
	)

	type testData struct {
		message   string
		plainData bytes.Buffer
		PK        kyber.Point
	}

	testDataMap := make(map[int]testData)

	for _, v := range messageSize {
		message := randomStringGenerator(v.input)
		var plainData bytes.Buffer
		plainData.WriteString(message)

		shares, PK, _, _ := GenerateShares(uint32(nParticipants), uint32(threshold))

		_ = shares

		testDataMap[v.input] = testData{
			message:   message,
			plainData: plainData,
			PK:        PK,
		}
	}

	for _, v := range messageSize {
		data := testDataMap[v.input]

		b.Run(fmt.Sprintf("EncryptionOnly_%d_bytes", v.input), func(b *testing.B) {

			for i := 0; i < warmupRuns; i++ {
				var cipherData bytes.Buffer
				err := enc.Encrypt(data.PK, []byte(identity), &cipherData, &data.plainData)
				if err != nil {
					b.Fatalf("Warm-up encryption failed: %v", err)
				}
			}

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				b.ReportAllocs()

				var cipherData bytes.Buffer
				err := enc.Encrypt(data.PK, []byte(identity), &cipherData, &data.plainData)
				if err != nil {
					b.Fatalf("Encryption failed: %v", err)
				}
			}
		})
	}
}



func BenchmarkDistributedIBEAggregationOnly(b *testing.B) {
	const (
		identity   = "300"
		warmupRuns = 3
	)

	participantConfigs := []struct {
		nParticipants int
		threshold     int
	}{
		{4, 3}, {8, 6}, {16, 11}, {32, 22}, {64, 43},
		{128, 86}, {256, 171}, {512, 342}, {1024, 683},
	}

	for _, config := range participantConfigs {
		b.Run(fmt.Sprintf("AggregationOnly_%dp_%dt", config.nParticipants, config.threshold), func(b *testing.B) {
			ID := identity
			c, shares, signers, err := Shares(config.nParticipants, config.threshold, ID)
			s := bls.NewBLS12381Suite()
			if err != nil {
				panic(err.Error())
			}

			for i := 0; i < warmupRuns; i++ {
				b.StopTimer()
				var sk []ExtractedKey
				for k := 0; k < config.nParticipants; k++ {
					if signers[k] == 1 {
						sk = append(sk, Extract(s, shares[k].Value, uint32(k+1), []byte(ID)))
					}
				}
				b.StartTimer()
				_, _ = AggregateSK(s, sk, c, []byte(ID))
			}

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				b.ReportAllocs()
				b.StopTimer()
				var sk []ExtractedKey
				for k := 0; k < config.nParticipants; k++ {
					if signers[k] == 1 {
						sk = append(sk, Extract(s, shares[k].Value, uint32(k+1), []byte(ID)))
					}
				}
				b.StartTimer()
				_, _ = AggregateSK(s, sk, c, []byte(ID))
			}
		})
	}
}
