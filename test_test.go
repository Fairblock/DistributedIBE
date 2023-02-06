package tlock

import (
	"fmt"
	"math/rand"
	"testing"
)

func TestDistributedIBE(t *testing.T) {

	res, err := DistributedIBE(6, 3, "this is a size 32 bytes message!", "300")
	if res == false {
		t.Errorf(err.Error())
	}

}

func TestDistributedIBEFail(t *testing.T) {

	_, err := DistributedIBEFail(6, 3, "this is a size 32 bytes message!", "300")
	if err == nil {
		t.Errorf("Decryption worked with less than threshold keys!")
	}

}

func TestDistributedIBEFInvalidCommitment(t *testing.T) {

	_, err := DistributedIBEFInvalidCommitment(6, 3, "this is a size 32 bytes message!", "300")
	if err == nil {
		t.Errorf("Wrong commitment accepted!")
	}

}

func TestDistributedIBEFInvalidShare(t *testing.T) {

	_, err := DistributedIBEFInvalidShare(6, 3, "this is a size 32 bytes message!", "300")
	if err == nil {
		t.Errorf("Wrong share accepted!")
	}

}

var participants = []struct {
	input int
}{

	{input: 5},
	{input: 10},
	{input: 20},
	{input: 50},
	{input: 100},
}

func BenchmarkDistributedIBEE(b *testing.B) {
	for _, v := range participants {
		b.Run(fmt.Sprintf("input_size_%d", v.input), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				DistributedIBE(v.input, v.input-1, "this is a size 32 bytes message!", "300")
			}
		})
	}

}


var messageSize = []struct {
	input int
}{

	{input: 1},
	{input: 2},
	{input: 4},
	{input: 8},
	{input: 16},
    {input: 32},
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
			for i := 0; i < b.N; i++ {
				DistributedIBE(10, 7, randomStringGenerator(v.input), "300")
			}
		})
	}

}
