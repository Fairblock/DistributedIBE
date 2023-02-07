package tlock

import (
	"fmt"
	"bytes"
	"reflect"

	"math/rand"

	"testing"
)

func TestDistributedIBE(t *testing.T) {
	message := "this is a long message with more than 32 bytes! this is a long message with more than 32 bytes!"
	var plainData bytes.Buffer
	plainData.WriteString(message)

	res, err := DistributedIBE(6, 3, "300",plainData, message)
	if res == false {
		t.Errorf(err.Error())
	}

}

func TestDistributedIBEFail(t *testing.T) {

	message := "this is a long message with more than 32 bytes!"
	var plainData bytes.Buffer
	plainData.WriteString(message)

	res, err := DistributedIBEFail(6, 3, "300",plainData, message)

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

	_, err := DistributedIBEFInvalidCommitment(6, 3, "300",plainData, message)
	
	if err == nil {
		t.Errorf("Wrong commitment accepted!")
	}



}

func TestDistributedIBEFInvalidShare(t *testing.T) {

	message := "this is a long message with more than 32 bytes!"
	var plainData bytes.Buffer
	plainData.WriteString(message)

	_, err := DistributedIBEFInvalidShare(6, 3, "300",plainData, message)

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
	message := "this is a long message with more than 32 bytes!"
	var plainData bytes.Buffer
	plainData.WriteString(message)
	for _, v := range participants {
		b.Run(fmt.Sprintf("input_size_%d", v.input), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
			DistributedIBE(6, 3, "300",plainData, message)
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
				DistributedIBE(6, 3, "300",plainData, message)
			}
		})
	}

}
