package tlock

import (
	"fmt"
	"testing"
)

func TestDistributedIBEE(t *testing.T) {

	res, err := TestDistributedIBE(6, 3, "this is a size 32 bytes message!", "300")
	if res == false {
		t.Errorf(err.Error())
	}

}

var table = []struct {
	input int
}{

	{input: 5},
	{input: 10},
	{input: 20},
	{input: 50},
	{input: 100},
}

func BenchmarkDistributedIBEE(b *testing.B) {
	for _, v := range table {
		b.Run(fmt.Sprintf("input_size_%d", v.input), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				TestDistributedIBE(v.input, v.input-1, "this is a size 32 bytes message!", "300")
			}
		})
	}

}

func TestDistributedIBEFailingCase(t *testing.T) {

	_, err := TestDistributedIBEFail(6, 3, "this is a size 32 bytes message!", "300")
	if err == nil {
		t.Errorf("Decryption worked with less than threshold keys!")
	}

}
