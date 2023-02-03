package tlock

import (
	"fmt"
	"testing"
)

func TestDistributedIBEE(t *testing.T) {


	TestDistributedIBE(6,3)
	
	
}
var table = []struct {
    input int
}{
    {input: 1},
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
                TestDistributedIBE(v.input, v.input-1)
            }
        })
    }
	
	
}