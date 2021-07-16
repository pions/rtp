// +build gofuzz

package rtp

import "reflect"

// Fuzz implements a randomized fuzz test of the rtp
// parser using go-fuzz.
//
// To run the fuzzer, first download go-fuzz:
// `go get github.com/dvyukov/go-fuzz/...`
//
// Then build the testing package:
// `go-fuzz-build github.com/pions/rtp`
//
// And run the fuzzer on the corpus:
// ```
// go-fuzz -bin=rtp-fuzz.zip -workdir=fuzzer
// ````
func Fuzz(data []byte) int {
	var packet Packet
	if err := packet.Unmarshal(data); err != nil {
		return 0
	}
	out, err := packet.Marshal()
	if err != nil {
		return 0
	}
	if !reflect.DeepEqual(out, data) {
		panic("not equal")
	}

	return 1
}
