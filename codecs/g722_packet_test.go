package codecs //nolint:dupl

import (
	"bytes"
	"crypto/rand"
	"math"
	"testing"
)

func TestG722Payloader(t *testing.T) {
	p := G722Payloader{}

	const (
		testlen = 10000
		testmtu = 1500
	)

	// generate random 8-bit g722 samples
	samples := make([]byte, testlen)
	_, err := rand.Read(samples)
	if err != nil {
		t.Fatal("RNG Error: ", err)
	}

	// make a copy, for payloader input
	samplesIn := make([]byte, testlen)
	copy(samplesIn, samples)

	// split our samples into payloads
	payloads := p.Payload(testmtu, samplesIn)

	outcnt := int(math.Ceil(float64(testlen) / testmtu))
	if len(payloads) != outcnt {
		t.Fatalf("Generated %d payloads instead of %d", len(payloads), outcnt)
	}

	if !bytes.Equal(samplesIn, samples) {
		t.Fatal("Modified input samples")
	}

	samplesOut := bytes.Join(payloads, []byte{})

	if !bytes.Equal(samplesIn, samplesOut) {
		t.Fatal("Output samples don't match")
	}

	payload := []byte{0x90, 0x90, 0x90}

	// 0 MTU, small payload
	res := p.Payload(0, payload)
	if len(res) != 0 {
		t.Fatal("Generated payload should be empty")
	}

	// Positive MTU, small payload
	res = p.Payload(1, payload)
	if len(res) != len(payload) {
		t.Fatal("Generated payload should be the same size as original payload size")
	}

	// Positive MTU, small payload
	res = p.Payload(uint16(len(payload)-1), payload)
	if len(res) != len(payload)-1 {
		t.Fatal("Generated payload should be the same smaller than original payload size")
	}

	// Positive MTU, small payload
	res = p.Payload(10, payload)
	if len(res) != 1 {
		t.Fatal("Generated payload should be 1")
	}
}
