package codecs

import (
	"errors"
	"testing"
)

func TestVP8Packet_Unmarshal(t *testing.T) {
	pck := VP8Packet{}

	// Nil packet
	raw, err := pck.Unmarshal(nil)
	if raw != nil {
		t.Fatal("Result should be nil in case of error")
	}
	if !errors.Is(err, errNilPacket) {
		t.Fatal("Error should be:", errNilPacket)
	}

	// Nil payload
	raw, err = pck.Unmarshal([]byte{})
	if raw != nil {
		t.Fatal("Result should be nil in case of error")
	}
	if !errors.Is(err, errShortPacket) {
		t.Fatal("Error should be:", errShortPacket)
	}

	// Payload smaller than header size
	raw, err = pck.Unmarshal([]byte{0x00, 0x11, 0x22})
	if raw != nil {
		t.Fatal("Result should be nil in case of error")
	}
	if !errors.Is(err, errShortPacket) {
		t.Fatal("Error should be:", errShortPacket)
	}

	// Normal payload
	raw, err = pck.Unmarshal([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x90})
	if raw == nil {
		t.Fatal("Result shouldn't be nil in case of success")
	}
	if err != nil {
		t.Fatal("Error should be nil in case of success")
	}

	// Header size, only X
	raw, err = pck.Unmarshal([]byte{0x80, 0x00, 0x00, 0x00})
	if raw == nil {
		t.Fatal("Result shouldn't be nil in case of success")
	}
	if err != nil {
		t.Fatal("Error should be nil in case of success")
	}

	// Header size, X and I
	raw, err = pck.Unmarshal([]byte{0x80, 0x80, 0x00, 0x00})
	if raw == nil {
		t.Fatal("Result shouldn't be nil in case of success")
	}
	if err != nil {
		t.Fatal("Error should be nil in case of success")
	}

	// Header size, X and I, PID 16bits
	raw, err = pck.Unmarshal([]byte{0x80, 0x80, 0x81, 0x00})
	if raw != nil {
		t.Fatal("Result should be nil in case of error")
	}
	if !errors.Is(err, errShortPacket) {
		t.Fatal("Error should be:", errShortPacket)
	}

	// Header size, X and L
	raw, err = pck.Unmarshal([]byte{0x80, 0x40, 0x00, 0x00})
	if raw == nil {
		t.Fatal("Result shouldn't be nil in case of success")
	}
	if err != nil {
		t.Fatal("Error should be nil in case of success")
	}

	// Header size, X and T
	raw, err = pck.Unmarshal([]byte{0x80, 0x20, 0x00, 0x00})
	if raw == nil {
		t.Fatal("Result shouldn't be nil in case of success")
	}
	if err != nil {
		t.Fatal("Error should be nil in case of success")
	}

	// Header size, X and K
	raw, err = pck.Unmarshal([]byte{0x80, 0x10, 0x00, 0x00})
	if raw == nil {
		t.Fatal("Result shouldn't be nil in case of success")
	}
	if err != nil {
		t.Fatal("Error should be nil in case of success")
	}

	// Header size, all flags
	raw, err = pck.Unmarshal([]byte{0xff, 0xff, 0x00, 0x00})
	if raw != nil {
		t.Fatal("Result should be nil in case of error")
	}
	if !errors.Is(err, errShortPacket) {
		t.Fatal("Error should be:", errShortPacket)
	}
}

func TestVP8Payloader_Payload(t *testing.T) {
	pck := VP8Payloader{}
	payload := []byte{0x90, 0x90, 0x90}

	// Positive MTU, nil payload
	res := pck.Payload(1, nil)
	if len(res) != 0 {
		t.Fatal("Generated payload should be empty")
	}

	// Positive MTU, small payload
	// MTU of 1 results in fragment size of 0
	res = pck.Payload(1, payload)
	if len(res) != 0 {
		t.Fatal("Generated payload should be empty")
	}

	// Positive MTU, small payload
	res = pck.Payload(2, payload)
	if len(res) != len(payload) {
		t.Fatal("Generated payload should be the same size as original payload size")
	}
}

func TestVP8PartitionHeadChecker_IsPartitionHead(t *testing.T) {
	checker := &VP8PartitionHeadChecker{}
	t.Run("SmallPacket", func(t *testing.T) {
		if checker.IsPartitionHead([]byte{0x00}) {
			t.Fatal("Small packet should not be the head of a new partition")
		}
	})
	t.Run("SFlagON", func(t *testing.T) {
		if !checker.IsPartitionHead([]byte{0x10, 0x00, 0x00, 0x00}) {
			t.Fatal("Packet with S flag should be the head of a new partition")
		}
	})
	t.Run("SFlagOFF", func(t *testing.T) {
		if checker.IsPartitionHead([]byte{0x00, 0x00, 0x00, 0x00}) {
			t.Fatal("Packet without S flag should not be the head of a new partition")
		}
	})
}
