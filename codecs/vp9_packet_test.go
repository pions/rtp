package codecs

import (
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"testing"
)

func TestVP9Packet_Unmarshal(t *testing.T) {
	cases := map[string]struct {
		b   []byte
		pkt VP9Packet
		err error
	}{
		"Nil": {
			b:   nil,
			err: errNilPacket,
		},
		"Empty": {
			b:   []byte{},
			err: errShortPacket,
		},
		"NonFlexible": {
			b: []byte{0x00, 0xAA},
			pkt: VP9Packet{
				Payload: []byte{0xAA},
			},
		},
		"NonFlexiblePictureID": {
			b: []byte{0x80, 0x02, 0xAA},
			pkt: VP9Packet{
				I:         true,
				PictureID: 0x02,
				Payload:   []byte{0xAA},
			},
		},
		"NonFlexiblePictureIDExt": {
			b: []byte{0x80, 0x81, 0xFF, 0xAA},
			pkt: VP9Packet{
				I:         true,
				PictureID: 0x01FF,
				Payload:   []byte{0xAA},
			},
		},
		"NonFlexiblePictureIDExt_ShortPacket0": {
			b:   []byte{0x80, 0x81},
			err: errShortPacket,
		},
		"NonFlexiblePictureIDExt_ShortPacket1": {
			b:   []byte{0x80},
			err: errShortPacket,
		},
		"NonFlexibleLayerIndicePictureID": {
			b: []byte{0xA0, 0x02, 0x23, 0x01, 0xAA},
			pkt: VP9Packet{
				I:         true,
				L:         true,
				PictureID: 0x02,
				TID:       0x01,
				SID:       0x01,
				D:         true,
				TL0PICIDX: 0x01,
				Payload:   []byte{0xAA},
			},
		},
		"FlexibleLayerIndicePictureID": {
			b: []byte{0xB0, 0x02, 0x23, 0x01, 0xAA},
			pkt: VP9Packet{
				F:         true,
				I:         true,
				L:         true,
				PictureID: 0x02,
				TID:       0x01,
				SID:       0x01,
				D:         true,
				Payload:   []byte{0x01, 0xAA},
			},
		},
		"NonFlexibleLayerIndicePictureID_ShortPacket0": {
			b:   []byte{0xA0, 0x02, 0x23},
			err: errShortPacket,
		},
		"NonFlexibleLayerIndicePictureID_ShortPacket1": {
			b:   []byte{0xA0, 0x02},
			err: errShortPacket,
		},
		"FlexiblePictureIDRefIndex": {
			b: []byte{0xD0, 0x02, 0x03, 0x04, 0xAA},
			pkt: VP9Packet{
				I:         true,
				P:         true,
				F:         true,
				PictureID: 0x02,
				PDiff:     []uint8{0x01, 0x02},
				Payload:   []byte{0xAA},
			},
		},
		"FlexiblePictureIDRefIndex_TooManyPDiff": {
			b:   []byte{0xD0, 0x02, 0x03, 0x05, 0x07, 0x09, 0x10, 0xAA},
			err: errTooManyPDiff,
		},
		"FlexiblePictureIDRefIndexNoPayload": {
			b: []byte{0xD0, 0x02, 0x03, 0x04},
			pkt: VP9Packet{
				I:         true,
				P:         true,
				F:         true,
				PictureID: 0x02,
				PDiff:     []uint8{0x01, 0x02},
				Payload:   []byte{},
			},
		},
		"FlexiblePictureIDRefIndex_ShortPacket0": {
			b:   []byte{0xD0, 0x02, 0x03},
			err: errShortPacket,
		},
		"FlexiblePictureIDRefIndex_ShortPacket1": {
			b:   []byte{0xD0, 0x02},
			err: errShortPacket,
		},
		"FlexiblePictureIDRefIndex_ShortPacket2": {
			b:   []byte{0xD0},
			err: errShortPacket,
		},
		"ScalabilityStructureResolutionsNoPayload": {
			b: []byte{
				0x0A,
				(1 << 5) | (1 << 4), // NS:1 Y:1 G:0
				640 >> 8, 640 & 0xff,
				360 >> 8, 360 & 0xff,
				1280 >> 8, 1280 & 0xff,
				720 >> 8, 720 & 0xff,
			},
			pkt: VP9Packet{
				B:       true,
				V:       true,
				NS:      1,
				Y:       true,
				G:       false,
				NG:      0,
				Width:   []uint16{640, 1280},
				Height:  []uint16{360, 720},
				Payload: []byte{},
			},
		},
		"ScalabilityStructureNoPayload": {
			b: []byte{
				0x0A,
				(1 << 5) | (0 << 4) | (1 << 3), // NS:1 Y:0 G:1
				2,
				(0 << 5) | (1 << 4) | (0 << 2), // T:0 U:1 R:0 -
				(2 << 5) | (0 << 4) | (1 << 2), // T:2 U:0 R:1 -
				33,
			},
			pkt: VP9Packet{
				B:       true,
				V:       true,
				NS:      1,
				Y:       false,
				G:       true,
				NG:      2,
				PGTID:   []uint8{0, 2},
				PGU:     []bool{true, false},
				PGPDiff: [][]uint8{{}, {33}},
				Payload: []byte{},
			},
		},
	}
	for name, c := range cases {
		c := c
		t.Run(name, func(t *testing.T) {
			p := VP9Packet{}
			raw, err := p.Unmarshal(c.b)
			if c.err == nil {
				if raw == nil {
					t.Error("Result shouldn't be nil in case of success")
				}
				if err != nil {
					t.Error("Error should be nil in case of success")
				}
				if !reflect.DeepEqual(c.pkt, p) {
					t.Errorf("Unmarshalled packet expected to be:\n %v\ngot:\n %v", c.pkt, p)
				}
			} else {
				if raw != nil {
					t.Error("Result should be nil in case of error")
				}
				if !errors.Is(err, c.err) {
					t.Errorf("Error should be '%v', got '%v'", c.err, err)
				}
			}
		})
	}
}

func TestVP9Payloader_Payload(t *testing.T) {
	r0 := int(rand.New(rand.NewSource(0)).Int31n(0x7FFF)) //nolint:gosec
	var rands [][2]byte
	for i := 0; i < 10; i++ {
		rands = append(rands, [2]byte{byte(r0>>8) | 0x80, byte(r0 & 0xFF)})
		r0++
	}

	cases := map[string]struct {
		b   [][]byte
		mtu uint16
		res [][]byte
	}{
		"NilPayload": {
			b:   [][]byte{nil},
			mtu: 100,
			res: [][]byte{},
		},
		"SmallMTU": {
			b:   [][]byte{{0x00, 0x00}},
			mtu: 1,
			res: [][]byte{},
		},
		"OnePacket": {
			b:   [][]byte{{0x01, 0x02}},
			mtu: 10,
			res: [][]byte{
				{0x9C, rands[0][0], rands[0][1], 0x01, 0x02},
			},
		},
		"TwoPackets": {
			b:   [][]byte{{0x01, 0x02}},
			mtu: 4,
			res: [][]byte{
				{0x98, rands[0][0], rands[0][1], 0x01},
				{0x94, rands[0][0], rands[0][1], 0x02},
			},
		},
		"ThreePackets": {
			b:   [][]byte{{0x01, 0x02, 0x03}},
			mtu: 4,
			res: [][]byte{
				{0x98, rands[0][0], rands[0][1], 0x01},
				{0x90, rands[0][0], rands[0][1], 0x02},
				{0x94, rands[0][0], rands[0][1], 0x03},
			},
		},
		"TwoFramesFourPackets": {
			b:   [][]byte{{0x01, 0x02, 0x03}, {0x04}},
			mtu: 5,
			res: [][]byte{
				{0x98, rands[0][0], rands[0][1], 0x01, 0x02},
				{0x94, rands[0][0], rands[0][1], 0x03},
				{0x9C, rands[1][0], rands[1][1], 0x04},
			},
		},
	}
	for name, c := range cases {
		pck := VP9Payloader{
			InitialPictureIDFn: func() uint16 {
				return uint16(rand.New(rand.NewSource(0)).Int31n(0x7FFF)) //nolint:gosec
			},
		}
		c := c
		t.Run(fmt.Sprintf("%s_MTU%d", name, c.mtu), func(t *testing.T) {
			res := [][]byte{}
			for _, b := range c.b {
				res = append(res, pck.Payload(c.mtu, b)...)
			}
			if !reflect.DeepEqual(c.res, res) {
				t.Errorf("Payloaded packet expected to be:\n %v\ngot:\n %v", c.res, res)
			}
		})
	}
	t.Run("PictureIDOverflow", func(t *testing.T) {
		pck := VP9Payloader{
			InitialPictureIDFn: func() uint16 {
				return uint16(rand.New(rand.NewSource(0)).Int31n(0x7FFF)) //nolint:gosec
			},
		}
		pPrev := VP9Packet{}
		for i := 0; i < 0x8000; i++ {
			res := pck.Payload(4, []byte{0x01})
			p := VP9Packet{}
			_, err := p.Unmarshal(res[0])
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if i > 0 {
				if pPrev.PictureID == 0x7FFF {
					if p.PictureID != 0 {
						t.Errorf("Picture ID next to 0x7FFF must be 0, got %d", p.PictureID)
					}
				} else if pPrev.PictureID+1 != p.PictureID {
					t.Errorf("Picture ID next must be incremented by 1: %d -> %d", pPrev.PictureID, p.PictureID)
				}
			}

			pPrev = p
		}
	})
}

func TestVP9PartitionHeadChecker_IsPartitionHead(t *testing.T) {
	checker := &VP9PartitionHeadChecker{}
	t.Run("SmallPacket", func(t *testing.T) {
		if checker.IsPartitionHead([]byte{}) {
			t.Fatal("Small packet should not be the head of a new partition")
		}
	})
	t.Run("NormalPacket", func(t *testing.T) {
		if !checker.IsPartitionHead([]byte{0x18, 0x00, 0x00}) {
			t.Error("VP9 RTP packet with B flag should be head of a new partition")
		}
		if checker.IsPartitionHead([]byte{0x10, 0x00, 0x00}) {
			t.Error("VP9 RTP packet without B flag should not be head of a new partition")
		}
	})
}
