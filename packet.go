package rtp

import (
	"encoding/binary"
	"fmt"

	"github.com/pkg/errors"
)

// TODO(@kixelated) Remove Header.PayloadOffset and Packet.Raw

// Header represents an RTP packet header
// NOTE: PayloadOffset is populated by Marshal/Unmarshal and should not be modified
type Header struct {
	Version          uint8
	Padding          bool
	Extension        bool
	Marker           bool
	PayloadOffset    int
	PayloadType      uint8
	SequenceNumber   uint16
	Timestamp        uint32
	SSRC             uint32
	CSRC             []uint32
	ExtensionProfile uint16
	ExtensionPayload []byte
}

// Packet represents an RTP Packet
// NOTE: Raw is populated by Marshal/Unmarshal and should not be modified
type Packet struct {
	Header
	Raw     []byte
	Payload []byte
}

const (
	headerLength    = 4
	versionShift    = 6
	versionMask     = 0x3
	paddingShift    = 5
	paddingMask     = 0x1
	extensionShift  = 4
	extensionMask   = 0x1
	ccMask          = 0xF
	markerShift     = 7
	markerMask      = 0x1
	ptMask          = 0x7F
	seqNumOffset    = 2
	seqNumLength    = 2
	timestampOffset = 4
	timestampLength = 4
	ssrcOffset      = 8
	ssrcLength      = 4
	csrcOffset      = 12
	csrcLength      = 4
)

// String helps with debugging by printing packet information in a readable way
func (p Packet) String() string {
	out := "RTP PACKET:\n"

	out += fmt.Sprintf("\tVersion: %v\n", p.Version)
	out += fmt.Sprintf("\tMarker: %v\n", p.Marker)
	out += fmt.Sprintf("\tPayload Type: %d\n", p.PayloadType)
	out += fmt.Sprintf("\tSequence Number: %d\n", p.SequenceNumber)
	out += fmt.Sprintf("\tTimestamp: %d\n", p.Timestamp)
	out += fmt.Sprintf("\tSSRC: %d (%x)\n", p.SSRC, p.SSRC)
	out += fmt.Sprintf("\tPayload Length: %d\n", len(p.Payload))

	return out
}

// Unmarshal parses the passed byte slice and stores the result in the Header this method is called upon
func (h *Header) Unmarshal(rawPacket []byte) error {
	if len(rawPacket) < headerLength {
		return errors.Errorf("RTP header size insufficient; %d < %d", len(rawPacket), headerLength)
	}

	/*
	 *  0                   1                   2                   3
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |V=2|P|X|  CC   |M|     PT      |       sequence number         |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |                           timestamp                           |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |           synchronization source (SSRC) identifier            |
	 * +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	 * |            contributing source (CSRC) identifiers             |
	 * |                             ....                              |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	h.Version = rawPacket[0] >> versionShift & versionMask
	h.Padding = (rawPacket[0] >> paddingShift & paddingMask) > 0
	h.Extension = (rawPacket[0] >> extensionShift & extensionMask) > 0
	h.CSRC = make([]uint32, rawPacket[0]&ccMask)

	h.Marker = (rawPacket[1] >> markerShift & markerMask) > 0
	h.PayloadType = rawPacket[1] & ptMask

	h.SequenceNumber = binary.BigEndian.Uint16(rawPacket[seqNumOffset : seqNumOffset+seqNumLength])
	h.Timestamp = binary.BigEndian.Uint32(rawPacket[timestampOffset : timestampOffset+timestampLength])
	h.SSRC = binary.BigEndian.Uint32(rawPacket[ssrcOffset : ssrcOffset+ssrcLength])

	currOffset := csrcOffset + (len(h.CSRC) * csrcLength)
	if len(rawPacket) < currOffset {
		return errors.Errorf("RTP header size insufficient; %d < %d", len(rawPacket), currOffset)
	}

	for i := range h.CSRC {
		offset := csrcOffset + (i * csrcLength)
		h.CSRC[i] = binary.BigEndian.Uint32(rawPacket[offset:])
	}

	if h.Extension {
		if len(rawPacket) < currOffset+4 {
			return errors.Errorf("RTP header size insufficient for extension; %d < %d", len(rawPacket), currOffset)
		}

		h.ExtensionProfile = binary.BigEndian.Uint16(rawPacket[currOffset:])
		currOffset += 2
		extensionLength := int(binary.BigEndian.Uint16(rawPacket[currOffset:])) * 4
		currOffset += 2

		if len(rawPacket) < currOffset+extensionLength {
			return errors.Errorf("RTP header size insufficient for extension length; %d < %d", len(rawPacket), currOffset+extensionLength)
		}

		h.ExtensionPayload = rawPacket[currOffset : currOffset+extensionLength]
		currOffset += len(h.ExtensionPayload)
	}
	h.PayloadOffset = currOffset

	return nil
}

// Unmarshal parses the passed byte slice and stores the result in the Packet this method is called upon
func (p *Packet) Unmarshal(rawPacket []byte) error {
	if err := p.Header.Unmarshal(rawPacket); err != nil {
		return err
	}

	p.Payload = rawPacket[p.PayloadOffset:]
	p.Raw = rawPacket
	return nil
}

// Marshal serializes the header into bytes.
func (h *Header) Marshal() ([]byte, error) {
	buf := make([]byte, 0, h.marshalSize())
	return h.MarshalTo(buf)
}

// MarshalTo serializes the header and appends to the buffer.
func (h *Header) MarshalTo(buf []byte) ([]byte, error) {
	/*
	 *  0                   1                   2                   3
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |V=2|P|X|  CC   |M|     PT      |       sequence number         |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |                           timestamp                           |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |           synchronization source (SSRC) identifier            |
	 * +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	 * |            contributing source (CSRC) identifiers             |
	 * |                             ....                              |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	// Get the initial size of the buffer.
	origLen := len(buf)

	b0 := (h.Version << versionShift) | uint8(len(h.CSRC))
	if h.Padding {
		b0 |= 1 << paddingShift
	}

	if h.Extension {
		b0 |= 1 << extensionShift
	}

	b1 := h.PayloadType
	if h.Marker {
		b1 = 1 << markerShift
	}

	buf = append(buf,
		b0,
		b1,
		byte(h.SequenceNumber>>8),
		byte(h.SequenceNumber),
		byte(h.Timestamp>>24),
		byte(h.Timestamp>>16),
		byte(h.Timestamp>>8),
		byte(h.Timestamp),
		byte(h.SSRC>>24),
		byte(h.SSRC>>16),
		byte(h.SSRC>>8),
		byte(h.SSRC),
	)

	for _, csrc := range h.CSRC {
		buf = append(buf,
			byte(csrc>>24),
			byte(csrc>>16),
			byte(csrc>>8),
			byte(csrc),
		)
	}

	if h.Extension {
		extSize := len(h.ExtensionPayload) / 4

		buf = append(buf,
			byte(h.ExtensionProfile>>8),
			byte(h.ExtensionProfile),
			byte(extSize>>8),
			byte(extSize),
		)

		buf = append(buf, h.ExtensionPayload...)
	}

	// Calculate the size of the header by seeing how many bytes we're written.
	// This should be the same as h.marshalSize()
	h.PayloadOffset = len(buf) - origLen

	return buf, nil
}

// marshalSize returns the size of the header once marshaled.
func (h *Header) marshalSize() int {
	// NOTE: Be careful to match the MarshalTo() method.
	size := 12 + (len(h.CSRC) * csrcLength)

	if h.Extension {
		size += 4 + len(h.ExtensionPayload)
	}

	return size
}

// Marshal serializes the packet into bytes.
func (p *Packet) Marshal() ([]byte, error) {
	buf := make([]byte, 0, p.marshalSize())
	return p.MarshalTo(buf)
}

// MarshalTo serializes the packet and appends to the buffer.
func (p *Packet) MarshalTo(buf []byte) ([]byte, error) {
	buf, err := p.Header.MarshalTo(buf)
	if err != nil {
		return nil, err
	}

	buf = append(buf, p.Payload...)
	p.Raw = buf

	return buf, nil
}

// marshalSize returns the size of the packet once marshaled.
func (p *Packet) marshalSize() int {
	return p.Header.marshalSize() + len(p.Payload)
}
