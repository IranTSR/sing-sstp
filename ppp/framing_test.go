package ppp

import (
	"bytes"
	"testing"
)

func TestFrameRoundTripWithFCS(t *testing.T) {
	info := []byte{0x01, 0x05, 0x00, 0x06, 0x01, 0x02, 0x05, 0xb4} // LCP Conf-Request id=5, MRU 1460
	f := FCSMode{FCS: true}
	raw := EncodeFrame(ProtoLCP, info, f)
	proto, got, err := DecodeFrame(raw, f)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if proto != ProtoLCP || !bytes.Equal(got, info) {
		t.Fatalf("round trip = %#x % x, want %#x % x", proto, got, ProtoLCP, info)
	}

	bad := append([]byte(nil), raw...)
	bad[len(bad)-1] ^= 0x08
	if _, _, err := DecodeFrame(bad, f); err != ErrFCSMismatch {
		t.Errorf("corrupted frame accepted: %v", err)
	}

	// Decoding a frame that carries a CRC without asking for one must not
	// silently lose two payload octets: the information field keeps them and
	// the control header length check is what tells the two apart.
	if _, got, err := DecodeFrame(raw, FCSMode{}); err != nil {
		t.Fatalf("FCS-off decode: %v", err)
	} else if len(got) != len(info)+2 {
		t.Errorf("FCS-off decode kept %d octets, want %d", len(got), len(info)+2)
	}
}

func TestFCSIsSensible(t *testing.T) {
	// The CRC is a function of the exact octet sequence: flipping any bit of
	// the header or the payload must change it, and the same bytes must
	// always give the same value.
	frame := EncodeFrame(ProtoIP, []byte{1, 2, 3, 4}, FCSMode{FCS: true})
	base := fcsValue(frame[:len(frame)-2])
	for i := 0; i < len(frame)-2; i++ {
		flipped := append([]byte(nil), frame...)
		flipped[i] ^= 0x01
		if fcsValue(flipped[:len(flipped)-2]) == base {
			t.Errorf("flipping bit 0 of octet %d kept the FCS", i)
		}
	}
	if fcsValue(frame[:len(frame)-2]) != base {
		t.Error("FCS is not pure")
	}
	if fcsValue([]byte{1, 2}) == fcsValue([]byte{1, 2, 0}) {
		t.Error("FCS ignores trailing octets")
	}
	// The wire order is low octet first: both halves of the little-endian
	// result must be visible in the frame tail.
	c := FCS(frame[:len(frame)-2])
	if frame[len(frame)-2] != c[0] || frame[len(frame)-1] != c[1] {
		t.Errorf("frame tail % x, FCS % x", frame[len(frame)-2:], c)
	}
}

func TestAccmEscapingRoundTrip(t *testing.T) {
	info := []byte{0x00, 0x01, 0x03, 0x04, 0x05, 0x07, 0x08, 0x0a,
		0x0b, 0x0d, 0x0e, 0x11, 0x13, 0x16, 0x17, 0x19,
		0x1a, 0x1c, 0x1d, 0x1f, flagField, escapeField, 0x41, 0x80, 0xfe}
	f := FCSMode{Accm: 0xFFFFFFFF}
	raw := EncodeFrame(ProtoIP, info, f)

	// Walk the escaped stream: 0x7D must always introduce a pair, and no
	// control octet may appear bare.
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == escapeField {
			if i+1 >= len(raw) {
				t.Fatalf("trailing escape octet with nothing to introduce")
			}
			i++
			continue
		}
		if c < 0x20 || c == flagField {
			t.Errorf("octet %#02x at %d should have been escaped", c, i)
		}
	}
	proto, got, err := DecodeFrame(raw, f)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if proto != ProtoIP {
		t.Errorf("protocol = %#x, want ProtoIP", proto)
	}
	if !bytes.Equal(got, info) {
		t.Errorf("round trip mismatch:\n got % x\nwant % x", got, info)
	}
}

func TestAccmOfZeroStillEscapesFlagAndEscape(t *testing.T) {
	// RFC 1662 and MS-SSTP 3.2.5.1: the negotiated map is zero, yet 0x7D and
	// 0x7E stay escaped in both directions, and 0x03 stays bare.
	info := []byte{flagField, escapeField, 0x03, 0x41}
	f := FCSMode{Accm: 0}
	raw := EncodeFrame(ProtoIP, info, f)

	// Structural expectations: the header is uncompressed, exactly the two
	// dangerous octets are escaped, 0x03 stays bare and nothing else changed.
	if !bytes.HasPrefix(raw, []byte{address, controlCt, 0x00, 0x21}) {
		t.Fatalf("header not uncompressed: % x", raw)
	}
	body := raw[4:]
	pairs := bytes.Split(body, []byte{escapeField})
	if len(pairs) != 3 {
		t.Fatalf("expected exactly two escape sequences, got % x", body)
	}
	if len(pairs[1]) == 0 || pairs[1][0] != flagField^escapeXOR {
		t.Errorf("0x7E was not escaped as % x", body)
	}
	if len(pairs[2]) == 0 || pairs[2][0] != escapeField^escapeXOR {
		t.Errorf("0x7D was not escaped as % x", body)
	}
	if !bytes.HasSuffix(pairs[2], []byte{0x03, 0x41}) {
		t.Errorf("0x03/0x41 should stay unescaped with ACCM=0: % x", body)
	}
	if _, got, err := DecodeFrame(raw, f); err != nil || !bytes.Equal(got, info) {
		t.Errorf("decode = % x, %v, want % x", got, err, info)
	}
	// A bare flag octet inside the frame is a framing error, not data.
	if _, _, err := DecodeFrame(append([]byte{address, controlCt, 0x00, 0x21}, flagField), f); err != ErrFlagInFrame {
		t.Errorf("bare flag octet = %v, want ErrFlagInFrame", err)
	}
}

func TestDecodeFrameRejectsBadHeaders(t *testing.T) {
	f := FCSMode{FCS: true}
	good := EncodeFrame(ProtoLCP, []byte{0x01, 0x01, 0x00, 0x04}, f)
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"header only", []byte{address, controlCt, 0xC0, 0x21}},
		{"truncated FCS", good[:len(good)-2]},
		{"wrong address", append([]byte{0x00, controlCt}, good[2:]...)},
		{"wrong control", append([]byte{address, 0x00}, good[2:]...)},
		{"no protocol field", []byte{address, controlCt}},
	} {
		if _, _, err := DecodeFrame(tc.in, f); err == nil {
			t.Errorf("%s was accepted", tc.name)
		} else if err == ErrFCSMismatch && tc.name != "truncated FCS" {
			t.Errorf("%s rejected for the wrong reason: %v", tc.name, err)
		}
	}
}

// The wire frame must fit the negotiated MRU including every header and CRC
// octet, so an oversized information field is a protocol error the caller can
// detect before handing the frame to the peer.
func maxFrameLength(mru uint16, withFCS bool) int {
	// address + control + protocol (+ CRC) on top of the information field.
	n := int(mru) + 4
	if withFCS {
		n += 2
	}
	return n
}

func TestMaxFrameLengthCoversHeaderAndCRC(t *testing.T) {
	if got := maxFrameLength(1500, true); got != 1500+4+2 {
		t.Errorf("MaxFrameLength(1500) = %d, want %d (address+control+protocol+crc)", got, 1500+6)
	}
	if got := maxFrameLength(0, true); got != 6 {
		t.Errorf("MaxFrameLength(0) = %d, want 6", got)
	}
}

// A peer that escapes characters below 0x20 (ACCM bit set) must be encoded
// symmetrically: the sender MUST escape according to its own map, while the
// receiver unconditionally unescapes (it cannot know the sender's map).
func TestReceiverUnescapesRegardlessOfOwnAccm(t *testing.T) {
	peerMap := uint32(1 << 0x03) // peer escapes 0x03 although we asked for 0
	info := []byte{0x03}
	raw := EncodeFrame(ProtoIP, info, FCSMode{Accm: peerMap})
	if bytes.Contains(raw[4:], []byte{0x03}) {
		t.Fatalf("0x03 was not escaped by a peer with that map: % x", raw)
	}
	proto, got, err := DecodeFrame(raw, FCSMode{Accm: 0})
	if err != nil {
		t.Fatalf("decode with our own map zero: %v", err)
	}
	if proto != ProtoIP || !bytes.Equal(got, info) {
		t.Errorf("decoded % x, want % x", got, info)
	}
}
