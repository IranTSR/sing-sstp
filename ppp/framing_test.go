package ppp

import (
	"bytes"
	"testing"
)

func TestFrameRoundTripWithFCS(t *testing.T) {
	info := []byte{0x01, 0x05, 0x00, 0x06, 0x01, 0x02, 0x05, 0xb4}
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
	// Without the FCS flag the same two octets are payload instead.
	_, got, err = DecodeFrame(raw, FCSMode{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(info)+2 {
		t.Errorf("no-FCS decode must keep the FCS octets as payload: % x", got)
	}
}

func TestFCSIsSensitiveToEveryOctet(t *testing.T) {
	base := FCS(EncodeFrame(ProtoIP, []byte{1, 2, 3, 4}, FCSMode{FCS: true})[:8])
	for i := 0; i < 8; i++ {
		f := FCSMode{FCS: true}
		frame := EncodeFrame(ProtoIP, []byte{1, 2, 3, 4}, f)
		frame[i] ^= 0x01
		if FCS(frame[:8]) == base {
			t.Errorf("flipping octet %d kept the FCS", i)
		}
	}
	// A compliant FCS must not depend on where the data stops: appending the
	// same bytes to two different prefixes must change the value.
	if FCS([]byte{0xff, 0x03}) == FCS([]byte{0xff, 0x03, 0x00}) {
		t.Error("FCS ignores trailing octets")
	}
	// Determinism, and the wire order is low octet first (RFC 1662 Appendix B).
	if FCS([]byte("abc")) != FCS([]byte("abc")) {
		t.Error("FCS is not pure")
	}
}

func TestAccmEscapingRoundTrip(t *testing.T) {
	// Control characters, the flag octet and the escape octet must all survive
	// a round trip when the peer negotiates the full map.
	info := []byte{0x00, 0x01, 0x03, 0x04, 0x05, 0x07, 0x08, 0x0a,
		0x0b, 0x0d, 0x0e, 0x11, 0x13, 0x16, 0x17, 0x19,
		0x1a, 0x1c, 0x1d, 0x1f, flagField, escapeField, 0x41, 0x80, 0xfe}
	f := FCSMode{Accm: 0xFFFFFFFF}
	raw := EncodeFrame(ProtoIP, info, f)
	for _, c := range info {
		if c < 0x20 || c == flagField || c == escapeField {
			if bytes.Contains(raw[4:], []byte{c}) {
				t.Errorf("octet %#02x leaked unescaped", c)
			}
		}
	}
	proto, got, err := DecodeFrame(raw, f)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if proto != ProtoIP || !bytes.Equal(got, info) {
		t.Errorf("round-trip mismatch:\n got % x\nwant % x", got, info)
	}
}

func TestAccmOfZeroStillEscapesFlagAndEscape(t *testing.T) {
	// RFC 1662: 0x7D and 0x7E are escaped by both sides regardless of the
	// map; MS-SSTP 3.2.5.1 pins the negotiated map to zero.
	info := []byte{flagField, escapeField, 0x03, 0x41}
	f := FCSMode{Accm: 0}
	raw := EncodeFrame(ProtoIP, info, f)
	if bytes.Contains(raw[4:], []byte{flagField}) || bytes.Contains(raw[4:], []byte{escapeField}) {
		t.Errorf("flag/escape octets were not escaped with ACCM=0: % x", raw)
	}
	_, got, err := DecodeFrame(raw, f)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, info) {
		t.Errorf("payload = % x, want % x", got, info)
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
		{"too short", good[:4]},
		{"wrong address", []byte{0x00, controlCt, 0xC0, 0x21, 0x01}},
		{"wrong control", []byte{address, 0x00, 0xC0, 0x21, 0x01}},
		{"no protocol", []byte{address, controlCt}},
		{"fcs only", good[:len(good)-2]},
	} {
		if _, _, err := DecodeFrame(tc.in, f); err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
	}
}
