package sstp

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"testing"
)

// The first half of this HLAK is the 128-bit send start key published in
// RFC 3079 section 3.5.3; the second half is its receive counterpart from the
// same derivation. It stands in for a live MS-CHAPv2 handshake so the
// compound-MAC path can be tested end to end in one place.
var testHLAK = mustHex("8B7CDC149B993A1BA118CB153F56DCCB" + "D5F0E9521E3EA9589645E86051C82226")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestPRFPlusLengths(t *testing.T) {
	seed := []byte(cmkSeed)
	if len(seed) != 29 {
		t.Fatalf("cmk seed is %d octets, MS-SSTP says 29", len(seed))
	}
	for _, tc := range []struct {
		n int
		h func() hash.Hash
	}{
		{20, sha1.New},
		{32, sha256.New},
		{48, sha256.New}, // crosses the T(i) boundary
	} {
		if got := prfPlus(testHLAK, seed, tc.n, tc.h); len(got) != tc.n {
			t.Errorf("prfPlus(%d) returned %d octets", tc.n, len(got))
		}
	}
}

// Values cross-checked against an independent implementation of the same
// spec text (MS-SSTP 3.2.5.2.2/3.2.5.2.4 plus RFC 4306 PRF+); they are not
// published vectors.
func TestCompoundMACKey(t *testing.T) {
	sha1Key := hex.EncodeToString(compoundMACKey(CertHashProtocolSHA1, testHLAK))
	if sha1Key != "437c0da87a59d1d10a04c4e345e9498d1561272a" {
		t.Errorf("CMK (SHA-1) = %s", sha1Key)
	}
	sha256Key := hex.EncodeToString(compoundMACKey(CertHashProtocolSHA256, testHLAK))
	if sha256Key != "e01e63cdde6f188d2e7dfc6f1e6178734b933bb8ed0bdc07812c2b58f17d517b" {
		t.Errorf("CMK (SHA-256) = %s", sha256Key)
	}
}

func TestCompoundMACShapes(t *testing.T) {
	nonce := bytes.Repeat([]byte{0xA7}, 32)
	cert := []byte("not-a-real-der-but-length-matters-only-to-the-hash")
	for _, tc := range []struct {
		id     byte
		macLen int
	}{
		{CertHashProtocolSHA256, 32},
		{CertHashProtocolSHA1, 20},
	} {
		mac, msg, err := CompoundMAC(tc.id, testHLAK, nonce, cert)
		if err != nil {
			t.Fatal(err)
		}
		if len(msg) != callConnectedLen {
			t.Errorf("message length = %d, want %d", len(msg), callConnectedLen)
		}
		if len(mac) != tc.macLen {
			t.Errorf("mac length = %d, want %d", len(mac), tc.macLen)
		}
		// The MAC field must sit at the very end of the 112-octet message.
		if off := callConnectedLen - tc.macLen; msg[off] == 0 && msg[off+tc.macLen-1] == 0 {
			t.Errorf("mac field at %d looks unwritten", off)
		}
		// The encoded message must round-trip through the decoder.
		p, err := Decode(msg)
		if err != nil {
			t.Fatalf("decode Call Connected: %v", err)
		}
		if p.Control == nil || p.Control.Type != MsgCallConnected || len(p.Control.Attributes) != 1 {
			t.Fatalf("decoded %+v", p)
		}
		a := p.Control.Attributes[0]
		if a.ID != AttribCryptoBinding || len(a.Value) != 100 {
			t.Errorf("crypto binding attribute = id %#x len %d, want 0x03 len 100", a.ID, len(a.Value))
		}
		if a.Value[3] != tc.id {
			t.Errorf("hash protocol byte = %#x, want %#x", a.Value[3], tc.id)
		}
		if !bytes.Equal(a.Value[4:36], nonce) {
			t.Error("server nonce was not echoed into the Call Connected message")
		}
		// Recompute the MAC over the message with the MAC field zeroed: a
		// conforming server must reach the same value.
		zeroed := append([]byte(nil), msg...)
		copy(zeroed[callConnectedLen-tc.macLen:], make([]byte, tc.macLen))
		recomputed := hmacSHA(compoundMACKey(tc.id, testHLAK), zeroed, tc.id)
		if !bytes.Equal(recomputed, mac) {
			t.Errorf("server-side recomputation mismatch for protocol %#x", tc.id)
		}
	}
}

// The framing example published in MS-SSTP section 4.7, used here as a wire
// format vector.
func TestCallConnectRequestWireFormat(t *testing.T) {
	want := mustHex("1001000E00010001000100060001")
	p := Packet{Control: &ControlMessage{
		Type:       MsgCallConnectRequest,
		Attributes: []Attribute{EncapsulatedProtocolAttr(EncapProtocolPPP)},
	}}
	got, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Errorf("encoded = %s, want %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}
	back, err := Decode(got)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Control.Attributes) != 1 || back.Control.Attributes[0].ID != AttribEncapsulatedProtocolID {
		t.Fatalf("unexpected decode: %+v", back)
	}
	if !bytes.Equal(back.Control.Attributes[0].Value, []byte{0x00, 0x01}) {
		t.Errorf("protocol id value = % x", back.Control.Attributes[0].Value)
	}
}

func TestEncodeDataPacketRespectsLengthCap(t *testing.T) {
	// 4 + 4091 = 4095 is the largest total the 12-bit Length field can hold.
	if _, err := (Packet{Data: bytes.Repeat([]byte{1}, 4091)}).Encode(); err != nil {
		t.Fatalf("4095-byte total should encode: %v", err)
	}
	if _, err := (Packet{Data: bytes.Repeat([]byte{1}, 4092)}).Encode(); err == nil {
		t.Error("4096-byte total must be rejected (12-bit length field)")
	}
}

func TestDecodeRejectsTrailingBytes(t *testing.T) {
	p, err := (Packet{Data: []byte{0x00, 0x21}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(append(p, 0x00)); err != ErrBadLength {
		t.Errorf("Decode with trailing byte = %v, want ErrBadLength", err)
	}
	if _, err := Decode(p[:2]); err != ErrBadLength {
		t.Errorf("Decode short buffer = %v, want ErrBadLength", err)
	}
}

func TestCryptoBindingRequestAndStatusInfo(t *testing.T) {
	value := append([]byte{0, 0, 0, CertHashProtocolSHA256}, bytes.Repeat([]byte{0x5A}, 32)...)
	req, err := ParseCryptoBindingRequest(value)
	if err != nil {
		t.Fatal(err)
	}
	if req.HashBitmask != CertHashProtocolSHA256 || len(req.Nonce) != 32 || req.Nonce[31] != 0x5A {
		t.Errorf("parsed %+v", req)
	}
	if _, err := ParseCryptoBindingRequest([]byte{0, 0, 0, 0, 1}); err != ErrBadLength {
		t.Errorf("short attribute = %v", err)
	}
	if _, err := ParseCryptoBindingRequest(append([]byte{0, 0, 0, 0x00}, bytes.Repeat([]byte{1}, 32)...)); err != ErrHashSelection {
		t.Error("bitmask with no hash protocol must be rejected")
	}
	st, err := ParseStatusInfo(append([]byte{0, 0, 0x02, 0x02}, []byte("bad cert")...))
	if err != nil {
		t.Fatal(err)
	}
	if st.StatusCode != 0x00000202 || statusCodeString(st.StatusCode) != "SSL BAD CERT STATUS" {
		t.Errorf("status = %#x (%s)", st.StatusCode, statusCodeString(st.StatusCode))
	}
	if statusCodeString(0xdeadbeef) != "UNKNOWN STATUS CODE" {
		t.Error("unknown status codes must not be silent")
	}
}

func TestPickHashProtocolPrefersSHA256(t *testing.T) {
	if got, err := PickHashProtocol(CertHashProtocolSHA1 | CertHashProtocolSHA256); err != nil || got != CertHashProtocolSHA256 {
		t.Errorf("both offered -> %#x, %v; spec says SHA-256 wins", got, err)
	}
	if got, err := PickHashProtocol(CertHashProtocolSHA1); err != nil || got != CertHashProtocolSHA1 {
		t.Errorf("sha1 only -> %#x, %v", got, err)
	}
	if _, err := PickHashProtocol(0x08); err != ErrHashSelection {
		t.Errorf("unknown bitmask -> %v", err)
	}
}
