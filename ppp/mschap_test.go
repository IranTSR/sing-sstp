package ppp

import (
	"encoding/hex"
	"strings"
	"testing"
)

// rfc2759Vector holds the published test values of RFC 2759 appendix 9.2.
var rfc2759Vector = struct {
	name  string
	pass  string
	peer  string // 16-octet PeerChallenge  (RFC 2759 9.2)
	auth  string // 16-octet AuthenticatorChallenge (RFC 2759 9.2)
	chal  string // expected 8-octet challenge
	pwh   string // expected 16-octet password hash
	pwhh  string // expected 16-octet password hash hash
	ntRep string // expected 24-octet NT-Response
	authR string // expected 42-octet authenticator response
}{
	name:  "User",
	pass:  "clientPass",
	peer:  "21402324255E262A28295F2B3A337C7E", // RFC 2759 9.2 PeerChallenge
	auth:  "5B5D7C7D7B3F2F3E3C2C602132262628", // RFC 2759 9.2 AuthenticatorChallenge
	chal:  "D02E4386BCE91226",
	pwh:   "44EBBA8D5312B8D611474411F56989AE",
	pwhh:  "41C00C584BD2D91C4017A2A12FA59F3F",
	ntRep: "82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF",
	authR: "S=407A5589115FD0D6209F510FE9C04566932CDA56",
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ToLower(s))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestMagicConstantLengths(t *testing.T) {
	for name, got := range map[string]int{
		"RFC2759 Magic1": len(magic1AuthResponse),
		"RFC2759 Magic2": len(magic2AuthResponse),
		"RFC3079 Magic1": len(magic1MasterKey),
		"RFC3079 Magic2": len(magic2SendKey),
		"RFC3079 Magic3": len(magic3RecvKey),
	} {
		want := map[string]int{"RFC2759 Magic1": 39, "RFC2759 Magic2": 41, "RFC3079 Magic1": 27, "RFC3079 Magic2": 84, "RFC3079 Magic3": 84}[name]
		if got != want {
			t.Errorf("%s = %d octets, want %d", name, got, want)
		}
	}
}

func TestNTPasswordHashVector(t *testing.T) {
	v := rfc2759Vector
	if got := hex.EncodeToString(NTPasswordHash(v.pass)); got != strings.ToLower(v.pwh) {
		t.Errorf("NtPasswordHash = %s, want %s", got, v.pwh)
	}
}

func TestChallengeHashVector(t *testing.T) {
	v := rfc2759Vector
	got, err := ChallengeHash(unhex(t, v.peer), unhex(t, v.auth), v.name)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != strings.ToLower(v.chal) {
		t.Errorf("ChallengeHash = %s, want %s", hex.EncodeToString(got), v.chal)
	}
}

func TestNTResponseVector(t *testing.T) {
	v := rfc2759Vector
	ntResp, err := NTResponse(unhex(t, v.chal), unhex(t, v.pwh))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(ntResp) != strings.ToLower(v.ntRep) {
		t.Errorf("NT-Response = %s, want %s", hex.EncodeToString(ntResp), v.ntRep)
	}
}

func TestAuthenticatorResponseVector(t *testing.T) {
	v := rfc2759Vector
	got, err := AuthenticatorResponse(v.pass, unhex(t, v.ntRep), unhex(t, v.peer), unhex(t, v.auth), v.name)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != v.authR {
		t.Errorf("AuthenticatorResponse = %q, want %q", got, v.authR)
	}
}

// desKeyFrom56 bit order, pinned by FIPS 81's published example expressed as a
// 56-bit key (14a7b9e9d9efe6 -> 1334577151717771 with odd parity inserted).
func TestDESKeyExpansionVectors(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"14a7b9e9d9efe6", "1334577151717771"},
		{"00000000000000", "0101010101010101"},
	} {
		got := hex.EncodeToString(desKeyFrom56(unhex(t, tc.in)))
		if got != tc.want {
			t.Errorf("desKeyFrom56(%s) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestMasterKeyVector(t *testing.T) {
	mk, err := MasterKey(unhex(t, rfc2759Vector.pwhh), unhex(t, rfc2759Vector.ntRep))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(mk); got != "fdece3717a8c838cb388e527ae3cdd31" {
		t.Errorf("MasterKey = %s, want fdece3717a8c838cb388e527ae3cdd31", got)
	}
}

// HLAK consistency: MS-SSTP section 3.2.5.2.2 defines the client key as
// MasterSendKey|MasterReceiveKey and the server key as the same pair with the
// halves exchanged, so both sides must arrive at identical 32 octets.
func TestHLAKHalvesAreMirrored(t *testing.T) {
	v := rfc2759Vector
	client, err := HLAKForSSTP(unhex(t, v.ntRep), unhex(t, v.pwh))
	if err != nil {
		t.Fatal(err)
	}
	server, err := HLAKForSSTPServer(unhex(t, v.ntRep), unhex(t, v.pwh))
	if err != nil {
		t.Fatal(err)
	}
	if len(client) != 32 || len(server) != 32 {
		t.Fatalf("HLAK sizes = %d/%d, want 32/32", len(client), len(server))
	}
	if hex.EncodeToString(client[16:32]) != hex.EncodeToString(server[0:16]) {
		t.Errorf("client receive half != server send half: %s vs %s",
			hex.EncodeToString(client[16:32]), hex.EncodeToString(server[0:16]))
	}
	if hex.EncodeToString(client[0:16]) != hex.EncodeToString(server[16:32]) {
		t.Errorf("client send half != server receive half: %s vs %s",
			hex.EncodeToString(client[0:16]), hex.EncodeToString(server[16:32]))
	}
	// The first half is the 128-bit send start key published in RFC 3079 3.5.3.
	if got := hex.EncodeToString(client[0:16]); got != "8b7cdc149b993a1ba118cb153f56dccb" {
		t.Errorf("client send half = %s, want 8b7cdc149b993a1ba118cb153f56dccb", got)
	}
}

func TestUtf16LE(t *testing.T) {
	if got := hex.EncodeToString(Utf16LE("clientPass")); got != "63006c00690065006e0074005000610073007300" {
		t.Errorf("Utf16LE(clientPass) = %s", got)
	}
	if got := hex.EncodeToString(Utf16LE("𐐀")); got != "3dd840dc" { // surrogate pair, little endian
		t.Errorf("Utf16LE(emoji) = %s, want 3dd800de", got)
	}
}
