// Package ppp implements the PPP layers used by SSTP: LCP, PAP, CHAP
// (including MS-CHAPv2), EAP-MSCHAPv2, IPCP, IPv6CP and MPPE.
//
// The MS-CHAPv2 primitives in this file follow RFC 2759 sections 3 and 8,
// and the MPPE key derivation follows RFC 3079 section 3. Both are covered
// by the published test vectors (RFC 2759 appendix 9.2 and 9.3, RFC 3079
// appendix 3.5), so a wrong constant, input order or parity step fails the
// unit tests instead of a live tunnel.
package ppp

import (
	"crypto/des"
	"crypto/sha1"
	"unicode/utf16"

	"github.com/IranTSR/sing-sstp/internal/md4"
)

// Magic constants, reproduced verbatim from RFC 2759 section 8.7 and
// RFC 3079 section 3.4.
var (
	// magic1AuthResponse is RFC 2759 Magic1[39]: "Magic server to client signing constant".
	magic1AuthResponse = []byte("Magic server to client signing constant")
	// magic2AuthResponse is RFC 2759 Magic2[41]: "Pad to make it do more than one iteration".
	magic2AuthResponse = []byte("Pad to make it do more than one iteration")

	// magic1MasterKey is RFC 3079 Magic1[27]: "This is the MPPE Master Key".
	magic1MasterKey = []byte("This is the MPPE Master Key")
	// magic2SendKey / magic3RecvKey are the RFC 3079 84-octet direction strings.
	magic2SendKey = []byte("On the client side, this is the send key; " +
		"on the server side, it is the receive key.")
	magic3RecvKey = []byte("On the client side, this is the receive key; " +
		"on the server side, it is the send key.")

	shsPad1 = make([]byte, 40)
	shsPad2 = fill(40, 0xf2)
)

func fill(n int, v byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}
	return b
}

// ChallengeHash returns the 8-octet MS-CHAPv2 challenge built from the
// peer (authenticator) challenge and the (server) challenge, exactly as
// RFC 2759 section 8.2 defines it: truncate(SHA1(peer | authenticator | name), 8).
//
// name MUST be the user name as presented by the peer, with any prepended
// domain already removed.
func ChallengeHash(peerChallenge, authenticatorChallenge []byte, name string) ([]byte, error) {
	if len(peerChallenge) != 16 || len(authenticatorChallenge) != 16 {
		return nil, ErrShortChallenge
	}
	h := sha1.New()
	h.Write(peerChallenge)
	h.Write(authenticatorChallenge)
	h.Write([]byte(name))
	return h.Sum(nil)[:8], nil
}

// NTPasswordHash returns MD4 over the UTF-16LE encoding of the password
// (RFC 2759 section 8.3), the 16-byte value usually called the NT hash.
func NTPasswordHash(password string) []byte {
	return md4.Sum(Utf16LE(password))
}

// PasswordHashHash returns MD4 of the NT hash (RFC 2759 section 8.4).
func PasswordHashHash(passwordHash []byte) ([]byte, error) {
	if len(passwordHash) != 16 {
		return nil, ErrBadHashSize
	}
	return md4.Sum(passwordHash), nil
}

// Utf16LE encodes s as UTF-16 little endian, matching the
// "0-to-256-unicode-char Password" input definition of RFC 2759.
func Utf16LE(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(units)*2)
	for _, u := range units {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

// NTResponse computes the 24-octet NT-Response for an 8-octet challenge and
// a 16-octet NT hash (RFC 2759 sections 8.5 and 8.6): the hash is zero padded
// to 21 octets, split into three 7-octet groups, each expanded into a
// parity-corrected DES key, and each key DES-encrypts the challenge in ECB mode.
func NTResponse(challenge, passwordHash []byte) ([]byte, error) {
	if len(challenge) != 8 {
		return nil, ErrBadHashSize
	}
	if len(passwordHash) != 16 {
		return nil, ErrBadHashSize
	}
	z := make([]byte, 21)
	copy(z, passwordHash)
	out := make([]byte, 0, 24)
	for i := 0; i < 3; i++ {
		block, err := des.NewCipher(desKeyFrom56(z[i*7 : i*7+7]))
		if err != nil {
			return nil, err
		}
		var dst [8]byte
		block.Encrypt(dst[:], challenge)
		out = append(out, dst[:]...)
	}
	return out, nil
}

// desKeyFrom56 turns a 7-octet value into an 8-octet DES key. The 56 key
// bits are read big-endian, split into eight groups of seven, each group is
// placed in its byte as bits 1..7, and bit 0 is set so that every byte has
// odd parity. This is the expansion FIPS 46 defines and the one RFC 2759
// section 8.6 expects the caller to perform.
func desKeyFrom56(src []byte) []byte {
	dst := make([]byte, 8)
	var acc uint64
	var have uint
	at := 0
	for _, b := range src {
		acc = acc<<8 | uint64(b)
		have += 8
		for have >= 7 && at < 8 {
			have -= 7
						seven := byte(acc>>have) << 1
			dst[at] = seven | oddParityBit(seven)
			at++
		}
		acc &= 1<<have - 1
	}
	return dst
}

// oddParityBit returns the bit that must be OR-ed into v (whose low bit is
// assumed to be zero) so that v ends up with an odd number of set bits.
func oddParityBit(v byte) byte {
	var ones byte
	for x := v; x != 0; x >>= 1 {
		ones ^= x & 1
	}
	return ones ^ 1 // 1 when the popcount is even
}

// AuthenticatorResponse returns the 42-octet "S=<40 hex>" string that proves
// possession of the same password used for the NT-Response
// (RFC 2759 section 8.7).
func AuthenticatorResponse(password string, ntResponse, peerChallenge, authenticatorChallenge []byte, name string) ([]byte, error) {
	if len(ntResponse) != 24 || len(peerChallenge) != 16 || len(authenticatorChallenge) != 16 {
		return nil, ErrBadInputSize
	}
	passwordHash := NTPasswordHash(password)
	passwordHashHash, err := PasswordHashHash(passwordHash)
	if err != nil {
		return nil, err
	}
	challenge, err := ChallengeHash(peerChallenge, authenticatorChallenge, name)
	if err != nil {
		return nil, err
	}
	digest := sha1Sum(passwordHashHash, ntResponse, magic1AuthResponse)
	final := sha1Sum(digest, challenge, magic2AuthResponse)
	out := make([]byte, 0, 42)
	out = append(out, "S="...)
	const hexSet = "0123456789ABCDEF"
	for _, b := range final {
		out = append(out, hexSet[b>>4], hexSet[b&0x0f])
	}
	return out, nil
}

func sha1Sum(parts ...[]byte) []byte {
	h := sha1.New()
	for _, p := range parts {
		h.Write(p)
	}
	sum := h.Sum(nil)
	if len(sum) != sha1.Size {
		panic("ppp: unexpected SHA-1 output size")
	}
	return sum
}

func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// MasterKey derives the 16-octet MPPE master key from the password hash hash
// and the NT-Response (RFC 3079 section 3.4, GetMasterKey).
func MasterKey(passwordHashHash, ntResponse []byte) ([]byte, error) {
	if len(passwordHashHash) != 16 || len(ntResponse) != 24 {
		return nil, ErrBadHashSize
	}
	d := sha1Sum(passwordHashHash, ntResponse, magic1MasterKey)
	return append([]byte(nil), d[:16]...), nil
}

// MasterSessionKeys derives the two 16-octet MPPE master session keys,
// labelled from the point of view of the party identified by isServer
// (RFC 3079 section 3.4, GetAsymmetricStartKey). send is the key used for
// traffic that party transmits, recv for traffic it receives.
//
// MS-SSTP section 3.2.5.2.2 asks the client for HLAK = MasterSendKey |
// MasterReceiveKey using the RFC 3079 section 3.1 call sequence, which is
// what HLAKForSSTP produces; a validating server swaps the halves.
func MasterSessionKeys(passwordHashHash, ntResponse []byte, isServer bool) (send, recv []byte, err error) {
	mk, err := MasterKey(passwordHashHash, ntResponse)
	if err != nil {
		return nil, nil, err
	}
	return asymmetricStartKey(mk, true, isServer), asymmetricStartKey(mk, false, isServer), nil
}

func asymmetricStartKey(masterKey []byte, isSend, isServer bool) []byte {
	var s []byte
	switch {
	case isSend && isServer, !isSend && !isServer:
		s = magic3RecvKey
	default:
		s = magic2SendKey
	}
	d := sha1Sum(masterKey, shsPad1, s, shsPad2)
	return append([]byte(nil), d[:16]...)
}

// HLAKForSSTP returns the 32-octet higher-layer authentication key the SSTP
// client must use after MS-CHAPv2 authentication (MS-SSTP section 3.2.5.2.2).
func HLAKForSSTP(ntResponse, passwordHash []byte) ([]byte, error) {
	passwordHashHash, err := PasswordHashHash(passwordHash)
	if err != nil {
		return nil, err
	}
	mk, err := MasterKey(passwordHashHash, ntResponse)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 32)
	out = append(out, asymmetricStartKey(mk, true, true)...)
	out = append(out, asymmetricStartKey(mk, false, true)...)
	return out, nil
}

// HLAKForSSTPServer returns the key a conforming server derives to validate
// the client's Compound MAC: MasterReceiveKey|MasterSendKey, the mirrored
// order of HLAKForSSTP (MS-SSTP section 3.2.5.2.2).
func HLAKForSSTPServer(ntResponse, passwordHash []byte) ([]byte, error) {
	passwordHashHash, err := PasswordHashHash(passwordHash)
	if err != nil {
		return nil, err
	}
	mk, err := MasterKey(passwordHashHash, ntResponse)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 32)
	out = append(out, asymmetricStartKey(mk, false, true)...)
	out = append(out, asymmetricStartKey(mk, true, true)...)
	return out, nil
}

