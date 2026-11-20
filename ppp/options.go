package ppp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// LCP option types (RFC 1661 section 6).
const (
	OptMRU      byte = 1
	OptAccm     byte = 2
	OptAuth     byte = 3
	OptMagic    byte = 5
	OptProtocol byte = 7 // Protocol-Field-Compression
	OptAcf      byte = 8 // Address-and-Control-Field-Compression
	// CCP/MPCP option codes for MPPE (RFC 3078 section 3.1).
	OptMPPEDebug         byte = 16
	OptMPPEShared        byte = 17
	OptMPPEKey56         byte = 18
	OptMPPEKey128        byte = 19
	OptMPPEStateless     byte = 20
	OptMPPECoercionOf64K byte = 21 // RFC 4337 section 3
)

// Authentication protocol labels used by this package. The wire encoding
// follows RFC 1661 section 6.4 (two-octet LCP code) plus the Microsoft
// algorithm octet for CHAP; RFC 2759 reserves 0x80 for MS-CHAP and 0x81 for
// MS-CHAPv2, and VPNGate relays (SoftEther) NAK a plain CHAP request into
// 0xC223 0x81.
const (
	AuthPAP      = "pap"
	AuthCHAP     = "chap-md5"
	AuthMSCHAP   = "mschap"   // 0x80
	AuthMSCHAPv2 = "mschapv2" // 0x81, what VPNGate speaks
)

// Option is one LCP/NCP option: type, and the value bytes exactly as they
// appear on the wire (without the two length header bytes).
type Option struct {
	Type  byte
	Value []byte
}

// EncodeOptions serialises a list of options, each as
// type(1) length(1) value.
func EncodeOptions(opts []Option) []byte {
	var out []byte
	for _, o := range opts {
		out = append(out, o.Type, byte(len(o.Value)+2))
		out = append(out, o.Value...)
	}
	return out
}

// DecodeOptions splits an option list. Zero-length options are a protocol
// error, as is a length that runs past the end of the buffer.
func DecodeOptions(b []byte) ([]Option, error) {
	var out []Option
	for len(b) > 0 {
		if len(b) < 2 {
			return nil, errors.New("ppp: truncated option list")
		}
		n := int(b[1])
		if n < 2 || n > len(b) {
			return nil, fmt.Errorf("ppp: bad option length %d for type %d", n, b[0])
		}
		out = append(out, Option{Type: b[0], Value: cloneBytes(b[2:n])})
		b = b[n:]
	}
	return out, nil
}

// FirstOption returns the first option of the given type, if any.
func FirstOption(opts []Option, typ byte) (Option, bool) {
	for _, o := range opts {
		if o.Type == typ {
			return o, true
		}
	}
	return Option{}, false
}

func cloneBytes(b []byte) []byte { return append([]byte(nil), b...) }

// NewMRUOption encodes the Maximum-Receive-Unit option.
func NewMRUOption(mru uint16) Option {
	var v [2]byte
	binary.BigEndian.PutUint16(v[:], mru)
	return Option{Type: OptMRU, Value: v[:]}
}

// MRUFromOption decodes an MRU option value.
func MRUFromOption(o Option) (uint16, error) {
	if len(o.Value) != 2 {
		return 0, fmt.Errorf("ppp: MRU option has %d value octets, want 2", len(o.Value))
	}
	return binary.BigEndian.Uint16(o.Value), nil
}

// NewAccmOption encodes the 32-bit Async-Control-Character-Map in network
// order (RFC 1661 section 6.2).
func NewAccmOption(accm uint32) Option {
	var v [4]byte
	binary.BigEndian.PutUint32(v[:], accm)
	return Option{Type: OptAccm, Value: v[:]}
}

// AccmFromOption decodes a 32-bit ACCM option value.
func AccmFromOption(o Option) (uint32, error) {
	if len(o.Value) != 4 {
		return 0, fmt.Errorf("ppp: ACCM option has %d value octets, want 4", len(o.Value))
	}
	return binary.BigEndian.Uint32(o.Value), nil
}

// NewAuthOption encodes the Authentication-Protocol option. The value is the
// two-octet LCP code (0xc023 PAP, 0xc223 CHAP) plus, for CHAP, the algorithm
// octet.
func NewAuthOption(auth string) (Option, error) {
	switch auth {
	case AuthPAP:
		return Option{Type: OptAuth, Value: []byte{0xC0, 0x23}}, nil
	case AuthCHAP, AuthMSCHAP, AuthMSCHAPv2:
		// RFC 1661 6.4 puts only the 2-octet code in the option; the CHAP
		// algorithm octet then arrives in the CHAP Challenge. Implementations
		// differ in whether they also carry it here, so we request the plain
		// code and pick the algorithm from what the server challenges with.
		return Option{Type: OptAuth, Value: []byte{0xC2, 0x23}}, nil
	default:
		return Option{}, fmt.Errorf("ppp: unknown authentication protocol %q", auth)
	}
}

// AuthFromOption reads the Authentication-Protocol option back into the
// labels used above.
func AuthFromOption(o Option) (string, error) {
	if len(o.Value) < 2 {
		return "", errors.New("ppp: short Authentication-Protocol option")
	}
	code := binary.BigEndian.Uint16(o.Value[:2])
	switch code {
	case ProtoPAP:
		return AuthPAP, nil
	case ProtoCHAP:
		if len(o.Value) < 3 {
			return "", errors.New("ppp: CHAP authentication option without algorithm octet")
		}
		switch o.Value[2] {
		case 0x05:
			return AuthCHAP, nil
		case 0x80:
			return AuthMSCHAP, nil
		case 0x81:
			return AuthMSCHAPv2, nil
		default:
			return "", fmt.Errorf("ppp: unsupported CHAP algorithm %#x", o.Value[2])
		}
	default:
		return "", fmt.Errorf("ppp: unsupported authentication code %#x", code)
	}
}

// CHAPAlgorithmName maps the algorithm octet of a CHAP Challenge to a label.
func CHAPAlgorithmName(alg byte) (string, error) {
	switch alg {
	case 0x05:
		return AuthCHAP, nil
	case 0x80:
		return AuthMSCHAP, nil
	case 0x81:
		return AuthMSCHAPv2, nil
	default:
		return "", fmt.Errorf("ppp: unsupported CHAP algorithm %#x", alg)
	}
}

// MPPE strength helpers (RFC 3078 section 3.1). A strength option carries no
// data: its presence is the demand. Because MPPE requires the RC4 keys to be
// at least 40 bits, a peer that offers nothing means "no encryption layer"
// and is not an error.
func NewMPPEStrengthOption(strength int) Option {
	switch strength {
	case 40:
		return Option{Type: OptMPPEShared} // 0x11 "40-bit" is signalled by the absence of 18/19
	case 56:
		return Option{Type: OptMPPEKey56}
	case 128:
		return Option{Type: OptMPPEKey128}
	default:
		return Option{Type: OptMPPEShared}
	}
}

func newMPPEStatelessOption(b bool) Option {
	v := []byte{0x00}
	if b {
		v = []byte{0x01}
	}
	return Option{Type: OptMPPEStateless, Value: v}
}

func isMPPEStrength(t byte) bool { return t == OptMPPEKey56 || t == OptMPPEKey128 }
