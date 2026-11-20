package ppp

import "errors"

// Wire constants for the PPP data channel inside SSTP. MS-SSTP carries each
// PPP frame as the payload of one SSTP data packet, so the HDLC flag
// octets of RFC 1662 are not used as delimiters here, but the ACCM-driven
// octet stuffing and the FCS are negotiated normally.
const (
	// Protocol field values.
	ProtoLCP    uint16 = 0xC021
	ProtoIPCP   uint16 = 0x8021
	ProtoIPv6CP uint16 = 0x8057
	ProtoPAP    uint16 = 0xC023
	ProtoCHAP   uint16 = 0xC223
	ProtoEAP    uint16 = 0xC227
	ProtoMPCP   uint16 = 0x00FD
	ProtoIP     uint16 = 0x0021
	ProtoIPv6   uint16 = 0x0057

	address   = 0xFF // PPP All-Stations address
	controlCt = 0x03 // PPP Unnumbered-Control field

	escapeField = 0x7D
	flagField   = 0x7E
	escapeXOR   = 0x20
)

var (
	ErrShortFrame  = errors.New("ppp: frame too short")
	ErrFCSMismatch = errors.New("ppp: frame check sequence mismatch")
)

// FCSMode selects the two optional framing layers of RFC 1662/1661: the 16-bit
// FCS (MS-SSTP does not use one, because the SSTP packet carries the length and
// TLS carries integrity) and the ACCM-driven octet stuffing, which applies to
// both directions whatever the FCS choice is.
type FCSMode struct {
	// FCS inserts and verifies the 16-bit frame check sequence.
	FCS bool
	// Accm is the character map negotiated by the LCP peer: bit i set means
	// the control character with value i is escaped in both directions.
	Accm uint32
}

// EncodeFrame serialises one PPP frame: address, control, protocol,
// information, then FCS and/or ACCM octet stuffing as configured.
func EncodeFrame(proto uint16, info []byte, f FCSMode) []byte {
	if info == nil {
		info = []byte{}
	}
	out := make([]byte, 0, 4+len(info)+2)
	out = append(out, address, controlCt, byte(proto>>8), byte(proto))
	out = append(out, info...)
	if f.FCS {
		c := fcsValue(out)
		out = append(out, byte(c), byte(c>>8))
	}
	// Escaping of 0x7D/0x7E is required even when ACCM is zero.
	out = ApplyACCM(out, f.Accm)
	return out
}

// ApplyACCM performs the octet stuffing required by the negotiated ACCM
// (RFC 1662 section B.4.2). It is a separate step because the escaping is
// applied over the whole frame, FCS included, after EncodeFrame ran.
func ApplyACCM(frame []byte, accm uint32) []byte {
	out := make([]byte, 0, len(frame)+8)
	for _, c := range frame {
		if c == flagField || c == escapeField || (c < 0x20 && accm&(1<<c) != 0) {
			out = append(out, escapeField, c^escapeXOR)
		} else {
			out = append(out, c)
		}
	}
	return out
}

// DecodeFrame reverses EncodeFrame (and the optional ACCM escaping) and
// returns the protocol field and the information octets.
func DecodeFrame(raw []byte, f FCSMode) (proto uint16, info []byte, err error) {
	b := unstuff(raw)
	// Tolerate an outer pair of flag octets: some stacks keep them even
	// though the SSTP framing makes them redundant.
	if len(b) > 0 && b[0] == flagField {
		b = b[1:]
	}
	if len(b) > 0 && b[len(b)-1] == flagField {
		b = b[:len(b)-1]
	}
	if len(b) < 5 {
		return 0, nil, ErrShortFrame
	}
	if b[0] != address || b[1] != controlCt {
		return 0, nil, ErrShortFrame
	}
	proto = uint16(b[2])<<8 | uint16(b[3])
	info = b[4:]
	if f.FCS {
		if len(info) < 2 {
			return 0, nil, ErrShortFrame
		}
		body := b[:len(b)-2]
		got := uint16(info[len(info)-2]) | uint16(info[len(info)-1])<<8
		if want := fcsValue(body); want != got {
			return 0, nil, ErrFCSMismatch
		}
		info = info[:len(info)-2]
	}
	return proto, info, nil
}

// unstuff reverses the octet stuffing (RFC 1662 section B.4.1). Escaped
// characters are always decoded; a lone trailing escape octet is dropped
// because the frame is already truncated at that point.
func unstuff(raw []byte) []byte {
	out := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == escapeField {
			if i+1 < len(raw) {
				i++
				out = append(out, raw[i]^escapeXOR)
			}
			continue
		}
		out = append(out, c)
	}
	return out
}

// FCS computes the values of the 16-bit CRC of the header and information
// fields (RFC 1662 Appendix F: CRC-16 with polynomial 0x8408 reflected, init
// 0xFFFF, final ones complement), returning the two octets ready for the wire.
func FCS(data []byte) [2]byte {
	v := fcsValue(data)
	return [2]byte{byte(v), byte(v >> 8)}
}

func fcsValue(data []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, c := range data {
		crc = crcUpdate(crc, c)
	}
	return ^crc
}

func crcUpdate(crc uint16, b byte) uint16 {
	crc ^= uint16(b)
	for i := 0; i < 8; i++ {
		if crc&1 != 0 {
			crc = (crc >> 1) ^ 0x8408
		} else {
			crc >>= 1
		}
	}
	return crc
}
