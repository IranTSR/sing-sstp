// Package sstp implements the client side of the Secure Socket Tunneling
// Protocol (MS-SSTP): the HTTPS upgrade, the SSTP control channel, and the
// crypto binding that ties PPP authentication to the TLS session.
//
// Framing rules implemented here follow [MS-SSTP] sections 2.2.1 through
// 2.2.14 and 3.2.x; the compound-MAC construction follows MS-SSTP section
// 3.2.5.2 and the PRF+ of RFC 4306 section 2.13.
package sstp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"hash"
)

// Hash protocols of MS-SSTP section 2.2.6.
const (
	CertHashProtocolSHA1   = 0x01
	CertHashProtocolSHA256 = 0x02
)

const (
	// cmkSeed is the 29-octet PRF+ seed of MS-SSTP section 3.2.5.2.2 item 2.
	cmkSeed = "SSTP inner method derived CMK"
	// callConnectedLen is the fixed length of a Call Connected message
	// (MS-SSTP section 2.2.11): 112 octets for both hash protocols.
	callConnectedLen = 112
)

var (
	ErrBadLength     = errors.New("sstp: malformed packet length")
	ErrBadVersion    = errors.New("sstp: unsupported SSTP version")
	ErrHashSelection = errors.New("sstp: server offered no usable crypto binding hash")
	ErrBindingFailed = errors.New("sstp: server rejected the crypto binding")
)

// version is the only SSTP version defined: major 1, minor 0.
const version byte = 0x10

// Packet is one SSTP packet: either a control message (Control != nil) or a
// data packet carrying a PPP frame (Data != nil).
type Packet struct {
	Version byte
	Control *ControlMessage
	Data    []byte
}

// ControlMessage is the body of an SSTP control packet.
type ControlMessage struct {
	Type       uint16
	Attributes []Attribute
}

// Attribute is a decoded SSTP attribute (MS-SSTP section 2.2.4).
type Attribute struct {
	ID    byte
	Value []byte
}

// Control message types (MS-SSTP section 2.2.2).
const (
	MsgCallConnectRequest    uint16 = 0x0001
	MsgCallConnectAck        uint16 = 0x0002
	MsgCallConnectNAK        uint16 = 0x0003
	MsgCallConnected         uint16 = 0x0004
	MsgCallAbort             uint16 = 0x0005
	MsgCallDisconnect        uint16 = 0x0006
	MsgCallDisconnectAck     uint16 = 0x0007
	MsgEchoRequest           uint16 = 0x0008
	MsgEchoResponse          uint16 = 0x0009
)

// Attribute IDs (MS-SSTP section 2.2.4).
const (
	AttribEncapsulatedProtocolID byte = 0x01
	AttribStatusInfo             byte = 0x02
	AttribCryptoBinding          byte = 0x03
	AttribCryptoBindingRequest   byte = 0x04
)

// Encapsulated protocol values (MS-SSTP section 2.2.5).
const EncapProtocolPPP uint16 = 0x0001

// Encode serialises p. Exactly one of Control and Data must be set. The
// 4-byte header carries Version, 7 reserved bits plus the C bit, and 4
// reserved bits plus a 12-bit total length that includes the header, which
// caps any SSTP packet at 4095 octets.
func (p Packet) Encode() ([]byte, error) {
	var body []byte
	var cBit byte
	switch {
	case p.Control != nil && p.Data != nil:
		return nil, errors.New("sstp: packet has both control and data")
	case p.Control != nil:
		cBit = 0x01
		var err error
		body, err = p.Control.encode()
		if err != nil {
			return nil, err
		}
	case p.Data != nil:
		body = p.Data
	default:
		return nil, errors.New("sstp: empty packet")
	}
	total := 4 + len(body)
	// The 12-bit Length field counts this packet, so 4095 is the maximum and
	// the payload can never exceed 4091 octets.
	if total > 0x0fff {
		return nil, ErrBadLength
	}
	out := make([]byte, 0, total)
	out = append(out, version, cBit, byte(total>>8), byte(total))
	out = append(out, body...)
	return out, nil
}

func (m *ControlMessage) encode() ([]byte, error) {
	out := make([]byte, 0, 4+8*len(m.Attributes))
	out = append(out, byte(m.Type>>8), byte(m.Type))
	out = append(out, byte(len(m.Attributes)>>8), byte(len(m.Attributes)))
	for _, a := range m.Attributes {
		vlen := len(a.Value)
		total := 4 + vlen
		if total > 0x0fff {
			return nil, ErrBadLength
		}
		out = append(out,
			0x00, a.ID, // reserved, attribute id
			byte(total>>8), byte(total))
		out = append(out, a.Value...)
	}
	return out, nil
}

// Decode parses a single SSTP packet from buf, which must contain exactly one
// whole packet; trailing bytes are rejected so that framing errors show up
// early instead of desynchronising the stream.
func Decode(buf []byte) (Packet, error) {
	var p Packet
	if len(buf) < 4 {
		return p, ErrBadLength
	}
	if buf[0]>>4 != version>>4 {
		return p, ErrBadVersion
	}
	p.Version = buf[0]
	total := int(binary.BigEndian.Uint16(buf[2:4])) & 0x0fff
	if total < 4 || total > len(buf) {
		return p, ErrBadLength
	}
	body := buf[4:total]
	if len(buf) != total {
		return p, ErrBadLength
	}
	if buf[1]&0x01 == 0 {
		p.Data = body
		return p, nil
	}
	if len(body) < 4 {
		return p, ErrBadLength
	}
	m := &ControlMessage{Type: binary.BigEndian.Uint16(body[0:2])}
	n := int(binary.BigEndian.Uint16(body[2:4]))
	body = body[4:]
	for i := 0; i < n; i++ {
		if len(body) < 4 {
			return p, ErrBadLength
		}
		al := int(binary.BigEndian.Uint16(body[2:4])) & 0x0fff
		if al < 4 || al > len(body) {
			return p, ErrBadLength
		}
		m.Attributes = append(m.Attributes, Attribute{ID: body[1], Value: body[4:al]})
		body = body[al:]
	}
	if len(body) != 0 {
		return p, ErrBadLength
	}
	p.Control = m
	return p, nil
}

// EncapsulatedProtocolAttr builds the single-protocol attribute used in a
// Call Connect Request (MS-SSTP section 2.2.5).
func EncapsulatedProtocolAttr(proto uint16) Attribute {
	return Attribute{ID: AttribEncapsulatedProtocolID, Value: []byte{byte(proto >> 8), byte(proto)}}
}

// CryptoBindingRequest is the parsed content of the attribute the server
// sends in Call Connect Ack (MS-SSTP sections 2.2.6 and 2.2.10).
type CryptoBindingRequest struct {
	HashBitmask byte
	Nonce       []byte
}

// ParseCryptoBindingRequest decodes a Crypto Binding Request attribute body.
func ParseCryptoBindingRequest(value []byte) (CryptoBindingRequest, error) {
	var r CryptoBindingRequest
	// value layout: 3 reserved, 1 bitmask, 32 nonce
	if len(value) < 36 {
		return r, ErrBadLength
	}
	r.HashBitmask = value[3]
	r.Nonce = append([]byte(nil), value[4:36]...)
	if r.HashBitmask&(CertHashProtocolSHA1|CertHashProtocolSHA256) == 0 {
		return r, ErrHashSelection
	}
	return r, nil
}

// StatusInfo is the parsed content of a Status Info attribute
// (MS-SSTP section 2.2.8), carried by Call Connect NAK and error messages.
type StatusInfo struct {
	StatusCode uint32
	AttribID   byte
	Message    string
}

// ParseStatusInfo decodes a Status Info attribute body.
func ParseStatusInfo(value []byte) (StatusInfo, error) {
	var s StatusInfo
	if len(value) < 5 {
		return s, ErrBadLength
	}
	s.StatusCode = binary.BigEndian.Uint32(value[0:4])
	s.AttribID = value[4]
	if len(value) > 5 {
		s.Message = string(value[5:])
	}
	return s, nil
}

// Status codes of MS-SSTP section 2.2.8, decoded for readable error messages.
func statusCodeString(code uint32) string {
	switch code {
	case 0x00000001:
		return "UNDEFINED"
	case 0x00000002:
		return "PROTOCOL VERSION NOT SUPPORTED"
	case 0x00000100:
		return "REASON NONCE MISMATCH"
	case 0x00000101:
		return "REASON CERT HASH ALGORITHM MISMATCH"
	case 0x00000102:
		return "REASON CERT HASH INVALID"
	case 0x00000200:
		return "SSL CERTIFICATE NOT PRESENTED"
	case 0x00000201:
		return "SSL CONNECT FAILURE"
	case 0x00000202:
		return "SSL BAD CERT STATUS"
	case 0x00000203:
		return "SSL CERT REVOKED"
	case 0x00000204:
		return "SSL INVALID CA"
	case 0x00000205:
		return "SSL UNKNOWN CA"
	case 0x00000206:
		return "SSL CERT EXPIRED"
	case 0x00000207:
		return "SSL CERT SIMPLE EXPIRED"
	case 0x00000300:
		return "HTTP PROXY AUTHENTICATION REQUIRED"
	case 0x00000301:
		return "HTTP PROXY UNAUTHORIZED (ACCESS FAILED)"
	default:
		return "UNKNOWN STATUS CODE"
	}
}

// CompoundMAC computes the Compound MAC of the Crypto Binding attribute for a
// given hash protocol, HLAK (MS-SSTP section 3.2.5.2.2 / 3.2.5.2.4) and
// server nonce, together with the finished 112-octet Call Connected message.
//
// The MAC input is the whole message with the Compound MAC field and its
// padding zeroed, exactly as sections 3.2.5.2.1 and 3.2.5.2.3 require.
func CompoundMAC(hashProtocol byte, hlak, serverNonce []byte, certDER []byte) (out []byte, msg []byte, err error) {
	if len(hlak) != 32 {
		return nil, nil, errors.New("sstp: HLAK must be 32 octets")
	}
	if len(serverNonce) != 32 {
		return nil, nil, errors.New("sstp: server nonce must be 32 octets")
	}
	certHash, hashLen, padAfterCert, macLen, id, err := certHashFor(hashProtocol, certDER)
	if err != nil {
		return nil, nil, err
	}
	msg = make([]byte, callConnectedLen)
	// SSTP header + control header + attribute header, all with zero padding
	// fields already clear.
	msg[0] = version
	msg[1] = 0x01
	binary.BigEndian.PutUint16(msg[2:4], callConnectedLen)
	binary.BigEndian.PutUint16(msg[4:6], MsgCallConnected)
	binary.BigEndian.PutUint16(msg[6:8], 1)
	msg[8] = 0x00
	msg[9] = AttribCryptoBinding
	binary.BigEndian.PutUint16(msg[10:12], uint16(4+3+1+32+hashLen+padAfterCert+macLen))
	msg[12] = 0
	msg[13] = 0
	msg[14] = 0
	msg[15] = id
	copy(msg[16:48], serverNonce)
	copy(msg[48:48+hashLen], certHash)
	// The padding field after the cert hash (12 octets for SHA-1, none for
	// SHA-256) and the compound MAC slot are left zero while hashing, as the
	// input rules of sections 3.2.5.2.1 and 3.2.5.2.3 require.
	macOff := 48 + hashLen + padAfterCert
	key := compoundMACKey(hashProtocol, hlak)
	mac := hmacSHA(key, msg, hashProtocol)
	copy(msg[macOff:macOff+macLen], mac)
	return mac, msg, nil
}

func compoundMACKey(hashProtocol byte, hlak []byte) []byte {
	switch hashProtocol {
	case CertHashProtocolSHA1:
		return prfPlus(hlak, []byte(cmkSeed), 20, sha1.New)
	default:
		return prfPlus(hlak, []byte(cmkSeed), 32, sha256.New)
	}
}

// prfPlus is the PRF+ of RFC 4306 section 2.13:
// T1 = HMAC(K, S | LEN | 0x01), Ti = HMAC(K, T(i-1) | S | LEN | i), where LEN
// is the output length as a 16-bit little-endian integer.
func prfPlus(key, seed []byte, n int, h func() hash.Hash) []byte {
	leLen := []byte{byte(n), byte(n >> 8)}
	out := make([]byte, 0, n)
	var prev []byte
	for i := 1; len(out) < n; i++ {
		mac := hmac.New(h, key)
		if prev != nil {
			mac.Write(prev)
		}
		mac.Write(seed)
		mac.Write(leLen)
		mac.Write([]byte{byte(i)})
		prev = mac.Sum(nil)
		out = append(out, prev...)
	}
	return out[:n]
}

func hmacSHA(key, data []byte, hashProtocol byte) []byte {
	var h hash.Hash
	if hashProtocol == CertHashProtocolSHA1 {
		h = hmac.New(sha1.New, key)
	} else {
		h = hmac.New(sha256.New, key)
	}
	h.Write(data)
	return h.Sum(nil)
}

// certHashFor hashes the server certificate the way MS-SSTP section 2.2.11
// requires and reports the field sizes that follow from the chosen protocol.
func certHashFor(hashProtocol byte, certDER []byte) (sum []byte, hashLen, padLen, macLen, id byte, err error) {
	switch hashProtocol {
	case CertHashProtocolSHA1:
		s := sha1.Sum(certDER)
		return s[:], 20, 12, 20, CertHashProtocolSHA1, nil
	case CertHashProtocolSHA256:
		s := sha256.Sum256(certDER)
		return s[:], 32, 0, 32, CertHashProtocolSHA256, nil
	default:
		return nil, 0, 0, 0, 0, ErrHashSelection
	}
}

// PickHashProtocol chooses the client hash protocol from the server bitmask:
// SHA-256 when the server allows it, otherwise SHA-1, per MS-SSTP section
// 3.2.5.3.2.
func PickHashProtocol(bitmask byte) (byte, error) {
	switch {
	case bitmask&CertHashProtocolSHA256 != 0:
		return CertHashProtocolSHA256, nil
	case bitmask&CertHashProtocolSHA1 != 0:
		return CertHashProtocolSHA1, nil
	default:
		return 0, ErrHashSelection
	}
}

// NewNonce returns a 32-octet random nonce.
func NewNonce() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// LeafDER returns the DER bytes of the leaf certificate of chain, which is
// what the compound MAC binds to.
func LeafDER(chain []*x509.Certificate) ([]byte, error) {
	if len(chain) == 0 {
		return nil, errors.New("sstp: empty certificate chain")
	}
	return chain[0].Raw, nil
}
