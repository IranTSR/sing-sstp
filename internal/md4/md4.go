// Package md4 implements the MD4 message-digest algorithm (RFC 1320).
//
// MD4 is cryptographically broken and MUST NOT be used for integrity or
// signature purposes. It exists here only because the MS-CHAPv2 password
// hash (RFC 2759 section 2) is defined in terms of MD4, and SSTP tunnels
// have no choice but to compute that hash to authenticate against
// MS-CHAPv2 servers.
//
// The implementation is a direct translation of the algorithm described in
// RFC 1320 sections 3.1 through 3.5 and is verified against the test suite
// in RFC 1320 appendix A.5.
package md4

import (
	"encoding/binary"
	"hash"
)

const (
	// Size is the number of bytes in an MD4 checksum.
	Size      = 16
	blockSize = 64
)

type digest struct {
	a, b, c, d uint32
	x          [blockSize]byte
	nx         int
	length     uint64
}

// New returns a new hash.Hash computing the MD4 checksum.
func New() hash.Hash {
	var d digest
	d.Reset()
	return &d
}

// Sum appends the current hash to b and returns the resulting slice.
func Sum(b []byte) []byte {
	h := New()
	h.Write(b)
	return h.Sum(b)
}

func (d *digest) Size() int      { return Size }
func (d *digest) BlockSize() int { return blockSize }

func (d *digest) Reset() {
	d.a, d.b, d.c, d.d = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
	d.nx = 0
	d.length = 0
}

func (d *digest) Write(p []byte) (int, error) {
	n := len(p)
	d.length += uint64(n)
	for d.nx+len(p) >= blockSize {
		lim := blockSize - d.nx
		copy(d.x[d.nx:], p[:lim])
		d.block(d.x[:])
		p = p[lim:]
		d.nx = 0
	}
	copy(d.x[d.nx:], p)
	d.nx += len(p)
	return n, nil
}

func (d *digest) Sum(in []byte) []byte {
	// Work on a copy so that Sum does not disturb the running hash.
	var pad [128]byte
	copy(pad[:], d.x[:d.nx])
	pos := d.nx
	pad[pos] = 0x80
	pos++
	for pos%64 != 56 {
		pad[pos] = 0
		pos++
	}
	binary.LittleEndian.PutUint64(pad[pos:], d.length<<3)
	pos += 8

	cp := *d
	for i := 0; i < pos; i += 64 {
		cp.block(pad[i:])
	}
	var out [Size]byte
	binary.LittleEndian.PutUint32(out[0:], cp.a)
	binary.LittleEndian.PutUint32(out[4:], cp.b)
	binary.LittleEndian.PutUint32(out[8:], cp.c)
	binary.LittleEndian.PutUint32(out[12:], cp.d)
	return append(in, out[:]...)
}

func (d *digest) block(p []byte) {
	a, b, c, dd := d.a, d.b, d.c, d.d
	var x [16]uint32
	for i := 0; i < 16; i++ {
		x[i] = binary.LittleEndian.Uint32(p[i*4:])
	}

	// Round 1: a = (a + F(b,c,d) + X[k]) <<< s
	r1 := func(a, b, c, dd *uint32, k, s uint32) {
		*a += ((*b & *c) | (^*b & *dd)) + x[k]
		*a = (*a << s) | (*a >> (32 - s))
	}
	for i := 0; i < 16; i += 4 {
		r1(&a, &b, &c, &dd, uint32(i+0), 3)
		r1(&dd, &a, &b, &c, uint32(i+1), 7)
		r1(&c, &dd, &a, &b, uint32(i+2), 11)
		r1(&b, &c, &dd, &a, uint32(i+3), 19)
	}

	// Round 2: a = (a + G(b,c,d) + X[k] + 5A827999) <<< s
	r2 := func(a, b, c, dd *uint32, k, s uint32) {
		*a += ((*b & *c) | (*b & *dd) | (*c & *dd)) + x[k] + 0x5a827999
		*a = (*a << s) | (*a >> (32 - s))
	}
	for i := 0; i < 4; i++ {
		r2(&a, &b, &c, &dd, uint32(i+0), 3)
		r2(&dd, &a, &b, &c, uint32(i+4), 5)
		r2(&c, &dd, &a, &b, uint32(i+8), 9)
		r2(&b, &c, &dd, &a, uint32(i+12), 13)
	}

	// Round 3: a = (a + H(b,c,d) + X[k] + 6ED9EBA1) <<< s
	r3 := func(a, b, c, dd *uint32, k, s uint32) {
		*a += (*b ^ *c ^ *dd) + x[k] + 0x6ed9eba1
		*a = (*a << s) | (*a >> (32 - s))
	}
	order := [16]uint32{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}
	shifts := [4]uint32{3, 9, 11, 15}
	for i := 0; i < 16; i += 4 {
		r3(&a, &b, &c, &dd, order[i+0], shifts[0])
		r3(&dd, &a, &b, &c, order[i+1], shifts[1])
		r3(&c, &dd, &a, &b, order[i+2], shifts[2])
		r3(&b, &c, &dd, &a, order[i+3], shifts[3])
	}

	d.a += a
	d.b += b
	d.c += c
	d.d += dd
}
