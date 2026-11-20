package ppp

import "errors"

// Errors returned by the MS-CHAPv2 and PPP helpers in this package.
var (
	ErrShortChallenge = errors.New("ppp: challenge must be 16 octets")
	ErrBadHashSize    = errors.New("ppp: unexpected hash or response size")
	ErrBadInputSize   = errors.New("ppp: bad MS-CHAPv2 input size")
)
