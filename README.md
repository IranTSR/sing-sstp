# sing-sstp

SSTP (Secure Socket Tunneling Protocol, [MS-SSTP]) client engine in Go, meant
to be plugged into a sing-box style core as a layer-3 tunnel: it terminates the
HTTPS tunnel, negotiates PPP, authenticates with MS-CHAPv2 or PAP, and exposes
a plain IP-packet stream so the core keeps ownership of routing, DNS, rules and
traffic counters.

Status: work in progress. Landed so far: MS-SSTP framing + attributes, crypto
binding (PRF+, CMK, compound MAC), MD4, and the MS-CHAPv2 / MPPE key ladder
pinned by the RFC 2759 and RFC 3079 test vectors. PPP layer and the dialing
client are next.

## Layout

    sstp/              HTTPS upgrade, SSTP control/data framing, crypto binding
    ppp/               PPP layer: LCP, auth, IPCP, IPv6CP, MPPE
    ppp/internal/*     per-protocol option codecs and the mock peer oracle
    internal/md4       MD4 (RFC 1320) — only needed for the NT hash
    examples/demo     CLI once the engine can dial

## Sources this implementation is written against

MS-SSTP v20240423 (sections 2.2.x framing, 3.2.x client rules, 4.x wire
examples), RFC 1661 (LCP), RFC 1662 (PPP framing), RFC 1666/RFC 1668/RFC 1669
(IPCP), RFC 1679/RFC 3078 (MPPE), RFC 2759 (MS-CHAPv2), RFC 3079 (MPPE keys),
RFC 4306 2.13 (PRF+).
