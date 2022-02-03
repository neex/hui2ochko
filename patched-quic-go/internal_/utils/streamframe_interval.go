package utils

import "github.com/neex/hui2ochko/patched-quic-go/internal_/protocol"

// ByteInterval is an interval from one ByteCount to the other
type ByteInterval struct {
	Start protocol.ByteCount
	End   protocol.ByteCount
}
