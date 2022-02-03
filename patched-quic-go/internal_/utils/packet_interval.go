package utils

import "github.com/neex/hui2ochko/patched-quic-go/internal_/protocol"

// PacketInterval is an interval from one PacketNumber to the other
type PacketInterval struct {
	Start protocol.PacketNumber
	End   protocol.PacketNumber
}
