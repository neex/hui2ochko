package utils

import (
	"github.com/neex/hui2ochko/patched-quic-go/internal_/protocol"
)

// NewConnectionID is a new connection ID
type NewConnectionID struct {
	SequenceNumber      uint64
	ConnectionID        protocol.ConnectionID
	StatelessResetToken protocol.StatelessResetToken
}
