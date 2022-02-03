package ackhandler

import "github.com/neex/hui2ochko/patched-quic-go/internal_/wire"

type Frame struct {
	wire.Frame // nil if the frame has already been acknowledged in another packet
	OnLost     func(wire.Frame)
	OnAcked    func(wire.Frame)
}
