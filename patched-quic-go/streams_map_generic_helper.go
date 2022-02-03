package quic

import (
	"github.com/cheekybits/genny/generic"

	"github.com/neex/hui2ochko/patched-quic-go/internal_/protocol"
)

// In the auto-generated streams maps, we need to be able to close the streams.
// Therefore, extend the generic.Type with the stream close method.
// This definition must be in a file that Genny doesn't process.
type item interface {
	generic.Type
	updateSendWindow(protocol.ByteCount)
	closeForShutdown(error)
}

const streamTypeGeneric protocol.StreamType = protocol.StreamTypeUni
