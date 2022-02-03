package wire

import (
	"bytes"
	"testing"

	"github.com/neex/hui2ochko/patched-quic-go/internal_/protocol"
	"github.com/neex/hui2ochko/patched-quic-go/quicvarint"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestWire(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Wire Suite")
}

const (
	// a QUIC version that uses the IETF frame types
	versionIETFFrames = protocol.VersionTLS
)

func encodeVarInt(i uint64) []byte {
	b := &bytes.Buffer{}
	quicvarint.Write(b, i)
	return b.Bytes()
}
