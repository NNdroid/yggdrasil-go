package core

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/yggdrasil-network/yggdrasil-go/src/config"
)

func TestSTUNPacketConn(t *testing.T) {
	pc1, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc1.Close()

	pc2, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc2.Close()

	s1 := newSTUNPacketConn(pc1)
	s2 := newSTUNPacketConn(pc2)

	payload := []byte("hello kcp stun obfuscation world!")

	// Test sending via s1
	n, err := s1.WriteTo(payload, pc2.LocalAddr())
	if err != nil {
		t.Fatalf("WriteTo error: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("WriteTo returned %d, expected %d", n, len(payload))
	}

	// Verify raw UDP packet on pc2 directly to inspect STUN header
	rawBuf := make([]byte, 2048)
	_ = pc2.SetReadDeadline(time.Now().Add(time.Second))
	nRaw, _, err := pc2.ReadFrom(rawBuf)
	if err != nil {
		t.Fatalf("pc2 ReadFrom error: %v", err)
	}

	// Check STUN Header requirements
	if nRaw < 24 {
		t.Fatalf("raw STUN packet too short: %d", nRaw)
	}
	msgType := binary.BigEndian.Uint16(rawBuf[0:2])
	if msgType != 0x0011 {
		t.Fatalf("expected STUN message type 0x0011, got 0x%04x", msgType)
	}
	magic := binary.BigEndian.Uint32(rawBuf[4:8])
	if magic != 0x2112A442 {
		t.Fatalf("expected STUN magic cookie 0x2112A442, got 0x%08x", magic)
	}
	attrType := binary.BigEndian.Uint16(rawBuf[20:22])
	if attrType != 0x0013 {
		t.Fatalf("expected STUN DATA attribute type 0x0013, got 0x%04x", attrType)
	}
	attrLen := binary.BigEndian.Uint16(rawBuf[22:24])
	if int(attrLen) != len(payload) {
		t.Fatalf("expected STUN DATA attribute len %d, got %d", len(payload), attrLen)
	}

	// Now re-send via s1 and read through s2.ReadFrom
	_, err = s1.WriteTo(payload, pc2.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}

	recvBuf := make([]byte, 2048)
	_ = s2.SetReadDeadline(time.Now().Add(time.Second))
	nRecv, _, err := s2.ReadFrom(recvBuf)
	if err != nil {
		t.Fatalf("s2 ReadFrom error: %v", err)
	}
	if nRecv != len(payload) {
		t.Fatalf("ReadFrom returned %d bytes, want %d", nRecv, len(payload))
	}
	if !bytes.Equal(recvBuf[:nRecv], payload) {
		t.Fatalf("payload mismatch: got %s, want %s", recvBuf[:nRecv], payload)
	}
}

func TestKCPPeering(t *testing.T) {
	cfgA, cfgB := config.GenerateConfig(), config.GenerateConfig()
	if err := cfgA.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}
	if err := cfgB.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}

	logger := GetLoggerWithPrefix("", false)
	logger.EnableLevel("debug")

	nodeA, err := New(cfgA.Certificate, logger)
	if err != nil {
		t.Fatal(err)
	}
	nodeB, err := New(cfgB.Certificate, logger)
	if err != nil {
		t.Fatal(err)
	}

	nodeAListenURL, err := url.Parse("kcp://127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	nodeAListener, err := nodeA.Listen(nodeAListenURL, "")
	if err != nil {
		t.Fatalf("nodeA failed to listen on KCP: %v", err)
	}
	defer nodeAListener.Cancel()

	nodeAURL, err := url.Parse("kcp://" + nodeAListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	if err = nodeB.CallPeer(nodeAURL, ""); err != nil {
		t.Fatalf("nodeB failed to call nodeA over KCP: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	if l := len(nodeA.GetPeers()); l != 1 {
		t.Fatalf("nodeA unexpected number of peers: %d", l)
	}
	if l := len(nodeB.GetPeers()); l != 1 {
		t.Fatalf("nodeB unexpected number of peers: %d", l)
	}
}
