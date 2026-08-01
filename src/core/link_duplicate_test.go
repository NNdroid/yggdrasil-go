package core

import (
	"bytes"
	"crypto/rand"
	"net/url"
	"testing"

	"github.com/yggdrasil-network/yggdrasil-go/src/config"
)

func TestOption3DuplicateToAllPeers(t *testing.T) {
	cfgA, cfgB, cfgC := config.GenerateConfig(), config.GenerateConfig(), config.GenerateConfig()
	if err := cfgA.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}
	if err := cfgB.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}
	if err := cfgC.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}

	logger := GetLoggerWithPrefix("", false)

	nodeA, err := New(cfgA.Certificate, logger)
	if err != nil {
		t.Fatal(err)
	}
	nodeB, err := New(cfgB.Certificate, logger)
	if err != nil {
		t.Fatal(err)
	}
	nodeC, err := New(cfgC.Certificate, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeA.Stop()
	defer nodeB.Stop()
	defer nodeC.Stop()

	// Listeners on B and C
	urlB, err := url.Parse("kcp://127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenerB, err := nodeB.Listen(urlB, "")
	if err != nil {
		t.Fatal(err)
	}
	defer listenerB.Cancel()

	urlC, err := url.Parse("kcp://127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenerC, err := nodeC.Listen(urlC, "")
	if err != nil {
		t.Fatal(err)
	}
	defer listenerC.Cancel()

	// Node A calls node B and node C
	callB, err := url.Parse("kcp://" + listenerB.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	callC, err := url.Parse("kcp://" + listenerC.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	if err := nodeA.CallPeer(callB, ""); err != nil {
		t.Fatalf("nodeA call B error: %v", err)
	}
	if err := nodeA.CallPeer(callC, ""); err != nil {
		t.Fatalf("nodeA call C error: %v", err)
	}

	if !WaitConnected(nodeA, nodeB) {
		t.Fatal("nodeA and nodeB did not connect")
	}
	if !WaitConnected(nodeA, nodeC) {
		t.Fatal("nodeA and nodeC did not connect")
	}

	if l := len(nodeA.GetPeers()); l != 2 {
		t.Fatalf("nodeA expected 2 peers, got %d", l)
	}

	// Enable Option 3 (Duplicate to All Peers) on Node A
	nodeA.SetDuplicateToAllPeers(true)
	if !nodeA.DuplicateToAllPeers() {
		t.Fatal("expected DuplicateToAllPeers to be true")
	}

	msgLen := 128
	done := CreateEchoListener(t, nodeB, msgLen, 1)

	// Format valid IPv6 packet from A to B
	msg := make([]byte, msgLen)
	_, _ = rand.Read(msg[40:])
	msg[0] = 0x60
	copy(msg[8:24], nodeB.Address())
	copy(msg[24:40], nodeA.Address())

	n, err := nodeA.WriteTo(msg, nodeB.LocalAddr())
	if err != nil {
		t.Fatalf("WriteTo error: %v", err)
	}
	if n != msgLen {
		t.Fatalf("WriteTo returned %d, want %d", n, msgLen)
	}

	buf := make([]byte, msgLen)
	_, _, err = nodeA.ReadFrom(buf)
	if err != nil {
		t.Fatalf("nodeA ReadFrom error: %v", err)
	}
	if !bytes.Equal(msg[40:], buf[40:]) {
		t.Fatalf("expected echo payload match")
	}
	<-done
}
