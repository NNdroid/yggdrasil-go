package core

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"sync"

	"github.com/Arceliar/phony"
	"github.com/xtaci/kcp-go/v5"
)

const (
	stunMagicCookie           uint32 = 0x2112A442
	stunTypeBindingIndication uint16 = 0x0011
	stunAttrTypeData          uint16 = 0x0013
	stunHeaderLen                    = 20
	stunAttrHeaderLen                = 4
)

var stunBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 2048)
		return &b
	},
}

// stunPacketConn wraps a net.PacketConn to obfuscate KCP packets as STUN packets.
type stunPacketConn struct {
	net.PacketConn
}

func newSTUNPacketConn(conn net.PacketConn) *stunPacketConn {
	return &stunPacketConn{PacketConn: conn}
}

func (c *stunPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	payloadLen := len(p)
	padLen := (4 - (payloadLen % 4)) % 4
	attrTotalLen := stunAttrHeaderLen + payloadLen + padLen
	stunMsgLen := attrTotalLen
	totalLen := stunHeaderLen + stunMsgLen

	bufPtr := stunBufPool.Get().(*[]byte)
	buf := *bufPtr
	if totalLen > len(buf) {
		buf = make([]byte, totalLen)
	}

	// STUN Header (20 bytes)
	// Message Type: 0x0011 (Binding Indication)
	binary.BigEndian.PutUint16(buf[0:2], stunTypeBindingIndication)
	// Message Length
	binary.BigEndian.PutUint16(buf[2:4], uint16(stunMsgLen))
	// Magic Cookie
	binary.BigEndian.PutUint32(buf[4:8], stunMagicCookie)
	// Transaction ID (12 bytes pseudo-random/random)
	_, _ = rand.Read(buf[8:20])

	// STUN DATA Attribute Header (4 bytes)
	binary.BigEndian.PutUint16(buf[20:22], stunAttrTypeData)
	binary.BigEndian.PutUint16(buf[22:24], uint16(payloadLen))

	// Attribute Payload
	copy(buf[24:24+payloadLen], p)

	// Padding bytes
	for i := 0; i < padLen; i++ {
		buf[24+payloadLen+i] = 0
	}

	_, err := c.PacketConn.WriteTo(buf[:totalLen], addr)
	stunBufPool.Put(bufPtr)
	if err != nil {
		return 0, err
	}
	return payloadLen, nil
}

func (c *stunPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	bufPtr := stunBufPool.Get().(*[]byte)
	rawBuf := *bufPtr
	defer stunBufPool.Put(bufPtr)

	for {
		nRaw, addr, err := c.PacketConn.ReadFrom(rawBuf)
		if err != nil {
			return 0, addr, err
		}
		if nRaw < stunHeaderLen+stunAttrHeaderLen {
			continue
		}
		if binary.BigEndian.Uint32(rawBuf[4:8]) != stunMagicCookie {
			continue
		}
		msgLen := int(binary.BigEndian.Uint16(rawBuf[2:4]))
		if stunHeaderLen+msgLen > nRaw {
			continue
		}

		pos := stunHeaderLen
		end := stunHeaderLen + msgLen
		for pos+stunAttrHeaderLen <= end {
			attrType := binary.BigEndian.Uint16(rawBuf[pos : pos+2])
			attrLen := int(binary.BigEndian.Uint16(rawBuf[pos+2 : pos+4]))
			if pos+stunAttrHeaderLen+attrLen > end {
				break
			}
			if attrType == stunAttrTypeData {
				dataStart := pos + stunAttrHeaderLen
				nCopy := attrLen
				if nCopy > len(p) {
					nCopy = len(p)
				}
				copy(p, rawBuf[dataStart:dataStart+nCopy])
				return nCopy, addr, nil
			}
			pad := (4 - (attrLen % 4)) % 4
			pos += stunAttrHeaderLen + attrLen + pad
		}
	}
}

type linkKCP struct {
	phony.Inbox
	*links
	tcp          *linkTCP
	listenconfig *net.ListenConfig
}

type linkKCPListener struct {
	*kcp.Listener
}

func (l *linkKCPListener) Accept() (net.Conn, error) {
	sess, err := l.Listener.AcceptKCP()
	if err != nil {
		return nil, err
	}
	// Best performance tuning
	sess.SetNoDelay(1, 10, 2, 1)
	sess.SetWindowSize(1024, 1024)
	sess.SetMtu(1350)
	sess.SetACKNoDelay(true)
	sess.SetStreamMode(true)
	_ = sess.SetReadBuffer(4194304)
	_ = sess.SetWriteBuffer(4194304)
	return sess, nil
}

func (l *links) newLinkKCP(tcp *linkTCP) *linkKCP {
	lk := &linkKCP{
		links: l,
		tcp:   tcp,
		listenconfig: &net.ListenConfig{
			Control: tcp.tcpContext,
		},
	}
	return lk
}

func (l *linkKCP) dial(ctx context.Context, u *url.URL, info linkInfo, options linkOptions) (net.Conn, error) {
	return l.findSuitableIP(u, func(hostname string, ip net.IP, port int) (net.Conn, error) {
		raddr := &net.UDPAddr{
			IP:   ip,
			Port: port,
		}
		var localAddr string
		if ip.To4() != nil {
			localAddr = "0.0.0.0:0"
		} else {
			localAddr = "[::]:0"
		}
		packetConn, err := net.ListenPacket("udp", localAddr)
		if err != nil {
			return nil, err
		}
		stunConn := newSTUNPacketConn(packetConn)
		sess, err := kcp.NewConn2(raddr, nil, 0, 0, stunConn)
		if err != nil {
			_ = stunConn.Close()
			return nil, err
		}
		// Best performance tuning
		sess.SetNoDelay(1, 10, 2, 1)
		sess.SetWindowSize(1024, 1024)
		sess.SetMtu(1350)
		sess.SetACKNoDelay(true)
		sess.SetStreamMode(true)
		_ = sess.SetReadBuffer(4194304)
		_ = sess.SetWriteBuffer(4194304)

		return sess, nil
	})
}

func (l *linkKCP) listen(ctx context.Context, u *url.URL, sintf string) (net.Listener, error) {
	hostport := u.Host
	if sintf != "" {
		if host, port, err := net.SplitHostPort(hostport); err == nil {
			hostport = fmt.Sprintf("[%s%%%s]:%s", host, sintf, port)
		}
	}
	packetConn, err := l.listenconfig.ListenPacket(ctx, "udp", hostport)
	if err != nil {
		return nil, err
	}
	stunConn := newSTUNPacketConn(packetConn)
	listener, err := kcp.ServeConn(nil, 0, 0, stunConn)
	if err != nil {
		_ = stunConn.Close()
		return nil, err
	}
	return &linkKCPListener{
		Listener: listener,
	}, nil
}
