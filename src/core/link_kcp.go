package core

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"

	mrand "math/rand/v2"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Arceliar/phony"
	"github.com/xtaci/kcp-go/v5"
)

const (
	stunMagicCookie           uint32 = 0x2112A442
	stunTypeBindingRequest    uint16 = 0x0001
	stunTypeBindingIndication uint16 = 0x0011
	stunAttrTypeData          uint16 = 0x0013
	stunAttrTypePadding       uint16 = 0x0015
	stunHeaderLen                    = 20
	stunAttrHeaderLen                = 4
)

var bundleMagic = [4]byte{'K', 'C', 'P', 'B'}

// stunBufPool uses 65535 byte buffers to ensure no UDP packet truncation occurs
var stunBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65535)
		return &b
	},
}

var multiKCPBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 16384)
		return &b
	},
}

// fillFastTransactionID fills a 12-byte STUN transaction ID using fast pseudo-random generation.
func fillFastTransactionID(b []byte) {
	u1 := mrand.Uint64()
	u2 := mrand.Uint32()
	binary.BigEndian.PutUint64(b[0:8], u1)
	binary.BigEndian.PutUint32(b[8:12], u2)
}

// stunPacketConn wraps a net.PacketConn to obfuscate KCP packets as STUN packets.
type stunPacketConn struct {
	net.PacketConn
	msgType     uint16
	mixMsgType  bool
	randPadding bool
}

func newSTUNPacketConn(conn net.PacketConn, msgMode string, randPad bool) *stunPacketConn {
	mType := stunTypeBindingIndication
	mix := false
	switch strings.ToLower(msgMode) {
	case "request", "req":
		mType = stunTypeBindingRequest
	case "mix", "both":
		mix = true
	}
	return &stunPacketConn{
		PacketConn:  conn,
		msgType:     mType,
		mixMsgType:  mix,
		randPadding: randPad,
	}
}

func (c *stunPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	payloadLen := len(p)
	padLen := (4 - (payloadLen % 4)) % 4
	dataAttrTotalLen := stunAttrHeaderLen + payloadLen + padLen

	extraPadAttrLen := 0
	if c.randPadding {
		r := int(mrand.Uint32()%4 + 1)
		extraPadAttrLen = stunAttrHeaderLen + r*4
	}

	stunMsgLen := dataAttrTotalLen + extraPadAttrLen
	totalLen := stunHeaderLen + stunMsgLen

	bufPtr := stunBufPool.Get().(*[]byte)
	buf := *bufPtr
	if totalLen > len(buf) {
		buf = make([]byte, totalLen)
	}

	// STUN Header (20 bytes)
	curMsgType := c.msgType
	if c.mixMsgType {
		if mrand.Uint32()%2 == 0 {
			curMsgType = stunTypeBindingRequest
		} else {
			curMsgType = stunTypeBindingIndication
		}
	}
	binary.BigEndian.PutUint16(buf[0:2], curMsgType)
	binary.BigEndian.PutUint16(buf[2:4], uint16(stunMsgLen))
	binary.BigEndian.PutUint32(buf[4:8], stunMagicCookie)
	fillFastTransactionID(buf[8:20])

	// STUN DATA Attribute Header (4 bytes)
	binary.BigEndian.PutUint16(buf[20:22], stunAttrTypeData)
	binary.BigEndian.PutUint16(buf[22:24], uint16(payloadLen))

	copy(buf[24:24+payloadLen], p)
	for i := 0; i < padLen; i++ {
		buf[24+payloadLen+i] = 0
	}

	// Optional Random Padding Attribute Header
	if extraPadAttrLen > 0 {
		pos := 24 + payloadLen + padLen
		binary.BigEndian.PutUint16(buf[pos:pos+2], stunAttrTypePadding)
		padContentLen := extraPadAttrLen - stunAttrHeaderLen
		binary.BigEndian.PutUint16(buf[pos+2:pos+4], uint16(padContentLen))
		for i := 0; i < padContentLen; i++ {
			buf[pos+4+i] = byte(mrand.Uint32())
		}
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
		msgType := binary.BigEndian.Uint16(rawBuf[0:2])
		if msgType != stunTypeBindingIndication && msgType != stunTypeBindingRequest {
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

func parseKCPParams(u *url.URL) (conns int, sndwnd int, rcvwnd int, dataShards int, parityShards int, msgMode string, randPad bool) {
	conns = 1
	sndwnd = 4096
	rcvwnd = 4096

	q := u.Query()
	if val := q.Get("conns"); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n >= 1 && n <= 64 {
			conns = n
		}
	}
	if val := q.Get("sndwnd"); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			sndwnd = n
		}
	}
	if val := q.Get("rcvwnd"); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			rcvwnd = n
		}
	}
	if val := q.Get("fec"); val != "" {
		parts := strings.Split(val, ":")
		if len(parts) == 2 {
			ds, err1 := strconv.Atoi(parts[0])
			ps, err2 := strconv.Atoi(parts[1])
			if err1 == nil && err2 == nil && ds >= 0 && ps >= 0 {
				dataShards = ds
				parityShards = ps
			}
		}
	}
	msgMode = q.Get("stun_msg")
	padVal := q.Get("padding")
	if padVal == "rand" || padVal == "true" || padVal == "1" {
		randPad = true
	}
	return
}

type prefixConn struct {
	net.Conn
	prefix []byte
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

type multiKCPConn struct {
	conns     []net.Conn
	txIdx     uint64
	readCh    chan []byte
	unreadBuf []byte
	closeOnce sync.Once
	ctx       context.Context
	cancel    context.CancelFunc
}

func newMultiKCPConn(conns []net.Conn) *multiKCPConn {
	ctx, cancel := context.WithCancel(context.Background())
	m := &multiKCPConn{
		conns:  conns,
		readCh: make(chan []byte, 4096),
		ctx:    ctx,
		cancel: cancel,
	}
	for _, c := range conns {
		conn := c
		go func() {
			for {
				bufPtr := multiKCPBufPool.Get().(*[]byte)
				buf := *bufPtr
				n, err := conn.Read(buf)
				if err != nil {
					multiKCPBufPool.Put(bufPtr)
					m.cancel()
					return
				}
				select {
				case m.readCh <- buf[:n]:
				case <-m.ctx.Done():
					multiKCPBufPool.Put(bufPtr)
					return
				}
			}
		}()
	}
	return m
}

func (m *multiKCPConn) Read(b []byte) (int, error) {
	if len(m.unreadBuf) > 0 {
		n := copy(b, m.unreadBuf)
		m.unreadBuf = m.unreadBuf[n:]
		return n, nil
	}
	select {
	case data, ok := <-m.readCh:
		if !ok {
			return 0, io.EOF
		}
		n := copy(b, data)
		if n < len(data) {
			m.unreadBuf = make([]byte, len(data)-n)
			copy(m.unreadBuf, data[n:])
		}
		return n, nil
	case <-m.ctx.Done():
		return 0, io.EOF
	}
}

func (m *multiKCPConn) Write(b []byte) (int, error) {
	select {
	case <-m.ctx.Done():
		return 0, io.EOF
	default:
	}
	idx := atomic.AddUint64(&m.txIdx, 1) % uint64(len(m.conns))
	return m.conns[idx].Write(b)
}

func (m *multiKCPConn) Close() error {
	m.closeOnce.Do(func() {
		m.cancel()
		for _, c := range m.conns {
			_ = c.Close()
		}
	})
	return nil
}

func (m *multiKCPConn) LocalAddr() net.Addr {
	return m.conns[0].LocalAddr()
}

func (m *multiKCPConn) RemoteAddr() net.Addr {
	return m.conns[0].RemoteAddr()
}

func (m *multiKCPConn) SetDeadline(t time.Time) error {
	for _, c := range m.conns {
		_ = c.SetDeadline(t)
	}
	return nil
}

func (m *multiKCPConn) SetReadDeadline(t time.Time) error {
	for _, c := range m.conns {
		_ = c.SetReadDeadline(t)
	}
	return nil
}

func (m *multiKCPConn) SetWriteDeadline(t time.Time) error {
	for _, c := range m.conns {
		_ = c.SetWriteDeadline(t)
	}
	return nil
}

type linkKCP struct {
	phony.Inbox
	*links
	tcp          *linkTCP
	listenconfig *net.ListenConfig
}

type pendingBundle struct {
	total int
	conns map[int]net.Conn
}

type linkKCPListener struct {
	*kcp.Listener
	mu      sync.Mutex
	pending map[[16]byte]*pendingBundle
	ready   chan net.Conn
}

func (l *linkKCPListener) Accept() (net.Conn, error) {
	for {
		select {
		case conn, ok := <-l.ready:
			if !ok {
				return nil, net.ErrClosed
			}
			return conn, nil
		default:
		}

		sess, err := l.AcceptKCP()
		if err != nil {
			return nil, err
		}
		// Apply optimal KCP performance tuning
		sess.SetNoDelay(1, 10, 2, 1)
		sess.SetWindowSize(4096, 4096)
		sess.SetMtu(1350)
		sess.SetACKNoDelay(true)
		_ = sess.SetReadBuffer(16777216)
		_ = sess.SetWriteBuffer(16777216)

		// Read magic prefix to determine if bundled connection
		hdr := make([]byte, 22)
		_ = sess.SetReadDeadline(time.Now().Add(time.Second * 3))
		n, err := io.ReadFull(sess, hdr)
		_ = sess.SetReadDeadline(time.Time{})

		if err != nil || n < 22 || string(hdr[0:4]) != "KCPB" {
			// Single session connection or error
			var unread []byte
			if n > 0 {
				unread = hdr[:n]
			}
			return &prefixConn{Conn: sess, prefix: unread}, nil
		}

		// Bundle header parsed
		var bundleID [16]byte
		copy(bundleID[:], hdr[4:20])
		idx := int(hdr[20])
		total := int(hdr[21])

		l.mu.Lock()
		b, exists := l.pending[bundleID]
		if !exists {
			b = &pendingBundle{
				total: total,
				conns: make(map[int]net.Conn),
			}
			l.pending[bundleID] = b
		}
		b.conns[idx] = sess

		if len(b.conns) == b.total {
			delete(l.pending, bundleID)
			orderedConns := make([]net.Conn, b.total)
			for i := 0; i < b.total; i++ {
				orderedConns[i] = b.conns[i]
			}
			l.mu.Unlock()
			return newMultiKCPConn(orderedConns), nil
		}
		l.mu.Unlock()
	}
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
	conns, sndwnd, rcvwnd, dataShards, parityShards, msgMode, randPad := parseKCPParams(u)

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

		dialSession := func() (net.Conn, error) {
			packetConn, err := net.ListenPacket("udp", localAddr)
			if err != nil {
				return nil, err
			}
			stunConn := newSTUNPacketConn(packetConn, msgMode, randPad)
			sess, err := kcp.NewConn2(raddr, nil, dataShards, parityShards, stunConn)
			if err != nil {
				_ = stunConn.Close()
				return nil, err
			}
			sess.SetNoDelay(1, 10, 2, 1)
			sess.SetWindowSize(sndwnd, rcvwnd)
			sess.SetMtu(1350)
			sess.SetACKNoDelay(true)
			_ = sess.SetReadBuffer(16777216)
			_ = sess.SetWriteBuffer(16777216)
			return sess, nil
		}

		if conns <= 1 {
			return dialSession()
		}

		// Multi-connection bundle
		var bundleID [16]byte
		fillFastTransactionID(bundleID[:12])
		fillFastTransactionID(bundleID[4:16])

		sessions := make([]net.Conn, conns)
		for i := 0; i < conns; i++ {
			sess, err := dialSession()
			if err != nil {
				for j := 0; j < i; j++ {
					_ = sessions[j].Close()
				}
				return nil, err
			}
			// Send 22-byte bundle header
			hdr := make([]byte, 22)
			copy(hdr[0:4], bundleMagic[:])
			copy(hdr[4:20], bundleID[:])
			hdr[20] = byte(i)
			hdr[21] = byte(conns)
			if _, err := sess.Write(hdr); err != nil {
				_ = sess.Close()
				for j := 0; j < i; j++ {
					_ = sessions[j].Close()
				}
				return nil, err
			}
			sessions[i] = sess
		}
		return newMultiKCPConn(sessions), nil
	})
}

func (l *linkKCP) listen(ctx context.Context, u *url.URL, sintf string) (net.Listener, error) {
	_, _, _, dataShards, parityShards, msgMode, randPad := parseKCPParams(u)

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
	stunConn := newSTUNPacketConn(packetConn, msgMode, randPad)
	listener, err := kcp.ServeConn(nil, dataShards, parityShards, stunConn)
	if err != nil {
		_ = stunConn.Close()
		return nil, err
	}
	return &linkKCPListener{
		Listener: listener,
		pending:  make(map[[16]byte]*pendingBundle),
		ready:    make(chan net.Conn, 64),
	}, nil
}
