package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/Arceliar/phony"
	"github.com/coder/websocket"
)

type linkWSS struct {
	phony.Inbox
	*links
	tlsconfig *tls.Config
}

type linkWSSConn struct {
	net.Conn
}

func (l *links) newLinkWSS() *linkWSS {
	lwss := &linkWSS{
		links:     l,
		tlsconfig: l.core.config.tls.Clone(),
	}
	return lwss
}

func (l *linkWSS) dial(ctx context.Context, url *url.URL, info linkInfo, options linkOptions) (net.Conn, error) {
	tlsconfig := l.tlsconfig.Clone()
	return l.findSuitableIP(url, func(hostname string, ip net.IP, port int) (net.Conn, error) {
		tlsconfig.ServerName = hostname
		tlsconfig.MinVersion = tls.VersionTLS12
		tlsconfig.MaxVersion = tls.VersionTLS13
		u := *url
		u.Host = net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
		addr := &net.TCPAddr{
			IP:   ip,
			Port: port,
		}
		dialer, err := l.tcp.dialerFor(addr, info.sintf, url)
		if err != nil {
			return nil, err
		}

		subprotos, ua, customHost := parseWSOptions(url)
		if customHost == "" {
			customHost = hostname
		}

		headers := make(http.Header)
		headers.Set("User-Agent", ua)
		headers.Set("Accept-Language", "en-US,en;q=0.9")
		headers.Set("Cache-Control", "no-cache")
		// Randomize client request packet size to break DPI packet length fingerprinting
		headers.Set("X-Pad", generateRandomPad(64, 512))

		wsconn, _, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{
			HTTPClient: &http.Client{
				Transport: &http.Transport{
					Proxy:           http.ProxyFromEnvironment,
					Dial:            dialer.Dial,
					DialContext:     dialer.DialContext,
					TLSClientConfig: tlsconfig,
				},
			},
			HTTPHeader:   headers,
			Subprotocols: subprotos,
			Host:         customHost,
		})
		if err != nil {
			return nil, err
		}
		return &linkWSSConn{
			Conn: websocket.NetConn(ctx, wsconn, websocket.MessageBinary),
		}, nil
	})
}

func (l *linkWSS) listen(ctx context.Context, url *url.URL, _ string) (net.Listener, error) {
	return nil, fmt.Errorf("WSS listener not supported, use WS listener behind reverse proxy instead")
}
