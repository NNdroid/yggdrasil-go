package core

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Arceliar/phony"
	"github.com/coder/websocket"
)

const fallbackHTML = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
<p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.</p>
<p><em>Thank you for using nginx.</em></p>
</body>
</html>`

type linkWS struct {
	phony.Inbox
	*links
	listenconfig *net.ListenConfig
}

type linkWSConn struct {
	net.Conn
}

type linkWSListener struct {
	ch         chan *linkWSConn
	ctx        context.Context
	httpServer *http.Server
	listener   net.Listener
}

type wsServer struct {
	ch            chan *linkWSConn
	ctx           context.Context
	acceptOptions *websocket.AcceptOptions
}

func (l *linkWSListener) Accept() (net.Conn, error) {
	qs := <-l.ch
	if qs == nil {
		return nil, context.Canceled
	}
	return qs, nil
}

func (l *linkWSListener) Addr() net.Addr {
	return l.listener.Addr()
}

func (l *linkWSListener) Close() error {
	if err := l.httpServer.Shutdown(l.ctx); err != nil {
		return err
	}
	return l.listener.Close()
}

func (s *wsServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// If not a WebSocket upgrade request or probe scanner, return realistic Nginx HTML index page
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "nginx/1.24.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fallbackHTML))
		return
	}

	c, err := websocket.Accept(w, r, s.acceptOptions)
	if err != nil {
		return
	}

	s.ch <- &linkWSConn{
		Conn: websocket.NetConn(s.ctx, c, websocket.MessageBinary),
	}
}

func (l *links) newLinkWS() *linkWS {
	lt := &linkWS{
		links: l,
		listenconfig: &net.ListenConfig{
			KeepAlive: -1,
		},
	}
	return lt
}

func parseWSOptions(u *url.URL) (subprotocols []string, userAgent string, customHost string) {
	q := u.Query()
	subproto := q.Get("subprotocol")
	if subproto == "" {
		subproto = q.Get("subproto")
	}
	switch strings.ToLower(subproto) {
	case "none", "disable", "off":
		subprotocols = nil
	case "":
		subprotocols = []string{"ygg-ws"}
	default:
		subprotocols = []string{subproto}
	}

	userAgent = q.Get("useragent")
	if userAgent == "" {
		userAgent = q.Get("ua")
	}
	if userAgent == "" {
		userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	}

	customHost = q.Get("host")
	return
}

func wsAcceptOptions(url *url.URL) *websocket.AcceptOptions {
	subprotos, _, _ := parseWSOptions(url)
	opts := &websocket.AcceptOptions{
		Subprotocols: subprotos,
	}
	for _, origin := range url.Query()["origin"] {
		switch origin {
		case "":
			continue
		case "*":
			opts.InsecureSkipVerify = true
			opts.OriginPatterns = nil
			return opts
		default:
			opts.OriginPatterns = append(opts.OriginPatterns, origin)
		}
	}
	return opts
}

func (l *linkWS) dial(ctx context.Context, url *url.URL, info linkInfo, options linkOptions) (net.Conn, error) {
	return l.findSuitableIP(url, func(hostname string, ip net.IP, port int) (net.Conn, error) {
		u := *url
		u.Host = net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
		addr := &net.TCPAddr{
			IP:   ip,
			Port: port,
		}
		dialer, err := l.tcp.dialerFor(addr, info.sintf)
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

		wsconn, _, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{
			HTTPClient: &http.Client{
				Transport: &http.Transport{
					Proxy:       http.ProxyFromEnvironment,
					Dial:        dialer.Dial,
					DialContext: dialer.DialContext,
				},
			},
			HTTPHeader:   headers,
			Subprotocols: subprotos,
			Host:         customHost,
		})
		if err != nil {
			return nil, err
		}
		return &linkWSConn{
			Conn: websocket.NetConn(ctx, wsconn, websocket.MessageBinary),
		}, nil
	})
}

func (l *linkWS) listen(ctx context.Context, url *url.URL, _ string) (net.Listener, error) {
	nl, err := l.listenconfig.Listen(ctx, "tcp", url.Host)
	if err != nil {
		return nil, err
	}

	ch := make(chan *linkWSConn)

	httpServer := &http.Server{
		Handler: &wsServer{
			ch:            ch,
			ctx:           ctx,
			acceptOptions: wsAcceptOptions(url),
		},
		BaseContext:  func(_ net.Listener) context.Context { return ctx },
		ReadTimeout:  time.Second * 10,
		WriteTimeout: time.Second * 10,
	}

	lwl := &linkWSListener{
		ch:         ch,
		ctx:        ctx,
		httpServer: httpServer,
		listener:   nl,
	}
	go lwl.httpServer.Serve(nl) // nolint:errcheck
	return lwl, nil
}
