package core

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Arceliar/phony"
)

type linkTCP struct {
	phony.Inbox
	*links
	listenconfig *net.ListenConfig
}

func (l *links) newLinkTCP() *linkTCP {
	lt := &linkTCP{
		links: l,
		listenconfig: &net.ListenConfig{
			KeepAlive: -1,
		},
	}
	lt.listenconfig.Control = func(network, address string, c syscall.RawConn) error { return nil }
	return lt
}

func parseRateBytesPerSec(rateStr string) uint64 {
	rateStr = strings.TrimSpace(strings.ToUpper(rateStr))
	if rateStr == "" {
		return 0
	}
	var mult uint64 = 1
	if strings.HasSuffix(rateStr, "M") || strings.HasSuffix(rateStr, "MBPS") {
		mult = 1000 * 1000 / 8
		rateStr = strings.TrimSuffix(strings.TrimSuffix(rateStr, "MBPS"), "M")
	} else if strings.HasSuffix(rateStr, "G") || strings.HasSuffix(rateStr, "GBPS") {
		mult = 1000 * 1000 * 1000 / 8
		rateStr = strings.TrimSuffix(strings.TrimSuffix(rateStr, "GBPS"), "G")
	} else if strings.HasSuffix(rateStr, "K") || strings.HasSuffix(rateStr, "KBPS") {
		mult = 1000 / 8
		rateStr = strings.TrimSuffix(strings.TrimSuffix(rateStr, "KBPS"), "K")
	} else if strings.HasSuffix(rateStr, "BPS") {
		mult = 1 / 8
		rateStr = strings.TrimSuffix(rateStr, "BPS")
	}

	val, err := strconv.ParseUint(rateStr, 10, 64)
	if err != nil {
		return 0
	}
	return val * mult
}

func parseTCPCongestionParams(u *url.URL) (cc string, rate uint64) {
	if u == nil {
		return "", 0
	}
	q := u.Query()
	cc = q.Get("cc")
	if cc == "" {
		cc = q.Get("congestion")
	}
	rateStr := q.Get("rate")
	if r := q.Get("brutal"); r != "" {
		cc = "brutal"
		rateStr = r
	}
	rate = parseRateBytesPerSec(rateStr)
	return
}

func (l *linkTCP) dial(ctx context.Context, url *url.URL, info linkInfo, options linkOptions) (net.Conn, error) {
	return l.findSuitableIP(url, func(hostname string, ip net.IP, port int) (net.Conn, error) {
		addr := &net.TCPAddr{
			IP:   ip,
			Port: port,
		}
		dialer, err := l.tcp.dialerFor(addr, info.sintf, url)
		if err != nil {
			return nil, err
		}
		return dialer.DialContext(ctx, "tcp", addr.String())
	})
}

func (l *linkTCP) listen(ctx context.Context, url *url.URL, sintf string) (net.Listener, error) {
	hostport := url.Host
	if sintf != "" {
		if host, port, err := net.SplitHostPort(hostport); err == nil {
			hostport = fmt.Sprintf("[%s%%%s]:%s", host, sintf, port)
		}
	}
	cc, rate := parseTCPCongestionParams(url)
	lc := &net.ListenConfig{
		KeepAlive: -1,
		Control:   l.getControl(sintf, cc, rate),
	}
	return lc.Listen(ctx, "tcp", hostport)
}

func (l *linkTCP) dialerFor(dst *net.TCPAddr, sintf string, u *url.URL) (*net.Dialer, error) {
	if dst.IP.IsLinkLocalUnicast() {
		if sintf != "" {
			dst.Zone = sintf
		}
		if dst.Zone == "" {
			return nil, fmt.Errorf("link-local address requires a zone")
		}
	}
	cc, rate := parseTCPCongestionParams(u)
	dialer := &net.Dialer{
		Timeout:   time.Second * 5,
		KeepAlive: -1,
		Control:   l.getControl(sintf, cc, rate),
	}
	if sintf != "" {
		dialer.Control = l.getControl(sintf, cc, rate)
		ief, err := net.InterfaceByName(sintf)
		if err != nil {
			if dst.IP.IsLinkLocalUnicast() && dst.Zone != "" {
				return dialer, nil
			}
			return nil, fmt.Errorf("interface %q not found", sintf)
		}
		if ief.Flags&net.FlagUp == 0 {
			return nil, fmt.Errorf("interface %q is not up", sintf)
		}
		addrs, err := ief.Addrs()
		if err != nil {
			if dst.IP.IsLinkLocalUnicast() && dst.Zone != "" {
				return dialer, nil
			}
			return nil, fmt.Errorf("interface %q addresses not available: %w", sintf, err)
		}
		for addrindex, addr := range addrs {
			src, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if !src.IsGlobalUnicast() && !src.IsLinkLocalUnicast() {
				continue
			}
			bothglobal := src.IsGlobalUnicast() == dst.IP.IsGlobalUnicast()
			bothlinklocal := src.IsLinkLocalUnicast() == dst.IP.IsLinkLocalUnicast()
			if !bothglobal && !bothlinklocal {
				continue
			}
			if (src.To4() != nil) != (dst.IP.To4() != nil) {
				continue
			}
			if bothglobal || bothlinklocal || addrindex == len(addrs)-1 {
				dialer.LocalAddr = &net.TCPAddr{
					IP:   src,
					Port: 0,
					Zone: sintf,
				}
				break
			}
		}
		if dialer.LocalAddr == nil {
			if dst.IP.IsLinkLocalUnicast() && dst.Zone != "" {
				return dialer, nil
			}
			return nil, fmt.Errorf("no suitable source address found on interface %q", sintf)
		}
	}
	return dialer, nil
}
