//go:build linux

package core

import (
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	tcpBrutalParamsOpt = 185
)

type tcpBrutalParams struct {
	rate uint64 // bytes per second
	cwnd uint32 // initial congestion window (0 for default)
}

func applyTCPCongestionControl(fd uintptr, ccName string, rate uint64) error {
	if ccName == "" {
		return nil
	}
	_ = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, ccName)
	if strings.EqualFold(ccName, "brutal") && rate > 0 {
		params := tcpBrutalParams{
			rate: rate,
			cwnd: 0,
		}
		b := (*[12]byte)(unsafe.Pointer(&params))[:]
		_ = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, tcpBrutalParamsOpt, string(b))
	}
	return nil
}

func (t *linkTCP) tcpContext(network, address string, c syscall.RawConn) error {
	return nil
}

func (t *linkTCP) getControl(sintf string, ccName string, rate uint64) func(string, string, syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var err error
		btd := func(fd uintptr) {
			if sintf != "" {
				err = unix.BindToDevice(int(fd), sintf)
			}
			if ccName != "" {
				_ = applyTCPCongestionControl(fd, ccName, rate)
			}
		}
		_ = c.Control(btd)
		if err != nil && sintf != "" {
			t.core.log.Debugln("Failed to set SO_BINDTODEVICE:", sintf)
		}
		return t.tcpContext(network, address, c)
	}
}
