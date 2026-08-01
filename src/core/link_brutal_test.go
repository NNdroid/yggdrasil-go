package core

import (
	"net/url"
	"testing"
)

func TestTCPBrutalParamsParsing(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		input         string
		expectedBytes uint64
	}{
		{
			input:         "100M",
			expectedBytes: 12500000,
		},
		{
			input:         "100Mbps",
			expectedBytes: 12500000,
		},
		{
			input:         "1G",
			expectedBytes: 125000000,
		},
		{
			input:         "500K",
			expectedBytes: 62500,
		},
	} {
		got := parseRateBytesPerSec(tc.input)
		if got != tc.expectedBytes {
			t.Fatalf("parseRateBytesPerSec(%s) = %d, want %d", tc.input, got, tc.expectedBytes)
		}
	}

	u1, _ := url.Parse("tcp://1.2.3.4:9001?cc=brutal&rate=100M")
	cc1, rate1 := parseTCPCongestionParams(u1)
	if cc1 != "brutal" || rate1 != 12500000 {
		t.Fatalf("parseTCPCongestionParams got cc=%s, rate=%d", cc1, rate1)
	}

	u2, _ := url.Parse("ws://1.2.3.4:9001/ws?brutal=50M")
	cc2, rate2 := parseTCPCongestionParams(u2)
	if cc2 != "brutal" || rate2 != 6250000 {
		t.Fatalf("parseTCPCongestionParams got cc=%s, rate=%d", cc2, rate2)
	}
}
