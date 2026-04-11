package ss

import (
	"bufio"
	"context"
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"github.com/v2rayA/v2rayA/pkg/plugin"
)

const (
	testSS2022IdentityPSK = "plwpSUaDxoeuxNzl03v6lGMAya/8K8stAE6IhK2xvrE="
	testSS2022UserPSK     = "eDhBQmVFQ0tMWnM3X1l5NkR4OTFiNDB4dUJKSFpnVjU="
)

func TestNewShadowsocksDialer_SS2022Accepted(t *testing.T) {
	link := "ss://MjAyMi1ibGFrZTMtYWVzLTI1Ni1nY206" +
		"cGx3cFNVYUR4b2V1eE56bDAzdjZsR01BeWEvOEs4c3RBRTZJaEsyeHZyRT06" +
		"ZURoQlFtVkZRMHRNV25NM1gxbDVOa1I0T1RGaU5EQjRkVUpLU0ZwblZqVT0=@8.148.220.188:10220#ss2022-test"

	d, err := NewShadowsocksDialer(link, &plugin.Direct{})
	if err != nil {
		t.Fatalf("NewShadowsocksDialer returned error: %v", err)
	}
	if d == nil {
		t.Fatal("expected dialer, got nil")
	}
}

func TestNewShadowsocksDialer_SS2022RejectsPlugins(t *testing.T) {
	link := "ss://MjAyMi1ibGFrZTMtYWVzLTI1Ni1nY206" +
		"cGx3cFNVYUR4b2V1eE56bDAzdjZsR01BeWEvOEs4c3RBRTZJaEsyeHZyRT06" +
		"ZURoQlFtVkZRMHRNV25NM1gxbDVOa1I0T1RGaU5EQjRkVUpLU0ZwblZqVT0=@8.148.220.188:10220?plugin=v2ray-plugin%3Bhost%3Dexample.com#ss2022-test"

	_, err := NewShadowsocksDialer(link, &plugin.Direct{})
	if err == nil {
		t.Fatal("expected error for shadowsocks-2022 with plugin, got nil")
	}
}

func TestShadowsocks2022Dialer_TCPRoundTrip(t *testing.T) {
	link := "ss://MjAyMi1ibGFrZTMtYWVzLTI1Ni1nY206" +
		"cGx3cFNVYUR4b2V1eE56bDAzdjZsR01BeWEvOEs4c3RBRTZJaEsyeHZyRT06" +
		"ZURoQlFtVkZRMHRNV25NM1gxbDVOa1I0T1RGaU5EQjRkVUpLU0ZwblZqVT0=@8.148.220.188:10220#ss2022-test"

	d, err := NewShadowsocksDialer(link, &plugin.Direct{})
	if err != nil {
		t.Fatalf("NewShadowsocksDialer returned error: %v", err)
	}

	conn, err := d.DialContext(context.Background(), "tcp", "www.gstatic.com:443")
	if err != nil {
		t.Fatalf("DialContext returned error: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))

	tlsConn := tls.Client(conn, &tls.Config{ServerName: "www.gstatic.com"})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}
	if _, err := tlsConn.Write([]byte("GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("TLS write failed: %v", err)
	}
	line, err := bufio.NewReader(tlsConn).ReadString('\n')
	if err != nil {
		t.Fatalf("TLS read failed: %v", err)
	}
	if !strings.Contains(line, "204") {
		t.Fatalf("unexpected HTTP status line: %q", line)
	}
}
