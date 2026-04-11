package ss

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	ss2022 "github.com/metacubex/sing-shadowsocks2"
	mbuf "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/v2rayA/v2rayA/core/serverObj"
	"github.com/v2rayA/v2rayA/pkg/plugin"
)

type Shadowsocks2022 struct {
	method     ss2022.Method
	upstream   plugin.Dialer
	serverAddr string
}

func newShadowsocks2022Dialer(link string, d plugin.Dialer) (plugin.Dialer, error) {
	obj, err := serverObj.ParseSSURL(link)
	if err != nil {
		return nil, err
	}
	if obj.Plugin.Name != "" {
		return nil, fmt.Errorf("shadowsocks-2022 with SIP003 plugin is not supported yet")
	}
	method, err := ss2022.CreateMethod(context.Background(), obj.Cipher, ss2022.MethodOptions{
		Password: obj.Password,
	})
	if err != nil {
		return nil, err
	}
	return &Shadowsocks2022{
		method:     method,
		upstream:   d,
		serverAddr: net.JoinHostPort(obj.Server, strconv.Itoa(obj.Port)),
	}, nil
}

func (s *Shadowsocks2022) Addr() string {
	return ""
}

func (s *Shadowsocks2022) Dial(network, addr string) (net.Conn, error) {
	return s.DialContext(context.Background(), network, addr)
}

func (s *Shadowsocks2022) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := s.upstream.DialContext(ctx, "tcp", s.serverAddr)
	if err != nil {
		return nil, fmt.Errorf("[shadowsocks2022]: dial to %s: %w", s.serverAddr, err)
	}
	wrapped, err := s.method.DialConn(conn, M.ParseSocksaddr(addr))
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("[shadowsocks2022]: wrap %s: %w", addr, err)
	}
	return wrapped, nil
}

func (s *Shadowsocks2022) DialUDP(network string) (plugin.FakeNetPacketConn, error) {
	conn, err := s.upstream.DialContext(context.Background(), "tcp", s.serverAddr)
	if err != nil {
		return nil, fmt.Errorf("[shadowsocks2022]: dial udp to %s: %w", s.serverAddr, err)
	}
	return &singPacketConnAdapter{conn: conn, pc: s.method.DialPacketConn(conn)}, nil
}

type singPacketConnAdapter struct {
	conn net.Conn
	pc   N.NetPacketConn
}

func (s *singPacketConnAdapter) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buffer := mbuf.NewSize(len(p))
	defer buffer.Release()
	destination, err := s.pc.ReadPacket(buffer)
	if err != nil {
		return 0, nil, err
	}
	copied := copy(p, buffer.Bytes())
	return copied, destination.UDPAddr(), nil
}

func (s *singPacketConnAdapter) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	buffer := mbuf.NewPacket()
	defer buffer.Release()
	buffer.Resize(buffer.RawCap()-len(p), len(p))
	copy(buffer.Bytes(), p)
	err = s.pc.WritePacket(buffer, M.SocksaddrFromNet(addr))
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *singPacketConnAdapter) Close() error {
	return s.conn.Close()
}

func (s *singPacketConnAdapter) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *singPacketConnAdapter) SetDeadline(t time.Time) error {
	return s.conn.SetDeadline(t)
}

func (s *singPacketConnAdapter) SetReadDeadline(t time.Time) error {
	return s.conn.SetReadDeadline(t)
}

func (s *singPacketConnAdapter) SetWriteDeadline(t time.Time) error {
	return s.conn.SetWriteDeadline(t)
}
