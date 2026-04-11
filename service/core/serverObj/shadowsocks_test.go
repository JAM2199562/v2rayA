package serverObj

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/v2rayA/v2rayA/core/v2ray/where"
)

const (
	testSS2022IdentityPSK = "plwpSUaDxoeuxNzl03v6lGMAya/8K8stAE6IhK2xvrE="
	testSS2022UserPSK     = "eDhBQmVFQ0tMWnM3X1l5NkR4OTFiNDB4dUJKSFpnVjU="
)

func newSS2022Node() *Shadowsocks {
	return &Shadowsocks{
		Name:     "ss2022-test",
		Server:   "8.148.220.188",
		Port:     10220,
		Password: testSS2022IdentityPSK + ":" + testSS2022UserPSK,
		Cipher:   "2022-blake3-aes-256-gcm",
		Protocol: "shadowsocks",
	}
}

func TestShadowsocks2022Configuration_V2Ray_UsesBestAvailablePath(t *testing.T) {
	obj := newSS2022Node()

	cfg, err := obj.Configuration(PriorInfo{
		Tag:         "test-ss2022",
		Variant:     where.V2ray,
		CoreVersion: "5.47.0",
	})
	if err != nil {
		t.Fatalf("Configuration returned error: %v", err)
	}

	b, err := json.Marshal(cfg.CoreOutbound)
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}
	got := string(b)

	if cfg.PluginChain == "" {
		for _, want := range []string{
			`"protocol":"shadowsocks2022"`,
			`"address":"8.148.220.188"`,
			`"port":10220`,
			`"method":"2022-blake3-aes-256-gcm"`,
			`"psk":"` + testSS2022UserPSK + `"`,
			`"ipsk":["` + testSS2022IdentityPSK + `"]`,
		} {
			if !strings.Contains(got, want) {
				t.Fatalf("native shadowsocks2022 config missing %s in %s", want, got)
			}
		}
		return
	}

	if cfg.CoreOutbound.Protocol != "socks" {
		t.Fatalf("plugin fallback should expose socks outbound, got %q", cfg.CoreOutbound.Protocol)
	}
	if !strings.Contains(cfg.PluginChain, "ss://") {
		t.Fatalf("plugin fallback should preserve ss link, got %q", cfg.PluginChain)
	}
}

func TestShadowsocks2022Configuration_Xray_UsesPluginFallback(t *testing.T) {
	obj := newSS2022Node()

	cfg, err := obj.Configuration(PriorInfo{
		Tag:         "test-ss2022-xray",
		Variant:     where.Xray,
		CoreVersion: "1.8.0",
	})
	if err != nil {
		t.Fatalf("Configuration returned error: %v", err)
	}
	if cfg.PluginChain == "" {
		t.Fatal("xray path should currently keep plugin fallback for shadowsocks-2022")
	}
	if cfg.CoreOutbound.Protocol != "socks" {
		t.Fatalf("plugin fallback should expose socks outbound, got %q", cfg.CoreOutbound.Protocol)
	}
}

func TestShadowsocks2022NeedPluginPort_CurrentlyRequiresPluginPort(t *testing.T) {
	obj := newSS2022Node()
	if !obj.NeedPluginPort() {
		t.Fatal("current shadowsocks-2022 implementation still requires a plugin port")
	}
}
