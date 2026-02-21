package serverObj

import (
	"testing"

	"github.com/v2rayA/v2rayA/core/coreObj"
)

func TestVlessConfiguration_UsesEncryptionFromURL(t *testing.T) {
	link := "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp&security=tls&encryption=mlkem768x25519plus.native%2Fxorpub%2Frandom#enc-test"

	obj, err := ParseVlessURL(link)
	if err != nil {
		t.Fatalf("ParseVlessURL returned error: %v", err)
	}

	cfg, err := obj.Configuration(PriorInfo{Tag: "test"})
	if err != nil {
		t.Fatalf("Configuration returned error: %v", err)
	}

	vnext, ok := cfg.CoreOutbound.Settings.Vnext.([]coreObj.Vnext)
	if !ok {
		t.Fatalf("unexpected vnext type: %T", cfg.CoreOutbound.Settings.Vnext)
	}
	if len(vnext) == 0 || len(vnext[0].Users) == 0 {
		t.Fatalf("vnext users should not be empty")
	}

	got := vnext[0].Users[0].Encryption
	want := "mlkem768x25519plus.native/xorpub/random"
	if got != want {
		t.Fatalf("unexpected encryption: got %q want %q", got, want)
	}
}

func TestVlessConfiguration_DefaultEncryptionNone(t *testing.T) {
	link := "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp&security=tls#enc-default"

	obj, err := ParseVlessURL(link)
	if err != nil {
		t.Fatalf("ParseVlessURL returned error: %v", err)
	}

	cfg, err := obj.Configuration(PriorInfo{Tag: "test"})
	if err != nil {
		t.Fatalf("Configuration returned error: %v", err)
	}

	vnext, ok := cfg.CoreOutbound.Settings.Vnext.([]coreObj.Vnext)
	if !ok {
		t.Fatalf("unexpected vnext type: %T", cfg.CoreOutbound.Settings.Vnext)
	}
	if len(vnext) == 0 || len(vnext[0].Users) == 0 {
		t.Fatalf("vnext users should not be empty")
	}

	got := vnext[0].Users[0].Encryption
	if got != "none" {
		t.Fatalf("unexpected encryption default: got %q want %q", got, "none")
	}
}
