package knownhosts

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestNew(t *testing.T) {
	khPath := writeTestKnownHosts(t)

	// Valid path should return a callback and no error; callback should be usable
	// in ssh.ClientConfig.HostKeyCallback
	if kh, err := New(khPath); err != nil {
		t.Errorf("Unexpected error from New on valid known_hosts path: %v", err)
	} else {
		_ = ssh.ClientConfig{
			HostKeyCallback: kh.HostKeyCallback(),
		}
	}

	// Invalid path should return an error
	if _, err := New(khPath + "_does_not_exist"); err == nil {
		t.Error("Expected error from New with invalid path, but error was nil")
	}
}

func TestHostKeyAlgorithms(t *testing.T) {
	khPath := writeTestKnownHosts(t)
	kh, err := New(khPath)
	if err != nil {
		t.Fatalf("Unexpected error from New: %v", err)
	}

	expectedAlgorithms := map[string][]string{
		"only-rsa.example.test:22":     {"ssh-rsa"},
		"only-ecdsa.example.test:22":   {"ecdsa-sha2-nistp256"},
		"only-ed25519.example.test:22": {"ssh-ed25519"},
		"multi.example.test:2233":      {"ssh-rsa", "ecdsa-sha2-nistp256", "ssh-ed25519"},
		"192.168.1.102:2222":           {"ecdsa-sha2-nistp256", "ssh-ed25519"},
		"unknown-host.example.test":    {}, // host not in file
		"multi.example.test:22":        {}, // different port than entry in file
		"192.168.1.102":                {}, // different port than entry in file
	}
	for host, expected := range expectedAlgorithms {
		actual := kh.HostKeyAlgorithms(host)
		if len(actual) != len(expected) {
			t.Errorf("Unexpected number of algorithms returned by HostKeyAlgorithms(%q): expected %d, found %d", host, len(expected), len(actual))
			continue
		}
		for n := range expected {
			if expected[n] != actual[n] {
				t.Errorf("Unexpected algorithms returned by HostKeyAlgorithms(%q): expected %v, found %v", host, expected, actual)
				break
			}
		}
	}
}

func TestIsHostKeyChanged(t *testing.T) {
	khPath := writeTestKnownHosts(t)
	kh, err := New(khPath)
	if err != nil {
		t.Fatalf("Unexpected error from New: %v", err)
	}
	noAddr, _ := net.ResolveTCPAddr("tcp", "0.0.0.0:0")
	pubKey := generatePubKeyEd25519(t)

	// Unknown host: should return false
	if err := kh("unknown.example.test:22", noAddr, pubKey); IsHostKeyChanged(err) {
		t.Error("IsHostKeyChanged unexpectedly returned true for unknown host")
	}

	// Known host, wrong key: should return true
	if err := kh("multi.example.test:2233", noAddr, pubKey); !IsHostKeyChanged(err) {
		t.Error("IsHostKeyChanged unexpectedly returned false for known host with different host key")
	}

	// Append the key for a known host that doesn't already have that key type,
	// re-init the known_hosts, and check again: should return false
	f, err := os.OpenFile(khPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("Unable to open %s for writing: %v", khPath, err)
	}
	if err := WriteKnownHost(f, "only-ecdsa.example.test:22", noAddr, pubKey); err != nil {
		t.Fatalf("Unable to write known host line: %v", err)
	}
	f.Close()
	if kh, err = New(khPath); err != nil {
		t.Fatalf("Unexpected error from New: %v", err)
	}
	if err := kh("only-ecdsa.example.test:22", noAddr, pubKey); IsHostKeyChanged(err) {
		t.Error("IsHostKeyChanged unexpectedly returned true for valid known host")
	}
}

func TestIsHostUnknown(t *testing.T) {
	khPath := writeTestKnownHosts(t)
	kh, err := New(khPath)
	if err != nil {
		t.Fatalf("Unexpected error from New: %v", err)
	}
	noAddr, _ := net.ResolveTCPAddr("tcp", "0.0.0.0:0")
	pubKey := generatePubKeyEd25519(t)

	// Unknown host: should return true
	if err := kh("unknown.example.test:22", noAddr, pubKey); !IsHostUnknown(err) {
		t.Error("IsHostUnknown unexpectedly returned false for unknown host")
	}

	// Known host, wrong key: should return false
	if err := kh("multi.example.test:2233", noAddr, pubKey); IsHostUnknown(err) {
		t.Error("IsHostUnknown unexpectedly returned true for known host with different host key")
	}

	// Append the key for an unknown host, re-init the known_hosts, and check
	// again: should return false
	f, err := os.OpenFile(khPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("Unable to open %s for writing: %v", khPath, err)
	}
	if err := WriteKnownHost(f, "newhost.example.test:22", noAddr, pubKey); err != nil {
		t.Fatalf("Unable to write known host line: %v", err)
	}
	f.Close()
	if kh, err = New(khPath); err != nil {
		t.Fatalf("Unexpected error from New: %v", err)
	}
	if err := kh("newhost.example.test:22", noAddr, pubKey); IsHostUnknown(err) {
		t.Error("IsHostUnknown unexpectedly returned true for valid known host")
	}
}

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"127.0.0.1":                 "127.0.0.1",
		"127.0.0.1:22":              "127.0.0.1",
		"[127.0.0.1]:22":            "127.0.0.1",
		"[127.0.0.1]:23":            "[127.0.0.1]:23",
		"127.0.0.1:23":              "[127.0.0.1]:23",
		"[a.b.c]:22":                "a.b.c",
		"abcd::abcd:abcd:abcd":      "abcd::abcd:abcd:abcd",
		"[abcd::abcd:abcd:abcd]":    "abcd::abcd:abcd:abcd",
		"[abcd::abcd:abcd:abcd]:22": "abcd::abcd:abcd:abcd",
		"[abcd::abcd:abcd:abcd]:23": "[abcd::abcd:abcd:abcd]:23",
	} {
		got := Normalize(in)
		if got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLine(t *testing.T) {
	edKeyStr := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF9Wn63tLEhSWl9Ye+4x2GnruH8cq0LIh2vum/fUHrFQ"
	edKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(edKeyStr))
	if err != nil {
		t.Fatalf("Unable to parse authorized key: %v", err)
	}
	for in, want := range map[string]string{
		"server.org":                             "server.org " + edKeyStr,
		"server.org:22":                          "server.org " + edKeyStr,
		"server.org:23":                          "[server.org]:23 " + edKeyStr,
		"[c629:1ec4:102:304:102:304:102:304]:22": "c629:1ec4:102:304:102:304:102:304 " + edKeyStr,
		"[c629:1ec4:102:304:102:304:102:304]:23": "[c629:1ec4:102:304:102:304:102:304]:23 " + edKeyStr,
	} {
		if got := Line([]string{in}, edKey); got != want {
			t.Errorf("Line(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWriteKnownHost(t *testing.T) {
	edKeyStr := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF9Wn63tLEhSWl9Ye+4x2GnruH8cq0LIh2vum/fUHrFQ"
	edKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(edKeyStr))
	if err != nil {
		t.Fatalf("Unable to parse authorized key: %v", err)
	}
	for _, m := range []struct {
		hostname   string
		remoteAddr string
		want       string
	}{
		{hostname: "::1", remoteAddr: "[::1]:22", want: "::1 " + edKeyStr + "\n"},
		{hostname: "127.0.0.1", remoteAddr: "127.0.0.1:22", want: "127.0.0.1 " + edKeyStr + "\n"},
		{hostname: "ipv4.test", remoteAddr: "192.168.0.1:23", want: "ipv4.test,[192.168.0.1]:23 " + edKeyStr + "\n"},
		{hostname: "ipv6.test", remoteAddr: "[ff01::1234]:23", want: "ipv6.test,[ff01::1234]:23 " + edKeyStr + "\n"},
	} {
		remote, err := net.ResolveTCPAddr("tcp", m.remoteAddr)
		if err != nil {
			t.Fatalf("Unable to resolve tcp addr: %v", err)
		}
		var got bytes.Buffer
		if err = WriteKnownHost(&got, m.hostname, remote, edKey); err != nil {
			t.Fatalf("Unable to write known host: %v", err)
		}
		if got.String() != m.want {
			t.Errorf("WriteKnownHost(%q) = %q, want %q", m.hostname, got.String(), m.want)
		}
	}
}

// writeTestKnownHosts generates the test known_hosts file and returns the
// file path to it. The generated file contains several hosts with a mix of
// key types; each known host has between 1 and 3 different known host keys.
// If generating or writing the file fails, the test fails.
func writeTestKnownHosts(t *testing.T) string {
	t.Helper()
	hosts := map[string][]ssh.PublicKey{
		"only-rsa.example.test:22":     {generatePubKeyRSA(t)},
		"only-ecdsa.example.test:22":   {generatePubKeyECDSA(t)},
		"only-ed25519.example.test:22": {generatePubKeyEd25519(t)},
		"multi.example.test:2233":      {generatePubKeyRSA(t), generatePubKeyECDSA(t), generatePubKeyEd25519(t)},
		"192.168.1.102:2222":           {generatePubKeyECDSA(t), generatePubKeyEd25519(t)},
		"[fe80::abc:abc:abcd:abcd]:22": {generatePubKeyEd25519(t), generatePubKeyRSA(t)},
	}

	dir := t.TempDir()
	khPath := filepath.Join(dir, "known_hosts")
	f, err := os.OpenFile(khPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("Unable to open %s for writing: %v", khPath, err)
	}
	defer f.Close()
	noAddr, _ := net.ResolveTCPAddr("tcp", "0.0.0.0:0")
	for host, keys := range hosts {
		for _, k := range keys {
			if err := WriteKnownHost(f, host, noAddr, k); err != nil {
				t.Fatalf("Unable to write known host line: %v", err)
			}
		}
	}
	return khPath
}

func generatePubKeyRSA(t *testing.T) ssh.PublicKey {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("Unable to generate RSA key: %v", err)
	}
	pub, err := ssh.NewPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("Unable to convert public key: %v", err)
	}
	return pub
}

func generatePubKeyECDSA(t *testing.T) ssh.PublicKey {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Unable to generate ECDSA key: %v", err)
	}
	pub, err := ssh.NewPublicKey(privKey.Public())
	if err != nil {
		t.Fatalf("Unable to convert public key: %v", err)
	}
	return pub
}

func generatePubKeyEd25519(t *testing.T) ssh.PublicKey {
	t.Helper()
	rawPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Unable to generate ed25519 key: %v", err)
	}
	pub, err := ssh.NewPublicKey(rawPub)
	if err != nil {
		t.Fatalf("Unable to convert public key: %v", err)
	}
	return pub
}
