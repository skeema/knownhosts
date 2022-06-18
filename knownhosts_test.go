package knownhosts

import (
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
	pubKey := generagePubKeyEd25519(t)

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
	pubKey := generagePubKeyEd25519(t)

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

// writeTestKnownHosts generates the test known_hosts file and returns the
// file path to it. The generated file contains several hosts with a mix of
// key types; each known host has between 1 and 3 different known host keys.
// If generating or writing the file fails, the test fails.
func writeTestKnownHosts(t *testing.T) string {
	t.Helper()
	hosts := map[string][]ssh.PublicKey{
		"only-rsa.example.test:22":     {generatePubKeyRSA(t)},
		"only-ecdsa.example.test:22":   {generatePubKeyECDSA(t)},
		"only-ed25519.example.test:22": {generagePubKeyEd25519(t)},
		"multi.example.test:2233":      {generatePubKeyRSA(t), generatePubKeyECDSA(t), generagePubKeyEd25519(t)},
		"192.168.1.102:2222":           {generatePubKeyECDSA(t), generagePubKeyEd25519(t)},
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

func generagePubKeyEd25519(t *testing.T) ssh.PublicKey {
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
