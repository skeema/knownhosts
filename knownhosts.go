// Package knownhosts is a thin wrapper around golang.org/x/crypto/ssh/knownhosts,
// adding the ability to obtain the list of host key algorithms for a known host.
package knownhosts

import (
	"errors"
	"net"

	"golang.org/x/crypto/ssh"
	xknownhosts "golang.org/x/crypto/ssh/knownhosts"
)

// HostKeyCallback wraps ssh.HostKeyCallback with an additional method to
// perform host key algorithm lookups from the known_hosts entries.
type HostKeyCallback ssh.HostKeyCallback

// New creates a host key callback from the given OpenSSH host key files. The
// returned value may be used in ssh.ClientConfig.HostKeyCallback by casting it
// to ssh.HostKeyCallback, or using its HostKeyCallback method. Otherwise, it
// operates the same as the New function in golang.org/x/crypto/ssh/knownhosts.
func New(files ...string) (HostKeyCallback, error) {
	cb, err := xknownhosts.New(files...)
	return HostKeyCallback(cb), err
}

// HostKeyCallback simply casts the receiver back to ssh.HostKeyCallback, for
// use in ssh.ClientConfig.HostKeyCallback.
func (hkcb HostKeyCallback) HostKeyCallback() ssh.HostKeyCallback {
	return ssh.HostKeyCallback(hkcb)
}

// HostKeyAlgorithms returns a slice of host key algorithms for the supplied
// host:port found in the known_hosts file(s), or an empty slice if the host
// is not already known.
// The result may be used in ssh.ClientConfig.HostKeyAlgorithms, either as-is
// or after filtering (if you wish to prefer or ignore particular algorithms).
// For hosts with multiple known_hosts entries, note that the order of this
// function's result does not match the order of lines in the known_hosts files.
func (hkcb HostKeyCallback) HostKeyAlgorithms(hostWithPort string) (algos []string) {
	var keyErr *xknownhosts.KeyError
	placeholderAddr := &net.TCPAddr{IP: []byte{0, 0, 0, 0}}
	placeholderPubKey := &fakePublicKey{}
	if hkcbErr := hkcb(hostWithPort, placeholderAddr, placeholderPubKey); errors.As(hkcbErr, &keyErr) {
		for _, knownKey := range keyErr.Want {
			algos = append(algos, knownKey.Key.Type())
		}
	}
	return algos
}

// HostKeyAlgorithms is a convenience function for performing host key algorithm
// lookups on an ssh.HostKeyCallback directly. It is intended for use in code
// paths that stay with the New method of golang.org/x/crypto/ssh/knownhosts
// rather than this package's New method.
func HostKeyAlgorithms(cb ssh.HostKeyCallback, hostWithPort string) []string {
	return HostKeyCallback(cb).HostKeyAlgorithms(hostWithPort)
}

// fakePublicKey is used as part of the work-around for
// https://github.com/golang/go/issues/29286
type fakePublicKey struct{}

func (fakePublicKey) Type() string {
	return "fake-public-key"
}
func (fakePublicKey) Marshal() []byte {
	return []byte("fake public key")
}
func (fakePublicKey) Verify(_ []byte, _ *ssh.Signature) error {
	return errors.New("Verify called on placeholder key")
}
