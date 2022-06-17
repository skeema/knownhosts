package knownhosts_test

import (
	"github.com/skeema/knownhosts"
	"golang.org/x/crypto/ssh"
)

func sshConfigForHost(hostWithPort string) (*ssh.ClientConfig, error) {
	kh, err := knownhosts.New("/home/myuser/.ssh/known_hosts")
	if err != nil {
		return nil, err
	}
	config := &ssh.ClientConfig{
		User:              "myuser",
		Auth:              []ssh.AuthMethod{ /* ... */ },
		HostKeyCallback:   kh.HostKeyCallback(), // or, equivalently, use ssh.HostKeyCallback(kh)
		HostKeyAlgorithms: kh.HostKeyAlgorithms(hostWithPort),
	}
	return config, nil
}
