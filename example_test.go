package knownhosts_test

import (
	"log"

	"github.com/skeema/knownhosts"
	"golang.org/x/crypto/ssh"
)

func ExampleNew() {
	sshHost := "yourserver.com:22"
	kh, err := knownhosts.New("/home/myuser/.ssh/known_hosts")
	if err != nil {
		log.Fatal("Failed to read known_hosts: ", err)
	}
	config := &ssh.ClientConfig{
		User:              "myuser",
		Auth:              []ssh.AuthMethod{ /* ... */ },
		HostKeyCallback:   kh.HostKeyCallback(), // or, equivalently, use ssh.HostKeyCallback(kh)
		HostKeyAlgorithms: kh.HostKeyAlgorithms(sshHost),
	}
	client, err := ssh.Dial("tcp", sshHost, config)
	if err != nil {
		log.Fatal("Failed to dial: ", err)
	}
	defer client.Close()
}
