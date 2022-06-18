package knownhosts_test

import (
	"fmt"
	"log"
	"net"
	"os"

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

func ExampleWriteKnownHost() {
	sshHost := "yourserver.com:22"
	khPath := "/home/myuser/.ssh/known_hosts"
	kh, err := knownhosts.New(khPath)
	if err != nil {
		log.Fatal("Failed to read known_hosts: ", err)
	}

	// Create a custom permissive hostkey callback which still errors on hosts
	// with changed keys, but allows unknown hosts and adds them to known_hosts
	cb := ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := kh(hostname, remote, key)
		if knownhosts.IsHostKeyChanged(err) {
			return fmt.Errorf("REMOTE HOST IDENTIFICATION HAS CHANGED for host %s! This may indicate a MitM attack.", hostname)
		} else if knownhosts.IsHostUnknown(err) {
			f, ferr := os.OpenFile(khPath, os.O_APPEND|os.O_WRONLY, 0600)
			if ferr == nil {
				defer f.Close()
				ferr = knownhosts.WriteKnownHost(f, hostname, remote, key)
			}
			if ferr == nil {
				log.Printf("Added host %s to known_hosts\n", hostname)
			} else {
				log.Printf("Failed to add host %s to known_hosts: %v\n", hostname, ferr)
			}
			return nil // permit previously-unknown hosts (warning: may be insecure)
		}
		return err
	})

	config := &ssh.ClientConfig{
		User:              "myuser",
		Auth:              []ssh.AuthMethod{ /* ... */ },
		HostKeyCallback:   cb,
		HostKeyAlgorithms: kh.HostKeyAlgorithms(sshHost),
	}
	client, err := ssh.Dial("tcp", sshHost, config)
	if err != nil {
		log.Fatal("Failed to dial: ", err)
	}
	defer client.Close()

}
