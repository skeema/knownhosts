# Go known_hosts host key algorithm lookup

[![build status](https://img.shields.io/github/workflow/status/skeema/knownhosts/Tests/main)](https://github.com/skeema/knownhosts/actions)
[![godoc](https://img.shields.io/badge/godoc-reference-blue.svg)](https://pkg.go.dev/github.com/skeema/knownhosts)


> This repo is brought to you by [Skeema](https://github.com/skeema/skeema), a
> declarative pure-SQL schema management system for MySQL and MariaDB. Our
> Premium edition products include extensive [SSH tunnel](https://www.skeema.io/docs/options/#ssh)
> functionality, which internally makes use of this technique for known_hosts
> interactions.

Go provides excellent functionality for OpenSSH known_hosts files in its
external package [golang.org/x/crypto/ssh/knownhosts](https://pkg.go.dev/golang.org/x/crypto/ssh/knownhosts). 
However, that package has a [painful omission](https://github.com/golang/go/issues/29286):
it does not expose a straightforward way to look up known_hosts entries, and
this is often problematic for hosts that have multiple host keys of different
types. If the host's first public key is *not* in known_hosts, but a key of a
different type *is*, the HostKeyCallback returns an error. The caller must
populate `ssh.ClientConfig.HostKeyAlgorithms` to prevent this, but 
[golang.org/x/crypto/ssh/knownhosts](https://pkg.go.dev/golang.org/x/crypto/ssh/knownhosts)
does not provide an obvious way to do this.

This package provides a solution to this problem. It is a thin wrapper around [golang.org/x/crypto/ssh/knownhosts](https://pkg.go.dev/golang.org/x/crypto/ssh/knownhosts),
using a subtle trick to look up the list of host key algorithms for a given
host. It may be used like so, instead of using [golang.org/x/crypto/ssh/knownhosts](https://pkg.go.dev/golang.org/x/crypto/ssh/knownhosts)
directly:

```golang
import (
	"golang.org/x/crypto/ssh"
	"github.com/skeema/knownhosts"
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
```

## How it works

It turns out you *can* use the callback from [golang.org/x/crypto/ssh/knownhosts](https://pkg.go.dev/golang.org/x/crypto/ssh/knownhosts)
to perform lookups for a host. It just requires a hack: invoke the callback
on the hostname in question, while also supplying a bogus key that won't match
anything in known_hosts. You can then iterate over the resulting KeyError.Want
to see which keys *are* actually present for that host. That's what this
package's `HostKeyAlgorithms` function does.
