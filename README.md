# DNS-SD

[![Build Status](https://travis-ci.org/brutella/hc.svg)](https://travis-ci.org/brutella/dnssd)

This library implements [Multicast DNS][mdns] and [DNS-Based Service Discovery][dnssd] to provide zero-configuration operations. It lets you announce and find services in a specific link-local domain.

[mdns]: https://tools.ietf.org/html/rfc6762
[dnssd]: https://tools.ietf.org/html/rfc6763

## Usage

#### Create a mDNS responder

The following code creates a service with name "My Website._http._tcp.local." for the host "My Computer" which has all IPs from network interface "eth0". The service is added to a responder.

```go
import (
	"context"
	"github.com/brutella/dnssd"
)

cfg := dnssd.Config{
    Name:   "My Website",
    Type:   "_http._tcp",
    Domain: "local",
    Host:   "My Computer",
    Ifaces: []string{"eth0"},,
    Port:   12345,
}
sv, _ := dnssd.NewService(cfg)
```

In most cases you only need to specify the name, type and port of the service.

```go
cfg := dnssd.Config{
    Name:   "My Website",
    Type:   "_http._tcp",
    Port:   12345,
}
sv, _ := dnssd.NewService(cfg)
```

Then you create a responder and add the service to it.
```go
rp, _ := dnssd.NewResponder()
hdl, _ := rp.Add(sv)

ctx, cancel := context.WithCancel(context.Background())
defer cancel()

rp.Respond(ctx)
```

When calling `Respond` the responder probes for the service instance name and host name to be unqiue in the network. 
Once probing is finished, the service will be announced.

#### Update TXT records

Once a service is added to a responder, you can use the `hdl` to update properties.

```go
hdl.UpdateText(map[string]string{"key1": "value1", "key2": "value2"}, rsp)
```

## `dnssd` command

The command line tool in `cmd/dnssd` lets you browse, register and resolve services similar to [dns-sd](https://www.unix.com/man-page/osx/1/dns-sd/).

### Install
You can install the tool with

`go install github.com/brutella/dnssd/cmd/dnssd`

### Usage

**Registering a service on your local machine**

Lets register a printer service (`_printer._tcp`) running on your local computer at port 515 with the name "Private Printer".

```sh
dnssd register -Name="Private Printer" -Type="_printer._tcp" -Port=515
```

**Registering a proxy service**

If the service is running on a different machine on your local network, you have to specify the hostname and IP.
Lets say the printer service is running on the printer with the hostname `ABCD` and IPv4 address `192.168.1.53`, you can register a proxy which announce that service on your network.

```sh
dnssd register -Name="Private Printer" -Type="_printer._tcp" -Port=515 -IP=192.168.1.53 -Host=ABCD
```

Use option `-Interface`, if you want to announce the service only on a specific network interface.
This might be necessary if your local machine is connected to multiple subnets and your announced service is only available on a specific subnet.

```sh
dnssd register -Name="Private Printer" -Type="_printer._tcp" -Port=515 -IP=192.168.1.53 -Host=ABCD -Interface=en0
```

**Browsing for a service**

If you want to browse for a service type, you can use the `browse` command.

```sh
dnssd browse -Type="_printer._tcp"
```

**Resolving a service instance**

If you know the name of a service instance, you can resolve its hostname with the `resolve` command.

```sh
dnssd resolve -Name="Private Printer" -Type="_printer._tcp"
```

## Conformance

This library passes the [multicast DNS tests](https://github.com/brutella/dnssd/blob/36a2d8c541aab14895fc5492d5ad8ec447a67c47/_cmd/bct/ConformanceTestResults) of Apple's Bonjour Conformance Test.

## TODO

- [ ] Support hot plugging
- [ ] Support negative responses (RFC6762 6.1)
- [ ] Handle txt records case insensitive
- [ ] Remove outdated services from cache regularly
- [ ] Make sure that hostnames are FQDNs

# Contact

Matthias Hochgatterer

Github: [https://github.com/brutella](https://github.com/brutella/)

Twitter: [https://twitter.com/brutella](https://twitter.com/brutella)


# License

*dnssd* is available under the MIT license. See the LICENSE file for more info.


### Windows LAN discovery and legacy unicast

On Windows, the existing browse APIs and `LookupInstance` also query from
independent ephemeral UDP ports. This avoids depending on which process owns
unicast replies to shared port 5353. Multicast listening and announcements are
retained. Other platforms keep multicast-only browsing by default.

Use explicit options to enable or disable the extra query path per browser:

```go
err := dnssd.LookupTypeWithOptions(ctx, "_scm._tcp.local.", onAdd, onRemove,
    dnssd.BrowseOptions{
        Continuous: true,
        LegacyUnicast: true,
        // Interfaces: []string{"eth0"},
    })
```

The zero value of `BrowseOptions` does not enable legacy queries, even on
Windows. Sockets bind to a local address on each selected interface and share
the normal browse cache. Legacy replies must match a pending transaction and
question, come from port 5353 on the local link, and are cached for at most
10 seconds. Continuous browsing refreshes these short-lived records. Interface
changes reset continuous-query backoff; stale bound sockets close on the next
query. Cancelling the browse closes its sockets and stops its forwarding workers.

This is still multicast-assisted discovery: outbound multicast queries must
reach the peer. It does not replace global discovery when multicast is blocked
in both directions. Cache removal is a discovery event, not proof that an
established application connection has failed.

Run unit tests with `go test -race ./...`. On a host permitting LAN multicast,
set `DNSSD_TEST_MULTICAST=1` to also run real-socket tests, including discovery
with the multicast receive path deliberately silent and dual-path deduplication.

### Continuous integration

GitHub Actions runs dependency verification, build, vet, and race-enabled tests
on every pull request and push to master. The matrix covers Linux, Windows, and
macOS with stable Go, plus Linux with the minimum supported Go 1.20. Module
files must remain unchanged. The aggregate check is named `CI` and can be
selected as a required status check in branch protection.

Real multicast integration tests remain opt-in with `DNSSD_TEST_MULTICAST=1`
on a controlled LAN; hosted CI runs deterministic tests and loopback socket
tests without requiring multicast connectivity.
