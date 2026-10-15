module github.com/otfabric/go-modbus-trace/spike/l0

go 1.26.0

// Spike only. The versions of gopacket's own dependencies are the newest ones
// already in the local module cache (offline rule); each is at or above what
// gopacket v1.7.4 requires, so MVS would select them anyway.
require (
	github.com/gopacket/gopacket v1.7.4
	github.com/vishvananda/netlink v1.3.1 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
)

require github.com/otfabric/go-modbus-capture v0.0.2
