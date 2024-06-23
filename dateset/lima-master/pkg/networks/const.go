package networks

const (
	SlirpNICName = "eth0"
	// CIDR is intentionally hardcoded to 192.168.5.0/24, as each of QEMU has its own independent slirp network.
	SlirpNetwork   = "192.168.5.0/24"
	SlirpGateway   = "192.168.5.2"
	SlirpIPAddress = "192.168.5.15"
)
