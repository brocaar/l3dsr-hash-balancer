package balancer

import (
	"fmt"
	"net"
)

// GetInterfaceAndAddrByName returns the net.IP for a given interface name.
func GetAddrByName(name string) (net.IP, error) {
	var ip net.IP

	iface, err := net.InterfaceByName(name)
	if err != nil {
		return ip, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return ip, err
	}

	for _, addr := range addrs {
		switch v := addr.(type) {
		case *net.IPAddr:
			return v.IP, nil
		case *net.IPNet:
			return v.IP, nil
		}
	}

	return ip, fmt.Errorf("Interface %s does not have an IP address", name)
}
