package balancer

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// EthPacket represents an ethernet packet.
type EthPacket struct {
	eth *layers.Ethernet
	ip  *layers.IPv4
	tcp *layers.TCP
}

// NewEthPacket creates and initializes a new EthPacket.
func NewEthPacket(eth *layers.Ethernet, ip *layers.IPv4, tcp *layers.TCP) EthPacket {
	return EthPacket{
		eth: eth,
		ip:  ip,
		tcp: tcp,
	}
}

// MarshalBinary returns the binary representation of the packet.
func (p EthPacket) MarshalBinary() ([]byte, error) {
	p.tcp.SetNetworkLayerForChecksum(p.ip)
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, opts, p.eth, p.ip, p.tcp, gopacket.Payload(p.tcp.Payload))
	return buf.Bytes(), err
}
