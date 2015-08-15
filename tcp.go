package balancer

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TCPPacket represents a TCP packet.
type TCPPacket struct {
	ip  *layers.IPv4
	tcp *layers.TCP
}

// NewTCPPacket creates and initializes a new TCP packet.
// The IP layer is needed to calculate the correct TCP checksum.
func NewTCPPacket(ip *layers.IPv4, tcp *layers.TCP) TCPPacket {
	return TCPPacket{
		ip:  ip,
		tcp: tcp,
	}
}

// MarshalBinary returns the binary representation of the packet.
func (p TCPPacket) MarshalBinary() ([]byte, error) {
	p.tcp.SetNetworkLayerForChecksum(p.ip)
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, opts, p.tcp, gopacket.Payload(p.tcp.Payload))
	return buf.Bytes(), err
}
