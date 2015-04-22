package tcp

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Packet is a struct holding all the information needed to create a TCP
// packet.
type Packet struct {
	ipLayer  *layers.IPv4
	tcpLayer *layers.TCP
}

// NewPacket creates a new instance of Packet for the given IP and TCP layers.
// Note that the IP layer is needed to calculate the correct TCP checksum.
func NewPacket(ip *layers.IPv4, tcp *layers.TCP) *Packet {
	return &Packet{
		ipLayer:  ip,
		tcpLayer: tcp,
	}
}

// Serialize returns the TCP packet as a slice of bytes.
func (p *Packet) Serialize() ([]byte, error) {
	p.tcpLayer.SetNetworkLayerForChecksum(p.ipLayer)
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, opts, p.tcpLayer, gopacket.Payload(p.tcpLayer.Payload))
	return buf.Bytes(), err
}
