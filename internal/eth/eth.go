package eth

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Packet is a struct holding all the information needed to create an Ethernet
// (level-2) packet.
type Packet struct {
	ethLayer *layers.Ethernet
	ipLayer  *layers.IPv4
	tcpLayer *layers.TCP
}

// NewPacket creates a new instance of Packet for the given Ethernet, IP
// and TCP layers.
func NewPacket(eth *layers.Ethernet, ip *layers.IPv4, tcp *layers.TCP) *Packet {
	return &Packet{
		ethLayer: eth,
		ipLayer:  ip,
		tcpLayer: tcp,
	}
}

// Serialize returns the Ethernet packet as a slice of bytes.
func (p *Packet) Serialize() ([]byte, error) {
	p.tcpLayer.SetNetworkLayerForChecksum(p.ipLayer)
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, opts, p.ethLayer, p.ipLayer, p.tcpLayer, gopacket.Payload(p.tcpLayer.Payload))
	return buf.Bytes(), err
}
