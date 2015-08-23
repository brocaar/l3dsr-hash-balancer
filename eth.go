package balancer

import (
	"fmt"

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
func NewEthPacket(eth *layers.Ethernet, ip *layers.IPv4, tcp *layers.TCP) *EthPacket {
	return &EthPacket{
		eth: eth,
		ip:  ip,
		tcp: tcp,
	}
}

// SetTOS sets the IP TOS field.
func (p *EthPacket) SetTOS(tos uint8) {
	p.ip.TOS = tos
}

// MarshalBinary returns the binary representation of the packet.
func (p *EthPacket) MarshalBinary() ([]byte, error) {
	p.tcp.SetNetworkLayerForChecksum(p.ip)
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, opts, p.eth, p.ip, p.tcp, gopacket.Payload(p.tcp.Payload))
	return buf.Bytes(), err
}

func (p *EthPacket) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d [ACK: %t, SYN: %t, RST: %t] [Seq: %d, Ack: %d]", p.ip.SrcIP, p.tcp.SrcPort, p.ip.DstIP, p.tcp.DstPort, p.tcp.ACK, p.tcp.SYN, p.tcp.RST, p.tcp.Seq, p.tcp.Ack)
}
