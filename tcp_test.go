package balancer

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestPacket(t *testing.T) {
	ipLayer := &layers.IPv4{
		SrcIP: net.ParseIP("127.0.0.1").To4(),
		DstIP: net.ParseIP("127.0.0.2").To4(),
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(8080),
		DstPort: layers.TCPPort(80),
	}

	tcpPacket := NewTCPPacket(ipLayer, tcpLayer)
	tcpBytes, err := tcpPacket.MarshalBinary()
	if err != nil {
		t.Fatalf("Could not serialize TCP packet: %s", err)
	}

	packet := gopacket.NewPacket(tcpBytes, layers.LayerTypeTCP, gopacket.Default)
	if tcpPacketLayer := packet.Layer(layers.LayerTypeTCP); tcpPacketLayer != nil {
		tcp, _ := tcpPacketLayer.(*layers.TCP)
		if tcp.SrcPort != layers.TCPPort(8080) || tcp.DstPort != layers.TCPPort(80) {
			t.Fatalf("Was expecting SrcPort 8080 and DstPort 80, got %d and %d", tcp.SrcPort, tcp.DstPort)
		}
	} else {
		t.Fatal("Could not get the TCP layer.")
	}
}
