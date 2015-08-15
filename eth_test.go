package balancer

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestEthPacket(t *testing.T) {
	srcMAC, _ := net.ParseMAC("11:11:11:11:11:11")
	dstMAC, _ := net.ParseMAC("22:22:22:22:22:22")

	ethLayer := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := &layers.IPv4{
		SrcIP:    net.ParseIP("127.0.0.1").To4(),
		DstIP:    net.ParseIP("127.0.0.2").To4(),
		Protocol: layers.IPProtocolTCP,
	}

	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(8080),
		DstPort: layers.TCPPort(80),
	}

	ethPacket := NewEthPacket(ethLayer, ipLayer, tcpLayer)
	ethBytes, err := ethPacket.MarshalBinary()
	if err != nil {
		t.Fatal(err.Error())
	}

	// back from bytes to packet
	packet := gopacket.NewPacket(ethBytes, layers.LayerTypeEthernet, gopacket.Default)

	// test ethernet layer
	if ethPacketLayer := packet.Layer(layers.LayerTypeEthernet); ethPacketLayer != nil {
		eth, _ := ethPacketLayer.(*layers.Ethernet)
		if eth.SrcMAC.String() != srcMAC.String() || eth.DstMAC.String() != dstMAC.String() {
			t.Fatalf("Was expecting src MAC: %s, got: %s. Was expecting dst MAC: %s, got: %s", srcMAC, eth.SrcMAC, dstMAC, eth.DstMAC)
		}
	} else {
		t.Fatal("Could not get the Ethernet layer.")
	}

	// test ip layer
	if ipPacketLayer := packet.Layer(layers.LayerTypeIPv4); ipPacketLayer != nil {
		ip, _ := ipPacketLayer.(*layers.IPv4)
		if ip.SrcIP.String() != net.ParseIP("127.0.0.1").String() || ip.DstIP.String() != net.ParseIP("127.0.0.2").String() {
			t.Fatalf("Was expecting src IP: 127.0.0.1, got: %s. Was expecting dst IP: 127.0.0.2, got: %s", ip.SrcIP, ip.DstIP)
		}
	} else {
		t.Fatal("Could not get the IPv4 layer.")
	}

	// test the tcp layer
	if tcpPacketLayer := packet.Layer(layers.LayerTypeTCP); tcpPacketLayer != nil {
		tcp, _ := tcpPacketLayer.(*layers.TCP)
		if tcp.SrcPort != layers.TCPPort(8080) || tcp.DstPort != layers.TCPPort(80) {
			t.Fatalf("Was expecting SrcPort 8080 and DstPort 80, got %d and %d", tcp.SrcPort, tcp.DstPort)
		}
	} else {
		t.Fatal("Could not get the TCP layer.")
	}
}
