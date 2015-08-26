package balancer

import (
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// HandleBalancerPackets handles the incoming packets from the balancer
// app. When the connection is known, it will forward it to the backend.
// If not, it will first start a TCP handshake with the backend.
func HandleBalancerPackets(packetsIn chan gopacket.Packet, backendPackets chan *TCPPacket, stateTable *PacketBridgeStateTable) {
	for p := range packetsIn {
		// get layers
		layer := p.Layer(layers.LayerTypeEthernet)
		if layer == nil {
			log.Println("Could not get Ethernet layer")
			continue
		}
		ethLayer, ok := layer.(*layers.Ethernet)
		if !ok {
			log.Println("Could not cast layer to Ethernet")
			continue
		}

		layer = p.Layer(layers.LayerTypeIPv4)
		if layer == nil {
			log.Println("Could not get IPv4 layer")
			continue
		}
		ipLayer, ok := layer.(*layers.IPv4)
		if !ok {
			log.Println("Could not cast layer to IPv4")
			continue
		}

		layer = p.Layer(layers.LayerTypeTCP)
		if layer == nil {
			log.Println("Could not get TCP layer")
			continue
		}
		tcpLayer, ok := layer.(*layers.TCP)
		if !ok {
			log.Println("Could not cast layer to TCP")
			continue
		}

		if connState, ok := stateTable.GetByIP(ipLayer.SrcIP, tcpLayer.SrcPort); ok {
			// this is a known connection
			if connState.State == TCP_STATE_ESTABLISHED {
				// migrate the TCP state to packetbridge <> backend handshake
				tcpLayer.Ack = tcpLayer.Ack + connState.SeqOffset
				tcpLayer.SrcPort = connState.RandPort

				// the function responsible for sending the TCP packets will
				// set the correct source and destination IPs
				backendPackets <- NewTCPPacket(ipLayer, tcpLayer)
			} else {
				// TODO handle this case properly
				log.Println("Received packet, but connection is not established...")
			}
		} else {
			// we don't know about this connection yet, add it to the state
			// table and get the random port number for this connection
			// (so we can look it up later)
			connState := stateTable.NewState(ipLayer.SrcIP, ethLayer.SrcMAC, tcpLayer.SrcPort, ipLayer.TOS, tcpLayer.Ack, tcpLayer.Payload)

			// start the TCP handshake with the backend
			tcpSYN := &layers.TCP{
				SrcPort: connState.RandPort,
				DstPort: tcpLayer.DstPort,
				Seq:     tcpLayer.Seq - 1, // the handshake will increase it with +1
				Ack:     0,
				SYN:     true,
				Window:  64240,
			}

			log.Printf("New TCP connection: %s:%d, sending SYN to backend", ipLayer.SrcIP, tcpLayer.SrcPort)

			connState.State = TCP_STATE_SYN_SENT
			backendPackets <- NewTCPPacket(ipLayer, tcpSYN)
		}
	}
}

// SendToBackend sends packets from the packetbridge to the backend.
func SendToBackend(conn net.PacketConn, backendPackets chan *TCPPacket, srcIP, dstIP net.IP) {
	for p := range backendPackets {
		p.SetDstIP(dstIP)
		p.SetSrcIP(srcIP)

		bytes, err := p.MarshalBinary()
		if err != nil {
			log.Fatalf("Could not serialize packet: %s", err)
		}

		log.Printf("Sending packet to backend: %s", p)

		if _, err = conn.WriteTo(bytes, &net.IPAddr{IP: dstIP.To4()}); err != nil {
			log.Printf("Could not write TCP packet: %s", err)
		}
	}
}

// SendToClient sends packets to the client who started the request at
// the balancer.
func SendToClient(handle *pcap.Handle, ethPackets chan *EthPacket) {
	for p := range ethPackets {
		p.SetTOS(1)
		log.Printf("Sending eth packet: %s", p)
		bytes, err := p.MarshalBinary()
		if err != nil {
			log.Fatalf("Could not serialize packet: %s", err)
		}
		handle.WritePacketData(bytes)
	}
}

// HandleBackendPackets handles incoming packets from the backend. If the
// connection is known, it will forward these packets to the client.
func HandleBackendPackets(conn net.PacketConn, dstIP, srcIP net.IP, srcPort layers.TCPPort, pbIface *net.Interface, backendTCPPackets chan *TCPPacket, ethPackets chan *EthPacket, stateTable *PacketBridgeStateTable, balancers map[uint8]net.IP) {
	b := make([]byte, 1500)
	for {
		n, srcAddr, err := conn.ReadFrom(b)
		if err != nil {
			log.Printf("Could not read from TCP connection: %s", err)
			continue
		}

		packet := gopacket.NewPacket(b[:n], layers.LayerTypeTCP, gopacket.Default)
		layer := packet.Layer(layers.LayerTypeTCP)
		if layer == nil {
			log.Println("Could not get TCP layer")
			continue
		}
		tcpLayer, ok := layer.(*layers.TCP)
		if !ok {
			log.Println("Could not cast to TCP layer")
			continue
		}

		if !(srcAddr.String() == srcIP.String() && tcpLayer.SrcPort == srcPort) {
			// this was not the packet that we were waiting for, ignore
			continue
		}

		connState, ok := stateTable.GetByPort(tcpLayer.DstPort)
		if !ok {
			// set RST
			// (we received a packet for a connection that is not known)
			tcpRST := &layers.TCP{
				SrcPort: tcpLayer.DstPort,
				DstPort: tcpLayer.SrcPort,
				Seq:     tcpLayer.Ack,
				Ack:     tcpLayer.Seq + 1,
				ACK:     true,
				RST:     true,
				Window:  64240,
			}
			ipLayer := &layers.IPv4{
				Protocol: layers.IPProtocolTCP,
			}
			log.Printf("Packet received for unknown connection from backend (port: %d). Sending RST to backend.", tcpLayer.DstPort)
			backendTCPPackets <- NewTCPPacket(ipLayer, tcpRST)
		} else if connState.State == TCP_STATE_SYN_SENT && tcpLayer.SYN && tcpLayer.ACK {
			// send ACK
			// (we sent the SYN and are now receiving the SYN ACK from the backend)
			connState.State = TCP_STATE_ESTABLISHED
			connState.SeqOffset = tcpLayer.Seq - connState.SeqOffset + 1

			tcpACK := &layers.TCP{
				SrcPort: tcpLayer.DstPort,
				DstPort: tcpLayer.SrcPort,
				Seq:     tcpLayer.Ack,
				Ack:     tcpLayer.Seq + 1,
				ACK:     true,
				Window:  64240,
			}
			ipLayer := &layers.IPv4{
				Protocol: layers.IPProtocolTCP,
			}

			log.Println("Received SYN ACK from backend, sending ACK.")
			backendTCPPackets <- NewTCPPacket(ipLayer, tcpACK)
		} else {
			// correct sequence number and set the RstPort to the original
			// client port. we're now sending the packet back to the user
			tcpLayer.Seq = tcpLayer.Seq - connState.SeqOffset
			tcpLayer.DstPort = connState.Port

			ethLayer := &layers.Ethernet{
				SrcMAC:       pbIface.HardwareAddr,
				DstMAC:       connState.HardwareAddr,
				EthernetType: layers.EthernetTypeIPv4,
			}

			ipLayer := &layers.IPv4{
				SrcIP:    balancers[connState.LBIndex].To4(),
				DstIP:    connState.IP.To4(),
				Protocol: layers.IPProtocolTCP,
				Version:  4,
				Id:       23423, // todo make this random?
				Flags:    layers.IPv4DontFragment,
				TTL:      64,
			}

			log.Println("Sending packet from the backend to the user")
			ethPackets <- NewEthPacket(ethLayer, ipLayer, tcpLayer)
		}
	}
}
