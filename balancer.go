package balancer

import (
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// BalancePacket implements the actual load-balance logic on packet level.
func BalancePackets(packetsIn chan gopacket.Packet, packetsOut chan *EthPacket, stateTable *StateTable, pool PoolBalancer) {
	for packet := range packetsIn {
		// get layers
		layer := packet.Layer(layers.LayerTypeEthernet)
		if layer == nil {
			log.Println("Could not get Ethernet layer")
			continue
		}
		ethLayer, ok := layer.(*layers.Ethernet)
		if !ok {
			log.Println("Could not cast layer to Ethernet")
			continue
		}
		layer = packet.Layer(layers.LayerTypeIPv4)
		if layer == nil {
			log.Println("Could not get IPv4 layer")
			continue
		}
		ipLayer, ok := layer.(*layers.IPv4)
		if !ok {
			log.Println("Could not cast layer to IPv4")
			continue
		}
		layer = packet.Layer(layers.LayerTypeTCP)
		if layer == nil {
			log.Println("Could not get TCP layer")
			continue
		}
		tcpLayer, ok := layer.(*layers.TCP)
		if !ok {
			log.Println("Could not cast layer to TCP")
			continue
		}

		if state, ok := stateTable.GetState(ipLayer.SrcIP, tcpLayer.SrcPort); ok {
			// this is a known state
			if state.State == TCP_STATE_SYN_RECEIVED && tcpLayer.ACK {
				// complete the handshake
				state.State = TCP_STATE_ESTABLISHED
				log.Printf("Handshake completed with %s:%d", ipLayer.SrcIP, tcpLayer.SrcPort)
			} else if state.State == TCP_STATE_ESTABLISHED && state.Server == nil && tcpLayer.ACK && tcpLayer.PSH {
				// we received the first data, set the backend server for the
				// connection state, so we know to which server we need to
				// forward the data
				// NOTE: for simplicity we assume the HTTP request is within
				// one packet, this might not be the case!

				// logic to parse the request, we don't care for now since
				// we're using a single server balancer
				// payloadReader := bufio.NewReader(bytes.NewReader(tcpLayer.Payload))
				// req, err := http.ReadRequest(payloadReader)
				// if err != nil {
				// 	log.Printf("Could not parse request: %s", err)
				// 	continue
				// }
				server, err := pool.RouteToServer(1)
				if err != nil {
					log.Printf("Could not route packet to server: %s", err)
					// we should reset the connection here?
					continue
				}
				state.Server = server
				log.Printf("Using server %s for client %s:%d", state.Server.IP, ipLayer.SrcIP, tcpLayer.SrcPort)
			}

			if state.State == TCP_STATE_ESTABLISHED && state.Server != nil {
				log.Printf("Forwarding packet %s:%d -> %s:%d to: %s", ipLayer.SrcIP, tcpLayer.SrcPort, ipLayer.DstIP, tcpLayer.DstPort, state.Server.IP)
				ethLayer.DstMAC = state.Server.HardwareAddr
				ipLayer.DstIP = state.Server.IP
				ipLayer.TTL = 64

				packetsOut <- NewEthPacket(ethLayer, ipLayer, tcpLayer)
			}
		} else {
			// this is a new connection
			if tcpLayer.SYN {
				log.Printf("New connection from: %s:%d", ipLayer.SrcIP, tcpLayer.SrcPort)

				// this is a new TCP handshake, respond
				state := stateTable.NewState(ipLayer.SrcIP, tcpLayer.SrcPort)
				tcpSYNCACK := &layers.TCP{
					SrcPort: tcpLayer.DstPort,
					DstPort: tcpLayer.SrcPort,
					Seq:     state.Seq,
					Ack:     tcpLayer.Seq + 1,
					SYN:     true,
					ACK:     true,
					Window:  64240,
				}
				state.State = TCP_STATE_SYN_RECEIVED

				// reverse eth and ip packet destination
				ethLayer.SrcMAC, ethLayer.DstMAC = ethLayer.DstMAC, ethLayer.SrcMAC
				ipLayer.SrcIP, ipLayer.DstIP = ipLayer.DstIP, ipLayer.SrcIP
				// set TTL to 64
				ipLayer.TTL = 64

				packetsOut <- NewEthPacket(ethLayer, ipLayer, tcpSYNCACK)
			} else {
				// this is not a new TCP handshake and the connection is unknown
				log.Println("We should send a RST at this point!")
			}
		}
	}
}
