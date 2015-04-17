package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type tcpState uint8

const (
	_                           = iota
	TCP_STATE_SYN_SENT tcpState = iota
	TCP_STATE_SYN_RECEIVED
	TCP_STATE_ESTABLISHED
	TCP_STATE_FIN_WAIT_1
	TCP_STATE_FIN_WAIT_2
	TCP_STATE_CLOSE_WAIT
	TCP_STATE_CLOSING
	TCP_STATE_LAST_ACK
	TCP_STATE_TIME_WAIT
	TCP_STATE_CLOSED
)

type tcpPacket struct {
	ipLayer   *layers.IPv4
	tcpLayer  *layers.TCP
	connState *tcpConnState
}

func (t *tcpPacket) Serialize() ([]byte, error) {
	t.tcpLayer.SetNetworkLayerForChecksum(t.ipLayer)
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, opts, t.tcpLayer, gopacket.Payload(t.tcpLayer.Payload))
	return buf.Bytes(), err
}

type loadBalancerHost struct {
	ip  net.IP
	mac net.HardwareAddr
}

type loadBalancerPool struct {
	sync.RWMutex
	balancers map[uint8]*loadBalancerHost
}

func (p *loadBalancerPool) set(i uint8, host *loadBalancerHost) {
	p.Lock()
	defer p.Unlock()
	p.balancers[i] = host
}

func (p *loadBalancerPool) get(i uint8) (*loadBalancerHost, bool) {
	p.RLock()
	defer p.Unlock()
	host, ok := p.balancers[i]
	return host, ok
}

type ipPacket struct {
	ethLayer  *layers.Ethernet
	ipLayer   *layers.IPv4
	tcpLayer  *layers.TCP
	connState *tcpConnState
}

func (i *ipPacket) Serialize() ([]byte, error) {
	i.tcpLayer.SetNetworkLayerForChecksum(i.ipLayer)
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, opts, i.ethLayer, i.ipLayer, i.tcpLayer, gopacket.Payload(i.tcpLayer.Payload))
	return buf.Bytes(), err
}

type tcpConnState struct {
	ip         net.IP
	mac        net.HardwareAddr
	port       layers.TCPPort
	randPort   layers.TCPPort
	lbIndex    uint8
	seqOffset  uint32
	payloadBuf []byte
	connState  tcpState
}

type tcpStateTable struct {
	sync.RWMutex
	byPort map[layers.TCPPort]*tcpConnState
	byIP   map[string]*tcpConnState
}

func (st *tcpStateTable) addConnection(ip net.IP, mac net.HardwareAddr, port layers.TCPPort, lbIndex uint8, seqOffset uint32, payload []byte) (*tcpConnState, layers.TCPPort) {
	var randPort layers.TCPPort
	st.Lock()
	defer st.Unlock()

	// generate random port that is not yet in the state table
	for {
		randPort = st.randomPort()
		if _, ok := st.byPort[randPort]; ok == false {
			break
		}
	}

	connState := &tcpConnState{
		ip:         ip,
		port:       port,
		mac:        mac,
		randPort:   randPort,
		lbIndex:    lbIndex,
		seqOffset:  seqOffset,
		payloadBuf: payload,
	}

	st.byPort[randPort] = connState
	st.byIP[fmt.Sprintf("%s:%d", ip.String(), port)] = connState
	return connState, randPort
}

func (st *tcpStateTable) randomPort() layers.TCPPort {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return layers.TCPPort(r.Int31n(65536))
}

func (st *tcpStateTable) getByPort(port layers.TCPPort) (*tcpConnState, bool) {
	st.RLock()
	defer st.RUnlock()
	connState, ok := st.byPort[port]
	return connState, ok
}

func (st *tcpStateTable) getByIP(ip net.IP, port layers.TCPPort) (*tcpConnState, bool) {
	st.RLock()
	defer st.RUnlock()
	connState, ok := st.byIP[fmt.Sprintf("%s:%d", ip.String(), port)]
	return connState, ok
}

func main() {
	frontend := flag.String("frontend", "eth1", "Front-end interface")
	backend := flag.String("backend", "eth2", "Back-end interface")
	balancersStr := flag.String("balancers", "1:192.168.34.30", "Comma separated list of the loadbalancers in the format INDEX:IP")
	port := flag.Int("port", 80, "The port number to forward packages for")
	flag.Parse()

	// setup TCP state table
	stateTable := &tcpStateTable{
		byPort: make(map[layers.TCPPort]*tcpConnState),
		byIP:   make(map[string]*tcpConnState),
	}

	// get interfaces & addresses
	feIface, feAddr := mustGetInterfaceAndAddr(*frontend)
	_, beAddr := mustGetInterfaceAndAddr(*backend)

	// parse the balancers string
	balancers, err := parseBalancers(*balancersStr)
	if err != nil {
		log.Fatalf("Could not parse the balancers flag: %s", err)
	}

	// setup PCAP handle for receiving IP packets from the client.
	// IP level is needed since we need to have access to the DSCP / ToS
	// field.
	pcapHandleInactive, err := pcap.NewInactiveHandle(*frontend)
	if err != nil {
		log.Fatalf("Could not bind to interface %s: %s", *frontend, err)
	}
	defer pcapHandleInactive.CleanUp()
	pcapHandleInactive.SetImmediateMode(true)
	pcapHandle, err := pcapHandleInactive.Activate()
	if err != nil {
		log.Fatalf("Could not activate handle: %s", err)
	}
	defer pcapHandle.Close()
	if err = pcapHandle.SetBPFFilter(fmt.Sprintf("tcp and dst port %d and dst host %s", *port, feAddr.String())); err != nil {
		log.Fatalf("Could not set BPF filter: %s", err)
	}

	// setup TCP connection.
	tcpConn, err := net.ListenPacket("ip4:tcp", feAddr.String())
	if err != nil {
		log.Fatalf("Could not open IPv4:TCP connection: %s", err)
	}
	defer tcpConn.Close()

	log.Printf("Starting proxy from %s -> %s", feAddr, beAddr)

	var tcpBackendChan = make(chan *tcpPacket)
	// var tcpClientChan = make(chan *tcpPacket)
	var ipPacketChan = make(chan *ipPacket)

	go forwardToBackend(tcpConn, tcpBackendChan, feAddr, beAddr)

	go sendIP(pcapHandle, feIface, ipPacketChan)
	go listenTCP(tcpConn, feAddr, beAddr, *port, tcpBackendChan, ipPacketChan, stateTable, balancers)
	listenIP(pcapHandle, tcpBackendChan, stateTable)
}

func mustGetInterfaceAndAddr(name string) (*net.Interface, net.IP) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		log.Fatalf("Could not get interface %s: %s", name, err)
	}

	ifaceAddrs, err := iface.Addrs()
	if err != nil {
		log.Fatalf("Could not get interface addresses for %s: %s", name, err)
	}
	for _, addr := range ifaceAddrs {
		switch v := addr.(type) {
		case *net.IPAddr:
			return iface, v.IP
		case *net.IPNet:
			return iface, v.IP
		}
	}

	log.Fatalf("Interface %s does not have an IP address", name)
	return nil, nil
}

func listenIP(handle *pcap.Handle, tcpBackendChan chan *tcpPacket, stateTable *tcpStateTable) {
	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range ps.Packets() {
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

		if connState, ok := stateTable.getByIP(ipLayer.SrcIP, tcpLayer.SrcPort); ok {
			// this is a known connection
			tcpLayer.Ack = tcpLayer.Ack + connState.seqOffset
			if connState.connState == TCP_STATE_ESTABLISHED {
				// use the random port assigned by the connection state
				tcpLayer.SrcPort = connState.randPort

				// the function responsible for sending the TCP packets will
				// set the correct source and destionation IPs
				tcpBackendChan <- &tcpPacket{
					ipLayer:   ipLayer,
					tcpLayer:  tcpLayer,
					connState: connState,
				}
			} else {
				// TODO handle this case
				log.Println("Received packet, but connection is not established...")
			}

		} else {
			// we don't know about this connection yet, add it to the state
			// table and get the random port number for this connection
			// (so we can look it up later)
			connState, randPort := stateTable.addConnection(ipLayer.SrcIP, ethLayer.SrcMAC, tcpLayer.SrcPort, ipLayer.TOS, tcpLayer.Ack, tcpLayer.Payload)

			// start the TCP handshake with the backend socket
			tcpSYNC := &layers.TCP{
				SrcPort: randPort,
				DstPort: tcpLayer.DstPort,
				Seq:     tcpLayer.Seq - 1, // the handshake will increase it with one
				Ack:     0,
				SYN:     true,
				Window:  64240,
			}
			connState.connState = TCP_STATE_SYN_SENT
			tcpBackendChan <- &tcpPacket{
				ipLayer:   ipLayer,
				tcpLayer:  tcpSYNC,
				connState: connState,
			}
		}
	}
}

func listenTCP(conn net.PacketConn, dstIP, srcIP net.IP, srcPort int, tcpBackendChan chan *tcpPacket, ipPacketChan chan *ipPacket, stateTable *tcpStateTable, balancers map[uint8]net.IP) {
	tcpPort := layers.TCPPort(srcPort)

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

		if !(srcAddr.String() == srcIP.String() && tcpLayer.SrcPort == tcpPort) {
			// this was not a packet that we were waiting for
			continue
		}

		connState, ok := stateTable.getByPort(tcpLayer.DstPort)

		if !ok {
			// send RST
			// (we received a package for a connection that is not known)
			tcpRST := &layers.TCP{
				SrcPort: tcpLayer.DstPort,
				DstPort: tcpLayer.SrcPort,
				Seq:     tcpLayer.Ack,
				Ack:     tcpLayer.Seq + 1,
				ACK:     true,
				RST:     true,
				Window:  64240,
			}
			tcpBackendChan <- &tcpPacket{
				ipLayer:   &layers.IPv4{Protocol: layers.IPProtocolTCP},
				tcpLayer:  tcpRST,
				connState: connState,
			}

		} else if connState.connState == TCP_STATE_SYN_SENT && tcpLayer.SYN && tcpLayer.ACK {
			// send ACK
			// (we sent the SYN and are now receiving the SYN ACK from the server)
			connState.connState = TCP_STATE_ESTABLISHED
			connState.seqOffset = tcpLayer.Seq - connState.seqOffset + 1

			tcpACK := &layers.TCP{
				SrcPort: tcpLayer.DstPort,
				DstPort: tcpLayer.SrcPort,
				Seq:     tcpLayer.Ack,
				Ack:     tcpLayer.Seq + 1,
				ACK:     true,
				Window:  64240,
			}
			tcpBackendChan <- &tcpPacket{
				ipLayer:   &layers.IPv4{Protocol: layers.IPProtocolTCP},
				tcpLayer:  tcpACK,
				connState: connState,
			}

		} else {
			// correct sequence number and set the DstPort to the original
			// client port
			tcpLayer.Seq = tcpLayer.Seq - connState.seqOffset
			tcpLayer.DstPort = connState.port

			ipLayer := &layers.IPv4{
				SrcIP:    balancers[connState.lbIndex].To4(),
				DstIP:    connState.ip.To4(),
				Protocol: layers.IPProtocolTCP,
				Version:  4,
				Id:       23423,
				Flags:    layers.IPv4DontFragment,
				TTL:      64,
			}

			ipPacketChan <- &ipPacket{
				ipLayer:   ipLayer,
				tcpLayer:  tcpLayer,
				connState: connState,
			}
		}
	}
}

func forwardToBackend(conn net.PacketConn, tcpChan chan *tcpPacket, srcIP, dstIP net.IP) {
	for packet := range tcpChan {
		packet.ipLayer.SrcIP = srcIP.To4()
		packet.ipLayer.DstIP = dstIP.To4()

		bytes, err := packet.Serialize()
		if err != nil {
			log.Fatalf("Could not serialize packet: %s", err)
		}

		if _, err = conn.WriteTo(bytes, &net.IPAddr{IP: dstIP.To4()}); err != nil {
			log.Printf("Could not write to TCP (%s:%d -> %s:%d) socket: %s", srcIP, packet.tcpLayer.SrcPort, dstIP, packet.tcpLayer.DstPort, err)
			log.Printf("Seq: %d, Ack: %d, ACK: %v, RST: %v, SYN: %v, FIN: %v", packet.tcpLayer.Seq, packet.tcpLayer.Ack, packet.tcpLayer.ACK, packet.tcpLayer.RST, packet.tcpLayer.SYN, packet.tcpLayer.FIN)
		}
	}
}

func sendIP(handle *pcap.Handle, iface *net.Interface, ipPacketChan chan *ipPacket) {
	for packet := range ipPacketChan {
		packet.ethLayer = &layers.Ethernet{
			DstMAC:       packet.connState.mac,
			SrcMAC:       iface.HardwareAddr,
			EthernetType: layers.EthernetTypeIPv4,
		}
		bytes, err := packet.Serialize()
		if err != nil {
			log.Fatalf("Could not serialize packet: %s", err)
		}
		handle.WritePacketData(bytes)
	}
}

// parseBalancers parses a string in the format "1:192.168.1.10,2:192.168.1.50"
// into a map.
func parseBalancers(s string) (map[uint8]net.IP, error) {
	out := make(map[uint8]net.IP)

	balancers := strings.Split(s, ",")
	for _, balancer := range balancers {
		parts := strings.Split(balancer, ":")
		if len(parts) != 2 {
			return nil, errors.New("Could not parse the balancer index and IP, it should be in the format INDEX:IP")
		}

		i, err := strconv.ParseInt(parts[0], 10, 8)
		if err != nil {
			return nil, err
		}

		out[uint8(i)] = net.ParseIP(parts[1])
	}

	return out, nil
}
