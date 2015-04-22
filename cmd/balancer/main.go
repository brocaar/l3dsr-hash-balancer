package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
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

type ipPacket struct {
	ethLayer *layers.Ethernet
	ipLayer  *layers.IPv4
	tcpLayer *layers.TCP
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

type backendServer struct {
	ip  net.IP
	mac net.HardwareAddr
}

type backendPool struct {
	sync.RWMutex
	servers []*backendServer
}

func newBackendPool() *backendPool {
	return &backendPool{
		servers: make([]*backendServer, 0),
	}
}

func (p *backendPool) addServer(ip net.IP, mac net.HardwareAddr) {
	p.Lock()
	defer p.Unlock()

	p.servers = append(p.servers, &backendServer{
		ip:  ip,
		mac: mac,
	})
}

func (p *backendPool) getServerForPath(path string) *backendServer {
	// this function should implement consistent hashing etc, for now we just
	// get the first server in the pool
	return p.servers[0]
}

type tcpConnState struct {
	connState tcpState
	server    *backendServer
	seq       uint32
}

type tcpStateTable struct {
	sync.RWMutex
	conns map[string]*tcpConnState
}

func (st *tcpStateTable) addConnection(ip net.IP, port layers.TCPPort) *tcpConnState {
	st.Lock()
	defer st.Unlock()
	connState := &tcpConnState{
		seq: st.getRandSequence(),
	}
	st.conns[fmt.Sprintf("%s:%d", ip.String(), port)] = connState
	return connState
}

func (st *tcpStateTable) getConnection(ip net.IP, port layers.TCPPort) (*tcpConnState, bool) {
	st.RLock()
	defer st.RUnlock()

	connState, ok := st.conns[fmt.Sprintf("%s:%d", ip.String(), port)]
	return connState, ok
}

func (st *tcpStateTable) getRandSequence() uint32 {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return uint32(r.Int31())
}

func main() {
	ifaceStr := flag.String("iface", "eth1", "Interface to listen on")
	port := flag.Int("port", 80, "Port to listen on")
	lbIndex := flag.Int("lbindex", 1, "Load balancer index (used for DSCP field)")

	// hardcoded backend server
	dstIP := net.ParseIP("192.168.34.10").To4()
	dstMAC, _ := net.ParseMAC("08:00:27:33:d1:63")
	pool := newBackendPool()
	pool.addServer(dstIP, dstMAC)

	stateTable := &tcpStateTable{
		conns: make(map[string]*tcpConnState),
	}

	_, ip := mustGetInterfaceAndAddr(*ifaceStr)

	handleInactive, err := pcap.NewInactiveHandle(*ifaceStr)
	if err != nil {
		log.Fatalf("Could not bind to interface: %s", err)
	}
	defer handleInactive.CleanUp()

	handleInactive.SetImmediateMode(true)
	handle, err := handleInactive.Activate()
	if err != nil {
		log.Fatalf("Could not activate interface: %s", err)
	}
	defer handle.Close()

	if err = handle.SetBPFFilter(fmt.Sprintf("tcp and dst port %d and dst host %s", *port, ip.String())); err != nil {
		log.Fatalf("Could not set BPF filter: %s", err)
	}

	ipPacketChan := make(chan *ipPacket)

	go sendIP(handle, ipPacketChan, *lbIndex)
	listenIP(handle, stateTable, ipPacketChan, pool)
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

func listenIP(handle *pcap.Handle, stateTable *tcpStateTable, ipPacketChan chan *ipPacket, pool *backendPool) {
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
		}
		tcpLayer, ok := layer.(*layers.TCP)
		if !ok {
			log.Println("Could not cast layer to TCP")
			continue
		}

		if connState, ok := stateTable.getConnection(ipLayer.SrcIP, tcpLayer.SrcPort); ok {
			if connState.connState == TCP_STATE_SYN_RECEIVED && tcpLayer.ACK {
				// complete the handshake
				connState.connState = TCP_STATE_ESTABLISHED
			} else if connState.connState == TCP_STATE_ESTABLISHED && connState.server == nil && tcpLayer.ACK && tcpLayer.PSH {
				// we received the first data, set the backend server for the
				// connection state, so we know to which server we need to
				// forward the data
				payloadReader := bufio.NewReader(bytes.NewReader(tcpLayer.Payload))
				req, err := http.ReadRequest(payloadReader)
				if err != nil {
					log.Printf("Could not parse request: %s", err)
					continue
				}
				connState.server = pool.getServerForPath(req.RequestURI)
			}

			if connState.connState == TCP_STATE_ESTABLISHED && connState.server != nil {
				ethLayer.DstMAC = connState.server.mac
				ipLayer.DstIP = connState.server.ip
				ipLayer.TTL = 64

				ipPacketChan <- &ipPacket{
					ethLayer: ethLayer,
					ipLayer:  ipLayer,
					tcpLayer: tcpLayer,
				}
			}

		} else {
			// reverse direction of packet since we're going to reply back
			// to the client
			ethLayer.SrcMAC, ethLayer.DstMAC = ethLayer.DstMAC, ethLayer.SrcMAC
			ipLayer.SrcIP, ipLayer.DstIP = ipLayer.DstIP, ipLayer.SrcIP
			ipLayer.TTL = 64

			if tcpLayer.SYN {
				// this is a new connection / TCP handshake
				connState := stateTable.addConnection(ipLayer.DstIP, tcpLayer.SrcPort)
				tcpSYNACK := &layers.TCP{
					SrcPort: tcpLayer.DstPort,
					DstPort: tcpLayer.SrcPort,
					Seq:     connState.seq,
					Ack:     tcpLayer.Seq + 1,
					SYN:     true,
					ACK:     true,
					Window:  64240,
				}
				connState.connState = TCP_STATE_SYN_RECEIVED
				ipPacketChan <- &ipPacket{
					ethLayer: ethLayer,
					ipLayer:  ipLayer,
					tcpLayer: tcpSYNACK,
				}

			} else {
				// this is not a new TCP handshake and connection is unknown
				log.Println("We should send a RST at this point!")
			}
		}
	}
}

func sendIP(handle *pcap.Handle, ipPacketChan chan *ipPacket, lbIndex int) {
	for packet := range ipPacketChan {
		packet.ipLayer.TOS = uint8(lbIndex)
		bytes, err := packet.Serialize()
		if err != nil {
			log.Fatalf("Could not serialize packet: %s", err)
		}
		handle.WritePacketData(bytes)
	}
}
