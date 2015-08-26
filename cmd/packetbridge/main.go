package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	balancer "github.com/brocaar/l3dsr-hash-balancer"
	"github.com/codegangsta/cli"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var revision string // set by the compiler

func run(c *cli.Context) {
	balancers, err := parseBalancers(c.String("balancers"))
	if err != nil {
		log.Fatalf("Could not parse the balancers: %s", err)
	}

	pbIP, err := balancer.GetAddrByName(c.String("packetbridge-iface"))
	if err != nil {
		log.Fatalf("Could not get interface IP: %s", err)
	}

	pbIface, err := net.InterfaceByName(c.String("packetbridge-iface"))
	if err != nil {
		log.Fatalf("Could not get interface: %s", err)
	}

	backendIP, err := balancer.GetAddrByName(c.String("backend-iface"))
	if err != nil {
		log.Fatalf("Could not get interface IP: %s", err)
	}

	stateTable := balancer.NewPacketBridgeStateTable()

	// setup PCAP handle for receiving IP packets from the client.
	// IP level is needed since we need to have access to the DSCP / ToS
	// field.
	ih, err := pcap.NewInactiveHandle(c.String("packetbridge-iface"))
	if err != nil {
		log.Fatalf("Could not bind to interface %s: %s", c.String("packetbridge-iface"), err)
	}
	defer ih.CleanUp()
	ih.SetImmediateMode(true)
	handle, err := ih.Activate()
	if err != nil {
		log.Fatalf("Could not activate handle: %s", err)
	}
	defer handle.Close()

	bpfFilter := fmt.Sprintf("tcp and dst port %d and dst host %s", c.Int("packetbridge-port"), pbIP.String())
	log.Println(bpfFilter)
	if err = handle.SetBPFFilter(bpfFilter); err != nil {
		log.Fatalf("Could not set BPF filter: %s", err)
	}

	ps := gopacket.NewPacketSource(handle, handle.LinkType())

	// setup TCP connection
	tcpConn, err := net.ListenPacket("ip4:tcp", pbIP.String())
	if err != nil {
		log.Fatalf("Could not open IPv4:TCP connection: %s", err)
	}

	backendTCPPackets := make(chan *balancer.TCPPacket)
	clientEthPackets := make(chan *balancer.EthPacket)

	log.Printf("Starting proxy %s -> %s", pbIP, backendIP)

	go balancer.ForwardToBackend(tcpConn, backendTCPPackets, pbIP, backendIP)
	go sendIP(handle, clientEthPackets)
	go balancer.ListenTCP(tcpConn, pbIP, backendIP, layers.TCPPort(c.Int("packetbridge-port")), pbIface, backendTCPPackets, clientEthPackets, stateTable, balancers)
	balancer.HandleIP(ps.Packets(), backendTCPPackets, stateTable)
}

func main() {
	app := cli.NewApp()
	app.Version = revision
	app.Name = "packetbridge"
	app.Usage = "Syncs TCP handshakes between client and backend services"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "packetbridge-iface",
			Value: "eth1",
			Usage: "interface to listen on",
		},
		cli.IntFlag{
			Name:  "packetbridge-port",
			Value: 80,
			Usage: "port number to forward packages for",
		},
		cli.StringFlag{
			Name:  "backend-iface",
			Value: "eth2",
			Usage: "interface to forward traffic to",
		},
		cli.StringFlag{
			Name:  "balancers",
			Value: "1:192.168.33.10",
			Usage: "comma separated list of balancers in the format index:ip",
		},
	}
	app.Action = run
	app.Run(os.Args)
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

func sendIP(handle *pcap.Handle, ethPackets chan *balancer.EthPacket) {
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
