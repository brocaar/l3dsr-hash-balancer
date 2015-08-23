package main

import (
	"fmt"
	"log"
	"net"
	"os"

	balancer "github.com/brocaar/l3dsr-hash-balancer"
	"github.com/codegangsta/cli"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var revision string // set by the compiler

func run(c *cli.Context) {
	backendIP := net.ParseIP(c.String("backend-ip")).To4()
	backendMAC, err := net.ParseMAC(c.String("backend-mac"))
	if err != nil {
		log.Fatalf("Could not parse backend MAC: %s", err)
	}

	// setup pcap handle
	hi, err := pcap.NewInactiveHandle(c.String("iface"))
	if err != nil {
		log.Fatalf("Could not bind to interface: %s", err)
	}
	defer hi.CleanUp()
	hi.SetImmediateMode(true)
	handle, err := hi.Activate()
	if err != nil {
		log.Fatalf("Could not activate handler: %s", err)
	}
	defer handle.Close()

	// setup BPF filter
	ip, err := balancer.GetAddrByName(c.String("iface"))
	if err != nil {
		log.Fatalf("Could not get IP for interface: %s", err)
	}
	if err = handle.SetBPFFilter(fmt.Sprintf("tcp and dst port %d and dst host %s", c.Int("port"), ip.String())); err != nil {
		log.Fatalf("Could not set BPF filter: %s", err)
	}

	// get packet channel
	ps := gopacket.NewPacketSource(handle, handle.LinkType())

	// handle packets
	ethPacketChan := make(chan *balancer.EthPacket)
	st := balancer.NewStateTable()
	pool := balancer.NewDummyBalancer()
	pool.AddServer(&balancer.Server{
		IP:           backendIP,
		HardwareAddr: backendMAC,
	})

	go balancer.BalancePackets(ps.Packets(), ethPacketChan, st, pool)
	sendPacket(handle, ethPacketChan, uint8(c.Int("lbindex")))
}

func sendPacket(handle *pcap.Handle, ethPacketChan chan *balancer.EthPacket, lbIndex uint8) {
	for p := range ethPacketChan {
		log.Printf("Sending packet %s", p)

		p.SetTOS(lbIndex)
		bytes, err := p.MarshalBinary()
		if err != nil {
			log.Fatalf("Could not marshal packet: %s", err)
		}
		handle.WritePacketData(bytes)
	}
}

func main() {
	app := cli.NewApp()
	app.Version = revision
	app.Name = "balancer"
	app.Usage = "Load-balancer application for for L3-DSR."
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "iface",
			Value: "eth1",
			Usage: "interface to listen on",
		},
		cli.IntFlag{
			Name:  "port",
			Value: 80,
			Usage: "port to listen on",
		},
		cli.IntFlag{
			Name:  "lbindex",
			Value: 1,
			Usage: "load-balancer index (used for DSCP field)",
		},
		cli.StringFlag{
			Name:  "backend-ip",
			Value: "192.168.34.20",
			Usage: "IP address of backend server",
		},
		cli.StringFlag{
			Name:  "backend-mac",
			Value: "08:00:27:33:d1:63",
			Usage: "MAC address of backend server",
		},
	}
	app.Action = run
	app.Run(os.Args)
}
