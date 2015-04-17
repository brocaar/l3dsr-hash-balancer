package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) != 5 {
		fmt.Printf("Usage: %s <srcIP> <srcPort> <dstIP> <dstPort> <seqNum>\n", os.Args[0])
		os.Exit(-1)
	}

	// parse IPs
	srcIP := net.ParseIP(args[0]).To4()
	dstIP := net.ParseIP(args[2]).To4()

	// parse ports
	srcPortInt, err := strconv.ParseInt(args[1], 10, 16)
	if err != nil {
		log.Fatal(err)
	}
	dstPortInt, err := strconv.ParseInt(args[3], 10, 16)
	if err != nil {
		log.Fatal(err)
	}
	srcPort := layers.TCPPort(srcPortInt)
	dstPort := layers.TCPPort(dstPortInt)

	// parse seq number
	seqNum, err := strconv.ParseInt(args[4], 10, 32)
	if err != nil {
		log.Fatal(err)
	}

	ipLayer := &layers.IPv4{
		SrcIP: srcIP,
		DstIP: dstIP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     uint32(seqNum),
		SYN:     true,
		Window:  64240,
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err = gopacket.SerializeLayers(buf, opts, tcpLayer); err != nil {
		log.Fatal(err)
	}

	// sending the packet
	conn, err := net.ListenPacket("ip4:tcp", args[0])
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstIP})
}
