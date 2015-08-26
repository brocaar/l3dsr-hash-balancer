package balancer

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
)

// State represents a single connection state
type State struct {
	State  TCPState
	Server *Server
	Seq    uint32
}

// StateTable keeps track of the connection states.
type StateTable struct {
	sync.RWMutex
	states map[string]*State
}

// NewStateTable creates and initializes a new StateTable.
func NewStateTable() *StateTable {
	return &StateTable{
		states: make(map[string]*State),
	}
}

func (s *StateTable) NewState(ip net.IP, port layers.TCPPort) *State {
	s.Lock()
	defer s.Unlock()
	state := &State{
		Seq: randomSequence(),
	}
	s.states[fmt.Sprintf("%s:%d", ip.String(), port)] = state
	return state
}

func (s *StateTable) GetState(ip net.IP, port layers.TCPPort) (*State, bool) {
	s.RLock()
	defer s.RUnlock()

	state, ok := s.states[fmt.Sprintf("%s:%d", ip.String(), port)]
	return state, ok
}

// PacketBridgeState represents a single connection state at the packet bridge.
type PacketBridgeState struct {
	State        TCPState
	IP           net.IP
	HardwareAddr net.HardwareAddr
	RandPort     layers.TCPPort
	Port         layers.TCPPort
	LBIndex      uint8
	SeqOffset    uint32
	PayloadBuf   []byte
}

// PacketBridgeStateTable represents a table of tcp connection states.
type PacketBridgeStateTable struct {
	sync.RWMutex
	byPort map[layers.TCPPort]*PacketBridgeState
	byIP   map[string]*PacketBridgeState
}

// NewPacketBridgeStateTable creates and initializes a new PacketBridgeStateTable.
func NewPacketBridgeStateTable() *PacketBridgeStateTable {
	return &PacketBridgeStateTable{
		byPort: make(map[layers.TCPPort]*PacketBridgeState),
		byIP:   make(map[string]*PacketBridgeState),
	}
}

func (s *PacketBridgeStateTable) NewState(ip net.IP, mac net.HardwareAddr, port layers.TCPPort, lbIndex uint8, seqOffset uint32, payload []byte) *PacketBridgeState {
	var randPort layers.TCPPort
	s.Lock()
	defer s.Unlock()

	// generate random port that is not yet in the table
	// todo max number of tries or a better way to find unique port!
	for {
		randPort = randomPort()
		if _, ok := s.byPort[randPort]; !ok {
			break
		}
	}

	state := &PacketBridgeState{
		IP:           ip,
		Port:         port,
		HardwareAddr: mac,
		RandPort:     randPort,
		LBIndex:      lbIndex,
		SeqOffset:    seqOffset,
		PayloadBuf:   payload,
	}

	s.byPort[randPort] = state
	s.byIP[fmt.Sprintf("%s:%d", ip.String(), port)] = state
	return state
}

func (s *PacketBridgeStateTable) GetByPort(port layers.TCPPort) (*PacketBridgeState, bool) {
	s.RLock()
	defer s.RUnlock()

	state, ok := s.byPort[port]
	return state, ok
}

func (s *PacketBridgeStateTable) GetByIP(ip net.IP, port layers.TCPPort) (*PacketBridgeState, bool) {
	s.RLock()
	defer s.RUnlock()

	state, ok := s.byIP[fmt.Sprintf("%s:%d", ip.String(), port)]
	return state, ok
}

func randomSequence() uint32 {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return uint32(r.Int31())
}

func randomPort() layers.TCPPort {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return layers.TCPPort(r.Int31n(65536))
}
