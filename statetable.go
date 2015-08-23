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

func randomSequence() uint32 {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return uint32(r.Int31())
}
