package balancer

import (
	"errors"
	"net"
)

// Balancer specifies the interface for a balancer backend.
type Balancer interface {
	AddServer(*Server)
	RouteToServer(int64) (*Server, error)
}

// Server contains all the information for a backend server.
type Server struct {
	IP           net.IP
	HardwareAddr net.HardwareAddr
}

// DummyBalancer provides a Balancer for a single server.
type DummyBalancer struct {
	server *Server
}

// NewDummyBalancers returns a new DummyBalancer.
func NewDummyBalancer() Balancer {
	return &DummyBalancer{}
}

// AddServer sets the (single) server.
func (b *DummyBalancer) AddServer(s *Server) {
	b.server = s
}

// RouteToServer returns the single server (or an error when no server is set).
func (b *DummyBalancer) RouteToServer(i int64) (*Server, error) {
	if b.server == nil {
		return nil, errors.New("Could not route to server.")
	}
	return b.server, nil
}
