package balancer

import (
	"errors"
	"net"
)

// PoolBalancer specifies the interface for a balancer backend.
type PoolBalancer interface {
	AddServer(*Server)
	RouteToServer(int64) (*Server, error)
}

// Server contains all the information for a backend server.
type Server struct {
	IP           net.IP
	HardwareAddr net.HardwareAddr
}

// DummyPool provides a PoolBalancer for a single server.
type DummyPool struct {
	server *Server
}

// NewDummyBalancers returns a new DummyPool.
func NewDummyBalancer() PoolBalancer {
	return &DummyPool{}
}

// AddServer sets the (single) server.
func (b *DummyPool) AddServer(s *Server) {
	b.server = s
}

// RouteToServer returns the single server (or an error when no server is set).
func (b *DummyPool) RouteToServer(i int64) (*Server, error) {
	if b.server == nil {
		return nil, errors.New("Could not route to server.")
	}
	return b.server, nil
}
