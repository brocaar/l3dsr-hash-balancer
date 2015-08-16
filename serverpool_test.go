package balancer

import "testing"

func TestDummyBalancer(t *testing.T) {
	s := &Server{}
	b := NewDummyBalancer()

	_, err := b.RouteToServer(123)
	if err == nil {
		t.Fatal("DummyBalancer should have returned an error when no server is set.")
	}

	b.AddServer(s)
	s2, err := b.RouteToServer(123)
	if err != nil {
		t.Fatal(err)
	}

	if s2 != s {
		t.Error("The server that was added should be equal to the returned server.")
	}
}
