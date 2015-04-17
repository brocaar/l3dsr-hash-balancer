# Level-3 Direct Server Return load balancer (hash based)

**work in progress**

This is a prototype for a L3-DSR hash based load balancer. It consists of
two parts 1) the load balancer application, 2) the packet bridge (which should
be installed on every server. An incoming requests is processed in the
following steps:

1. The client makes the TCP handshake with the load balancer application
2. The client sends the HTTP GET request to the load balancer
3. The load balancer chooses the server to route the traffic to (based on the
   GET request hash).
4. The load balancer sends the GET request to the packet bridge (with the
   sequence number, and acknowledgment number from the TCP handshake with
   the client). It will use the client IP as source and the load balancer
   IP in the IPv4 DSCP field (1=a.b.c.d, 2=e.f.g.h.i).
5. The packet bridge will setup a TCP handshake with the interface on which the
   HTTP server is listening.
6. After the packet bridge has a TCP connection with the HTTP server, it will
   replay the GET request and send back the response directly to the client,
   using the load balancer IP as a source.


# Installation

**TODO**

Since the TCP connections are handled by the software without opening any
ports, you need to make sure the system doesn't reset the connection.

To drop all `RST` packages run:

* `iptables -A OUTPUT -m dscp ! --dscp 1 -s FRONTEND_IP -p tcp --tcp-flags RST RST -j DROP`
* `iptables -A OUTPUT -s FRONTEND_IP -d BACKEND_IP -p tcp --tcp-flags RST RST -j DROP`
