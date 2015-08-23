# Level-3 Direct Server Return load balancer prototype

**note this is proof-of-concept project, do not use this in production**

This is a prototype for a L3-DSR hash based load balancer. For a client I was
researching if we could improve its CDN (for streaming content) by using
a hash-based loadbalancer with the capability of using Level-3 based Direct
Server Return (so that returning traffic is bypassing the loadbalancer).

This codebase only implements a naive balancer application which:

1. creates a handshake with the client
2. inspects the first packet to determine which server to route the traffic to
3. syncs the TCP handshake with the packetbridge application
4. forwards all further TCP traffic to the packetbridge

By using the DSCP field in the IPv4 header, the loadbalancer identifies itself
to the packetbride.

The packetbridge application:

1. receives TCP packets from the balancer application
2. creates (for new connections) a handshake with the backend (e.g. NGINX)
3. modifies the incoming traffic so that it matches with the TCP handshake
   of the backend
4. modifies outgoing traffic so that it matches with the TCP handshake of
   the client.

The packetbride will use the loadbalancer IP address (it knows because of the
DSCP field) for outgoing traffic, so that outgoing traffic bypasses the
loadbalancer.

## How to use

The easiest way to play with this project is to setup a Vagrant environment.
Running ``vagrant up`` will setup two boxes, one for the balancer, the other
for the backend.

TODO: add example commands.
