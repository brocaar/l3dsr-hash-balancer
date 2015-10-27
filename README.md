# Layer-3 Direct Server Return load balancer prototype

**note this is proof-of-concept project, do not use this in production**

This is a prototype for a L3-DSR hash based load balancer. For a client I was
researching if we could improve its CDN (for streaming content) by using
a hash-based loadbalancer with the capability of using Layer-3 based Direct
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

Note that all cli argument have defaults that matches the Vagrant
environment.

### starting the balancer

Run the following commands to start the balancer (within the Vagrant
environment). 

```
vagrant ssh balancer
cd src/github.com/brocaar/l3dsr-hash-balancer
go get ./...
make
sudo ./bin/balancer
```

The balancer box has one interface ``192.168.33.10`` on which it listens for
incoming requests.


### starting the packetbridge / backend

Run the following commands to start the packetbridge (within the Vagrant
environment).

```
vagrant ssh backend
cd src/github.com/brocaar/l3dsr-hash-balancer
sudo ./bin/packetbridge
```

The backend box has two interfaces. On ``192.168.33.20`` it listens for incoming
packets from the balancer. On ``192.168.33.30`` NGINX is running.

### making requests

Now that both applications are running, you can make a request to
``http://192.168.33.10/``. This will:

* Create a TCP handshake between you and the balancer (``.10``)
* The balancer (``.10``) will sync your TCP handshake with the packetbridge
  (``.20``)
* The packetbridge (``.20``) will create a TCP handshake with the backend
  (NGINX on ``.30``).
* The packetbridge will start forwarding your packets to NGIXN (``.30``) and
  the packets from NGINX to you (by using the ``.10`` source ip). Your HTTP
  client will think that all packets came from the balancer :-)
