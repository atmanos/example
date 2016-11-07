netstack
--------

This is an proof-of-concept application using [netstack] with AtmanOS to build
a simple HTTP server.

  [netstack]: github.com/google/netstack

`etharp.go` implements a link-layer netstack endpoint for processing ethernet
packets and managing an ARP cache. `netif.go` bridges the etharp endpoint and
netstack to AtmanOS's low-level network driver.
