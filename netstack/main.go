package main

import (
	anet "atman/net"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/adapters/gonet"
	"github.com/google/netstack/tcpip/network/ipv4"
	"github.com/google/netstack/tcpip/stack"
	"github.com/google/netstack/tcpip/transport/tcp"
)

func main() {
	log.SetOutput(os.Stdout)

	addrName := "10.0.2.20"
	port := 9999

	addr := tcpip.Address(net.ParseIP(addrName).To4())

	s, err := newStack(addr)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("A very HTTP-hello from AtmanOS\n"))
	})

	listenAndServe(s, addr, port)
}

func listenAndServe(s tcpip.Stack, addr tcpip.Address, port int) {
	fullAddr := tcpip.FullAddress{
		NIC:  1,
		Addr: addr,
		Port: uint16(port),
	}

	ln, _ := gonet.NewListener(s, fullAddr, ipv4.ProtocolNumber)

	http.Serve(ln, nil)
}

func newStack(addr tcpip.Address) (tcpip.Stack, error) {
	s := stack.New([]string{ipv4.ProtocolName}, []string{tcp.ProtocolName})

	mac := parseHardwareAddr(string(anet.DefaultDevice.MacAddr))
	linkID := stack.RegisterLinkEndpoint(NewEtharpLink(mac, addr, &netif{anet.DefaultDevice}))

	if err := s.CreateNIC(1, linkID); err != nil {
		return nil, err
	}

	if err := s.AddAddress(1, ipv4.ProtocolNumber, addr); err != nil {
		return nil, err
	}

	// Add default route.
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: tcpip.Address(strings.Repeat("\x00", len(addr))),
			Mask:        tcpip.Address(strings.Repeat("\x00", len(addr))),
			Gateway:     "",
			NIC:         1,
		},
	})

	return s, nil
}
