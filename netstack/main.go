package main

import (
	anet "atman/net"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/adapters/gonet"
	"github.com/google/netstack/tcpip/link/sniffer"
	"github.com/google/netstack/tcpip/network/arp"
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

func parseHardwareAddr(s string) tcpip.LinkAddress {
	var addr [6]byte

	fmt.Sscanf(
		s,
		"%02x:%02x:%02x:%02x:%02x:%02x",
		&addr[0],
		&addr[1],
		&addr[2],
		&addr[3],
		&addr[4],
		&addr[5],
	)

	return tcpip.LinkAddress(addr[:])
}
func newStack(addr tcpip.Address) (tcpip.Stack, error) {
	s := stack.New([]string{ipv4.ProtocolName, arp.ProtocolName}, []string{tcp.ProtocolName})

	mac := parseHardwareAddr(string(anet.DefaultDevice.MacAddr))
	linkID := stack.RegisterLinkEndpoint(&netif{mac: mac, device: anet.DefaultDevice})

	sniffed := sniffer.New(linkID)
	if err := s.CreateNIC(1, sniffed); err != nil {
		return nil, err
	}

	if err := s.AddAddress(1, arp.ProtocolNumber, "arp"); err != nil {
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
