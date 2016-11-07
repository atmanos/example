// EtharpLink implements the stack.LinkEndpoint interface
// for processing ethernet packets to and from the network layers.
//
// It is also responsible for maintaining ARP caches to map ip addresses
// to ethernet MAC addresses.
//
// It should eventually be implemented by netstack or AtmanOS directly.

package main

import (
	"atman/net/ip"
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/stack"
)

type EthernetDispatcher interface {
	DeliverEthernetPacket(v buffer.View)
}

type EthernetLink interface {
	WriteEthernetPacket(hdr *buffer.Prependable, payload buffer.View)
	Attach(dispatcher EthernetDispatcher)
}

const (
	arpProto           = 0x0806
	ethernetHeaderSize = 14
)

var (
	rawBroadcastAddr = ip.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

type EthernetArpHeader struct {
	HardwareType uint16 // 1
	ProtocolType uint16 // 0x0800
	HardwareLen  uint8  // 6
	ProtocolLen  uint8  // 4
	OpCode       uint16

	SenderHardwareAddress ip.HardwareAddr
	SenderIPAddr          ip.IPAddr
	TargetHardwareAddress ip.HardwareAddr
	TargetIPAddr          ip.IPAddr
}

func NewEtharpLink(mac, ipaddr tcpip.Address, link EthernetLink) *EtharpLink {
	var (
		rawmac    ip.HardwareAddr
		rawipaddr ip.IPAddr
	)

	copy(rawmac[:], mac)
	copy(rawipaddr[:], ipaddr)

	return &EtharpLink{
		mac:       mac,
		rawmac:    rawmac,
		ipaddr:    ipaddr,
		rawipaddr: rawipaddr,
		link:      link,
		cache:     map[tcpip.Address]ip.HardwareAddr{},
		pending:   map[tcpip.Address][]pendingPacket{},
	}
}

type EtharpLink struct {
	mac    tcpip.Address
	ipaddr tcpip.Address
	link   EthernetLink

	rawmac    ip.HardwareAddr
	rawipaddr ip.IPAddr

	dispatcher stack.NetworkDispatcher

	cache map[tcpip.Address]ip.HardwareAddr

	pending map[tcpip.Address][]pendingPacket
}

type pendingPacket struct {
	r        *stack.Route
	hdr      *buffer.Prependable
	payload  buffer.View
	protocol tcpip.NetworkProtocolNumber
}

var _ stack.LinkEndpoint = &EtharpLink{}

func (EtharpLink) MTU() uint32             { return 1500 }
func (EtharpLink) MaxHeaderLength() uint16 { return ethernetHeaderSize }

func (e *EtharpLink) WritePacket(r *stack.Route, hdr *buffer.Prependable, payload buffer.View, protocol tcpip.NetworkProtocolNumber) error {
	dest, ok := e.cache[r.RemoteAddress]
	if !ok {
		e.enqueuePacket(r, hdr, payload, protocol)

		var rawipaddr ip.IPAddr
		copy(rawipaddr[:], r.RemoteAddress)

		e.sendArp(rawBroadcastAddr, EthernetArpHeader{
			OpCode: 1,

			SenderHardwareAddress: e.rawmac,
			SenderIPAddr:          e.rawipaddr,

			TargetIPAddr: rawipaddr,
		})
		return nil
	}

	prependEthernetHeader(hdr, ip.EthernetHeader{
		Destination: dest,
		Source:      e.rawmac,
		Type:        ip.EtherType(protocol),
	})

	e.link.WriteEthernetPacket(hdr, payload)

	return nil
}

func (e *EtharpLink) DeliverEthernetPacket(v buffer.View) {
	hdr, packet := e.readHeader(v)

	protocol := tcpip.NetworkProtocolNumber(hdr.Type)

	switch protocol {
	case arpProto:
		e.handleARP(hdr, packet)
	default:
		vv := buffer.NewVectorisedView(len(packet), []buffer.View{packet})

		e.dispatcher.DeliverNetworkPacket(
			e,
			protocol,
			&vv,
		)
	}
}

func (e *EtharpLink) readHeader(v buffer.View) (ip.EthernetHeader, buffer.View) {
	var hdr ip.EthernetHeader

	binary.Read(bytes.NewReader(v[:ethernetHeaderSize]), binary.BigEndian, &hdr)

	v.TrimFront(ethernetHeaderSize)

	return hdr, v
}

func (e *EtharpLink) Attach(dispatcher stack.NetworkDispatcher) {
	e.sendGratuitousArp()
	e.dispatcher = dispatcher

	e.link.Attach(e)
}

func (e *EtharpLink) handleARP(hdr ip.EthernetHeader, v buffer.View) {
	var arp EthernetArpHeader

	if err := binary.Read(bytes.NewReader(v), binary.BigEndian, &arp); err != nil {
		return
	}

	e.cache[tcpip.Address(arp.SenderIPAddr[:])] = arp.SenderHardwareAddress

	switch arp.OpCode {
	case 1:
		e.handleARPRequest(arp)
	case 2:
		e.handleARPReply(arp)
	}
}

func (e *EtharpLink) handleARPRequest(arp EthernetArpHeader) {
	if tcpip.Address(arp.TargetIPAddr[:]) != e.ipaddr {
		return
	}

	e.sendArp(arp.SenderHardwareAddress, EthernetArpHeader{
		OpCode: 2,

		SenderHardwareAddress: e.rawmac,
		SenderIPAddr:          e.rawipaddr,

		TargetHardwareAddress: arp.SenderHardwareAddress,
		TargetIPAddr:          arp.SenderIPAddr,
	})
}

func (e *EtharpLink) handleARPReply(arp EthernetArpHeader) {
	ipaddr := tcpip.Address(arp.SenderIPAddr[:])
	pending := e.pending[ipaddr]

	delete(e.pending, ipaddr)

	for _, packet := range pending {
		e.WritePacket(packet.r, packet.hdr, packet.payload, packet.protocol)
		packet.r.Release()
	}
}

func (e *EtharpLink) sendArp(dest ip.HardwareAddr, arp EthernetArpHeader) {
	var (
		header  = buffer.NewPrependable(ethernetHeaderSize)
		payload = &bytes.Buffer{}
	)

	prependEthernetHeader(&header, ip.EthernetHeader{
		Destination: dest,
		Source:      e.rawmac,
		Type:        arpProto,
	})

	// Apply low level ARP message details
	arp.HardwareType = 1
	arp.ProtocolType = 0x0800
	arp.HardwareLen = 6
	arp.ProtocolLen = 4

	binary.Write(payload, binary.BigEndian, arp)

	e.link.WriteEthernetPacket(
		&header,
		payload.Bytes(),
	)
}

func (e *EtharpLink) sendGratuitousArp() {
	e.sendArp(rawBroadcastAddr, EthernetArpHeader{
		OpCode: 0x0001,

		SenderHardwareAddress: e.rawmac,
		SenderIPAddr:          e.rawipaddr,

		TargetHardwareAddress: e.rawmac,
		TargetIPAddr:          e.rawipaddr,
	})
}

func (e *EtharpLink) enqueuePacket(r *stack.Route, hdr *buffer.Prependable, payload buffer.View, protocol tcpip.NetworkProtocolNumber) {
	var (
		newr       = r.Clone()
		newhdr     = buffer.NewPrependable(hdr.UsedLength() + ethernetHeaderSize)
		newpayload = buffer.NewView(len(payload))
	)

	h := newhdr.Prepend(hdr.UsedLength())
	copy(h, hdr.UsedBytes())

	copy(newpayload, payload)

	e.pending[r.RemoteAddress] = append(e.pending[r.RemoteAddress], pendingPacket{
		&newr,
		&newhdr,
		newpayload,
		protocol,
	})
}

func prependEthernetHeader(h *buffer.Prependable, hdr ip.EthernetHeader) {
	var (
		buf = h.Prepend(ethernetHeaderSize)
		w   = bytes.NewBuffer(buf[:0])
	)

	binary.Write(w, binary.BigEndian, hdr)
}

func parseHardwareAddr(s string) tcpip.Address {
	var addr ip.HardwareAddr

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

	return tcpip.Address(addr[:])
}
