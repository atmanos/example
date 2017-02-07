// netif implements the stack.LinkEndpoint interface
// for reading and writing ethernet packets
// to AtmanOS's low-level netif Xen driver.
//
// It should eventually be implemented by AtmanOS.

package main

import (
	anet "atman/net"
	"bytes"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/stack"
)

const (
	NETIF_RSP_NULL = 1
)

type netif struct {
	mac    tcpip.LinkAddress
	device *anet.Device

	dispatcher stack.NetworkDispatcher
}

func (i netif) MTU() uint32                    { return 1500 }
func (i netif) MaxHeaderLength() uint16        { return uint16(EthernetHeaderSize) }
func (i netif) LinkAddress() tcpip.LinkAddress { return i.mac }

// WritePacket implements stack.LinkEndpoint
func (i *netif) WritePacket(r *stack.Route, hdr *buffer.Prependable, payload buffer.View, protocol tcpip.NetworkProtocolNumber) error {
	if r.RemoteLinkAddress == "" {
		// TODO: I think we would want to save this package,
		// call LinkAddressRequest, and then deliver after the address
		// is resolved. But this part of the arp handling is also TODO
		// in netstack, so we'll just drop it.
		println("netif: dropping packet with missing remote link addr")
		return nil
	}

	ethhdr := EthernetHeader(hdr.Prepend(EthernetHeaderSize))
	copy(ethhdr.Destination(), r.RemoteLinkAddress)
	copy(ethhdr.Source(), i.mac)
	ethhdr.SetType(uint16(protocol))

	i.writeEthernetPacket(hdr, payload)
	return nil
}

// writeEthernetPacket writes hdr and payload to a tx buffer
// and delivers it to the front-end driver to send.
func (i *netif) writeEthernetPacket(hdr *buffer.Prependable, payload buffer.View) {
	buf, _ := i.device.TxBuffers.Get()

	w := bytes.NewBuffer(buf.Page.Data[:0])
	w.Write(hdr.UsedBytes())
	w.Write(payload)

	i.device.SendTxBuffer(buf, w.Len())

	if notify := i.device.Tx.PushRequests(); notify {
		i.device.EventChannel.Notify()
	}
}

// Attach sets dispatcher as the target for network packet delivery
// and starts receiving packets.
//
// Attach implements stack.LinkEndpoint
func (i *netif) Attach(dispatcher stack.NetworkDispatcher) {
	i.dispatcher = dispatcher

	go i.rxLoop()
}

// rxLoop receives rx buffers from the front-end
// and delivers network packets to the attached dispatcher.
func (i *netif) rxLoop() {
	var dev = i.device

	for {
		dev.EventChannel.Wait()

		for dev.Rx.CheckForResponses() {
			var (
				rsp = (*anet.NetifRxResponse)(dev.Rx.NextResponse())
				buf = dev.RxBuffers.Lookup(int(rsp.ID))
			)

			i.deliverPacket(rsp, buf)

			dev.SendRxBuffer(buf)
		}

		if notify := dev.Rx.PushRequests(); notify {
			dev.EventChannel.Notify()
		}
	}
}

// deliverPacket handles the network packet in buf and delivers it
// to the attached network dispatcher.
func (i *netif) deliverPacket(rsp *anet.NetifRxResponse, buf *anet.Buffer) {
	if rsp.Status <= NETIF_RSP_NULL {
		return
	}

	size := int(rsp.Status)
	view := buffer.NewView(size)
	copy(view, buf.Page.Data[rsp.Offset:])

	ethhdr := EthernetHeader(view[:EthernetHeaderSize])
	view.TrimFront(EthernetHeaderSize)

	vv := buffer.NewVectorisedView(len(view), []buffer.View{view})

	i.dispatcher.DeliverNetworkPacket(
		i,
		tcpip.LinkAddress(ethhdr.Source()),
		tcpip.NetworkProtocolNumber(ethhdr.Type()),
		&vv,
	)
}
