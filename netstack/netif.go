// netif implements the EthernetLink interface
// for reading and writing complete ethernet packets
// to AtmanOS's low-level netif Xen driver.
//
// It should eventually be implemented by AtmanOS.

package main

import (
	anet "atman/net"
	"bytes"

	"github.com/google/netstack/tcpip/buffer"
)

const (
	NETIF_RSP_NULL = 1
)

type netif struct {
	device *anet.Device
}

func (i *netif) WriteEthernetPacket(hdr *buffer.Prependable, payload buffer.View) {
	buf, _ := i.device.TxBuffers.Get()

	w := bytes.NewBuffer(buf.Page.Data[:0])
	w.Write(hdr.UsedBytes())
	w.Write(payload)

	i.device.SendTxBuffer(buf, w.Len())

	if notify := i.device.Tx.PushRequests(); notify {
		i.device.EventChannel.Notify()
	}
}

func (i *netif) Attach(dispatcher EthernetDispatcher) {
	go i.dispatchLoop(dispatcher)
}

func (i *netif) dispatchLoop(d EthernetDispatcher) {
	var dev = i.device

	for {
		dev.EventChannel.Wait()

		for dev.Rx.CheckForResponses() {
			var (
				rsp = (*anet.NetifRxResponse)(dev.Rx.NextResponse())
				buf = dev.RxBuffers.Lookup(int(rsp.ID))
			)

			i.dispatch(d, rsp, buf)

			dev.SendRxBuffer(buf)
		}

		if notify := dev.Rx.PushRequests(); notify {
			dev.EventChannel.Notify()
		}
	}
}

func (i *netif) dispatch(d EthernetDispatcher, rsp *anet.NetifRxResponse, buf *anet.Buffer) {
	if rsp.Status <= NETIF_RSP_NULL {
		return
	}

	view := buffer.NewView(int(rsp.Status))
	copy(view, buf.Page.Data[rsp.Offset:])

	d.DeliverEthernetPacket(view)
}
