package main

import (
	anet "atman/net"
	"atman/net/ip"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	NETIF_RSP_NULL = 1
)

func main() {
	dev := anet.DefaultDevice

	fmt.Println("Network device initialized:")
	fmt.Printf("  Mac address: %s\n", dev.MacAddr)
	fmt.Printf("  IP address:  %s\n", dev.IPAddr)

	handleEvents(dev)
}

func handleEvents(dev *anet.Device) {
	for {
		dev.EventChannel.Wait()

		for dev.Rx.CheckForResponses() {
			rsp := (*anet.NetifRxResponse)(dev.Rx.NextResponse())

			if rsp.Status > NETIF_RSP_NULL {
				r := newPacketReader(dev, rsp)

				rx(dev, r)
			}

			enqueueRequest(dev, rsp.ID)
		}

		if notify := dev.Rx.PushRequests(); notify {
			dev.EventChannel.Notify()
		}
	}
}

func newPacketReader(dev *anet.Device, rsp *anet.NetifRxResponse) io.Reader {
	var (
		len    = uint16(rsp.Status)
		buf    = dev.RxBuffers[rsp.ID]
		packet = buf.Page.Data[rsp.Offset : rsp.Offset+len]
	)

	return bytes.NewReader(packet)
}

func rx(dev *anet.Device, r io.Reader) {
	var hdr ip.EthernetHeader

	if err := binary.Read(r, binary.BigEndian, &hdr); err != nil {
		fmt.Printf("rx: unable to read header: %s\n", err)
		return
	}

	fmt.Printf(
		"rx: packet from=%q to=%q type=0x%04x (%s)\n",
		hdr.Source,
		hdr.Destination,
		hdr.Type,
		hdr.Type.Name(),
	)
}

func enqueueRequest(dev *anet.Device, id uint16) {
	req := (*anet.NetifRxRequest)(dev.Rx.NextRequest())
	req.ID = id
	req.Gref = dev.RxBuffers[id].Gref
}
