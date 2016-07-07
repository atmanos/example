package main

import (
	anet "atman/net"
	"atman/net/ip"
	"atman/xen"
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"time"
)

func main() {
	dev := anet.DefaultDevice

	if dev == nil {
		fmt.Println("Failed to initialize network device")
		os.Exit(1)
	}

	grantTable := xen.MapGrantTable()

	fmt.Println("Network device initialized:")
	fmt.Printf("  Mac address: %s\n", dev.MacAddr)
	fmt.Printf("  IP address:  %s\n", dev.IPAddr)

	fmt.Printf(" RX entries=%d size=%d\n", dev.Rx.EntryCount, dev.Rx.EntrySize)

	for {
		dev.EventChannel.Wait()

		for dev.Rx.CheckForResponses() {
			rsp := (*anet.NetifRxResponse)(dev.Rx.NextResponse())
			buf := &dev.RxBuffers[rsp.ID]

			grantTable.EndAccess(buf.Gref)

			rx(dev, rsp)

			buf.Gref, _ = grantTable.GrantAccess(uint16(dev.Backend), buf.Page.Frame, false)

			// re-enqueue the previous request buffer
			req := (*anet.NetifRxRequest)(dev.Rx.NextRequest())
			req.ID = rsp.ID
			req.Gref = buf.Gref
		}

		if notify := dev.Rx.PushRequests(); notify {
			dev.EventChannel.Notify()
		}
	}

	time.Sleep(60 * time.Second)
}

const (
	NETIF_RSP_NULL = 1
)

func rx(dev *anet.Device, rsp *anet.NetifRxResponse) {
	if rsp.Status <= NETIF_RSP_NULL {
		return
	}

	size := rsp.Status
	packet := make([]byte, size)

	copy(packet, dev.RxBuffers[rsp.ID].Page.Data[rsp.Offset:])

	var (
		r   = bytes.NewReader(packet)
		hdr ip.EthernetHeader
	)

	if err := binary.Read(r, binary.BigEndian, &hdr); err != nil {
		fmt.Printf("rx: unable to read header: %s\n", err)
		return
	}

	fmt.Printf(
		"rx: packet len=%d from=%q to=%q type=0x%04x (%s)\n",
		size,
		hdr.Source,
		hdr.Destination,
		hdr.Type,
		hdr.Type.Name(),
	)
}
