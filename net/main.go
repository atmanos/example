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

	ip := ip.IPAddr{10, 0, 2, 20} // 192.168.1.12

	sendGratuitousArp(dev, ip)
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

		for dev.Tx.CheckForResponses() {
			rsp := (*anet.NetifTxResponse)(dev.Tx.NextResponse())
			fmt.Printf("%#v\n", rsp)
		}
	}
}

func newPacketReader(dev *anet.Device, rsp *anet.NetifRxResponse) io.Reader {
	var (
		len    = uint16(rsp.Status)
		buf    = dev.RxBuffers.Lookup(int(rsp.ID))
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

	switch hdr.Type {
	case ip.EtherTypeIPv4:
		recvipv4(r)
	}
}

func recvipv4(r io.Reader) {
	var hdr ip.IPv4Header

	if err := binary.Read(r, binary.BigEndian, &hdr); err != nil {
		fmt.Printf("rx: unable to read header: %s\n", err)
		return
	}

	fmt.Printf("%#v\n", hdr)
}

func enqueueRequest(dev *anet.Device, id uint16) {
	req := (*anet.NetifRxRequest)(dev.Rx.NextRequest())
	req.ID = id
	req.Gref = dev.RxBuffers.Lookup(int(id)).Gref
}

func sendGratuitousArp(dev *anet.Device, ipaddr ip.IPAddr) {
	broadcast := ip.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	hdr := &ip.EthernetHeader{
		Destination: broadcast,
		Source:      dev.MacAddr,
		Type:        ip.EtherTypeArp,
	}

	arp := &ip.EthernetArpHeader{
		HardwareType: 1,
		ProtocolType: 0x0800,
		HardwareLen:  6,
		ProtocolLen:  4,
		OpCode:       0x0001,

		SenderHardwareAddress: dev.MacAddr,
		SenderIPAddr:          ipaddr,

		TargetHardwareAddress: dev.MacAddr,
		TargetIPAddr:          ipaddr,
	}

	buf, _ := dev.TxBuffers.Get()

	w := bytes.NewBuffer(buf.Page.Data[:0])
	binary.Write(w, binary.BigEndian, hdr)
	binary.Write(w, binary.BigEndian, arp)

	dev.SendTxBuffer(buf, w.Len())

	if notify := dev.Tx.PushRequests(); notify {
		dev.EventChannel.Notify()
	}
}
