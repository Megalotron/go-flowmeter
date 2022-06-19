package capsule

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"strconv"
)

var (
	ErrInvalidPacket = errors.New("invalid or corrupted packet")
)

// A Packet act as an encapsulation of a PCAP *packet.
// It is used to fill up a Flow.
type Packet struct {
	// 1. Identification
	// -----
	// Used to identify the current Packet in the Flow.
	id uint64
	// Used to identify the packet's protocol based on the IANA list.
	protocol ProtocolNumber

	// 2. Content
	// -----
	// These two fields represents the source and destination ports of the current packet.
	srcPort uint16
	dstPort uint16
	// Similarly, these two fields represents the source and destination addresses for the
	// current packet.
	srcIP string
	dstIP string
	// This flag is used as an indication of whether this packet is a TCP termination-call.
	flagFIN bool

	// 3. Metadata
	// -----
	// Used to indicate when the packet was captured.
	timestamp uint64
	// Used to attach this packet to a specific Flow.
	flowID string
}

// nolint:lll
// NewPacket creates a new PCAP packet encapsulation from the given information.
func NewPacket(id uint64, protocol ProtocolNumber, srcPort uint16, dstPort uint16, srcIP string, dstIP string, timestamp uint64) *Packet {
	packet := &Packet{
		id:        id,
		protocol:  protocol,
		srcPort:   srcPort,
		dstPort:   dstPort,
		srcIP:     srcIP,
		dstIP:     dstIP,
		timestamp: timestamp,
	}

	// Using the given data, generate the Flow identifier.
	packet.generateFlowID()

	return packet
}

// generateFlowID uses the packet's content to determine the packet's direction.
// Then, using this information along with the source and destination data,
// it creates the identifier for the Flow which must contain this packet.
func (p *Packet) generateFlowID() {
	p.flowID = fmt.Sprintf("%s-%s-%d-%d-%d", p.srcIP, p.dstIP, p.srcPort, p.dstPort, p.protocol)
}

// ID returns the packet's unique identifier.
func (p *Packet) ID() uint64 {
	return p.id
}

// Protocol returns the IANA protocol identifier for this packet.
func (p *Packet) Protocol() ProtocolNumber {
	return p.protocol
}

// SrcPort returns the packet's source port.
func (p *Packet) SrcPort() uint16 {
	return p.srcPort
}

// DstPort returns the packet's destination port.
func (p *Packet) DstPort() uint16 {
	return p.dstPort
}

// SrcIP returns the packet's source address.
func (p *Packet) SrcIP() string {
	return p.srcIP
}

// DstIP returns the packet's destination address.
func (p *Packet) DstIP() string {
	return p.dstIP
}

// FlagFIN returns true if the packet is used as a TCP termination call.
// It returns false otherwise.
func (p *Packet) FlagFIN() bool {
	return p.flagFIN
}

// Timestamp returns the UNIX timestamp when the packet was captured.
func (p *Packet) Timestamp() uint64 {
	return p.timestamp
}

// FlowID returns the identifier of the Flow which contains this packet.
func (p *Packet) FlowID() string {
	return p.flowID
}

// FromPCAP takes a pcap packet extracted from a file and converts it to an encapsulation.
func (p *Packet) FromPCAP(packet gopacket.Packet, id uint64) error {
	// The packet misses crucial information.
	if packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
		return ErrInvalidPacket
	}

	// Packet's source and destination addresses.
	srcIP, dstIP := packet.NetworkLayer().NetworkFlow().Endpoints()

	// Packet's source and destination ports.
	srcPortRaw, dstPortRaw := packet.TransportLayer().TransportFlow().Endpoints()

	srcPort, err := strconv.ParseUint(srcPortRaw.String(), 10, 16)
	if err != nil {
		return err
	}

	dstPort, err := strconv.ParseUint(dstPortRaw.String(), 10, 16)
	if err != nil {
		return err
	}

	p.srcIP = srcIP.String()
	p.dstIP = dstIP.String()
	p.srcPort = uint16(srcPort)
	p.dstPort = uint16(dstPort)

	// Packet's protocol number.
	p.protocol = ProtocolUDP
	if packet.Layer(layers.LayerTypeTCP) != nil {
		p.protocol = ProtocolTCP
	}

	p.id = id

	return nil
}
